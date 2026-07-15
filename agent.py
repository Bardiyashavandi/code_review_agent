"""
agent.py
--------
Orchestrates github_fetcher -> semgrep_runner -> gemini_reviewer into a
single pipeline, and exposes it as a Google ADK 2.0 agent tool.

Usage:
    import os
    from agent import CodeReviewAgent

    agent = CodeReviewAgent(
        github_token=os.environ["GITHUB_TOKEN"],
        gemini_api_key=os.environ["GEMINI_API_KEY"],
    )
    result = agent.review_repo("https://github.com/owner/repo")
    for issue in result.review_report.issues:
        print(issue.severity, issue.path, issue.title)
"""

from __future__ import annotations

import logging
import os
import re
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field

# When ADK's `adk web` loads this file, it imports it as the submodule
# `code_review_agent.agent`, which only puts the *parent* directory
# (the one containing code_review_agent/) on sys.path -- not this folder
# itself. That breaks the plain top-level imports below (report_generator,
# gemini_reviewer, github_fetcher, semgrep_runner), since Python can't find
# them as top-level modules anymore. Explicitly adding this file's own
# directory to sys.path makes the imports work the same way whether this
# module is run directly (python3 main.py), imported by pytest, or loaded
# by ADK's package-style agent loader.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from google.adk.agents import Agent
from google.adk.tools import FunctionTool

import report_generator
import tracing
from gemini_reviewer import GeminiReviewer, GeminiReviewerError, ReviewIssue, ReviewReport
from github_fetcher import FetchResult, FileResult, GitHubFetcher
from semgrep_runner import Finding, ScanReport, SemgrepRunner, SemgrepRunnerError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class AgentError(Exception):
    """Orchestrator-level errors (e.g. bad constructor arguments).

    Errors raised by the underlying fetch/scan/review modules are NOT
    re-wrapped here: fetch-stage errors propagate unchanged, scan/review
    -stage errors are captured as StageError instead of raised.
    """
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class StageError:
    stage: str  # "fetch" | "scan" | "review"
    message: str


@dataclass
class PipelineResult:
    repo_url: str
    fetch_result: FetchResult
    scan_report: ScanReport
    review_report: ReviewReport
    stage_errors: list[StageError] = field(default_factory=list)
    duration_s: float = 0.0


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_BRANCH = "main"
DEFAULT_MAX_FILES = 100
DEFAULT_MODEL = "gemini-3.1-flash-lite"
DEFAULT_SEMGREP_CONFIG = "auto"


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class CodeReviewAgent:
    """
    Orchestrates the full review pipeline: fetch -> scan -> review.

    Only a fetch-stage failure is fatal (there is nothing to review without
    files). Scan and review failures are captured as StageError entries so
    the pipeline always returns a usable, possibly partial, PipelineResult.
    """

    def __init__(
        self,
        github_token: str,
        gemini_api_key: str,
        semgrep_config: str = DEFAULT_SEMGREP_CONFIG,
    ) -> None:
        if not github_token or not github_token.strip():
            raise ValueError("github_token must not be empty")
        if not gemini_api_key or not gemini_api_key.strip():
            raise ValueError("gemini_api_key must not be empty")

        self._fetcher = GitHubFetcher(token=github_token)
        self._semgrep = SemgrepRunner(config=semgrep_config)
        self._reviewer = GeminiReviewer(api_key=gemini_api_key)

    def review_repo(
        self,
        url: str,
        branch: str = DEFAULT_BRANCH,
        max_files: int = DEFAULT_MAX_FILES,
    ) -> PipelineResult:
        """Run the full fetch -> scan -> review pipeline for a single repo."""
        start = time.monotonic()
        stage_errors: list[StageError] = []

        with tracing.span(
            "run", "review_repo",
            repo_url=url, branch=branch, max_files=max_files,
        ) as run_span:

            # --- Fetch: fatal on failure -----------------------------------
            with tracing.span("stage", "fetch", repo_url=url, branch=branch) as fetch_span:
                fetch_result = self._fetcher.fetch_python_files(url, branch=branch, max_files=max_files)
                fetch_span.set(
                    files_fetched=len(fetch_result.files),
                    truncated=fetch_result.truncated,
                )
            logger.info("Fetched %d files from %s", len(fetch_result.files), url)

            # --- Scan: non-fatal on failure ---------------------------------
            try:
                with tracing.span("stage", "scan", files_in=len(fetch_result.files)) as scan_span:
                    scan_report = self._semgrep.scan(fetch_result.files)
                    scan_span.set(
                        scanned=scan_report.scanned,
                        findings=len(scan_report.findings),
                        skipped=len(scan_report.skipped),
                    )
            except (SemgrepRunnerError, ValueError) as exc:
                message = getattr(exc, "message", str(exc))
                logger.warning("Scan stage failed: %s", message)
                stage_errors.append(StageError(stage="scan", message=message))
                scan_report = ScanReport(
                    findings=[],
                    scanned=0,
                    skipped=[f.path for f in fetch_result.files],
                    duration_s=0.0,
                )

            # --- Review: non-fatal on failure --------------------------------
            try:
                with tracing.span("stage", "review", files_in=len(fetch_result.files)) as review_span:
                    review_report = self._reviewer.review(fetch_result.files, scan_report)
                    review_span.set(
                        files_reviewed=review_report.files_reviewed,
                        issues=len(review_report.issues),
                        model=review_report.model,
                    )
            except (GeminiReviewerError, ValueError) as exc:
                message = getattr(exc, "message", str(exc))
                logger.warning("Review stage failed: %s", message)
                stage_errors.append(StageError(stage="review", message=message))
                review_report = ReviewReport(
                    issues=[],
                    summary=f"Review unavailable: {message}",
                    model=DEFAULT_MODEL,
                    files_reviewed=0,
                    duration_s=0.0,
                )

            duration = time.monotonic() - start
            logger.info(
                "Pipeline complete for %s in %.2fs (%d stage errors)",
                url, duration, len(stage_errors),
            )

            run_span.set(
                files_fetched=len(fetch_result.files),
                truncated=fetch_result.truncated,
                semgrep_findings=len(scan_report.findings),
                review_issues=len(review_report.issues),
                stage_errors=[e.stage for e in stage_errors],
                duration_s=round(duration, 3),
            )

            result = PipelineResult(
                repo_url=url,
                fetch_result=fetch_result,
                scan_report=scan_report,
                review_report=review_report,
                stage_errors=stage_errors,
                duration_s=duration,
            )

        return result

    # --- Granular, single-stage entry points -----------------------------
    # These exist so the ADK agent can be given separate fetch/scan/review
    # tools instead of only the one-shot review_repo() pipeline, letting the
    # model itself plan and sequence multi-step tool calls. They delegate to
    # the exact same underlying clients as review_repo() — no new behavior,
    # just exposed individually.

    def fetch_files(
        self,
        url: str,
        branch: str = DEFAULT_BRANCH,
        max_files: int = DEFAULT_MAX_FILES,
    ) -> FetchResult:
        """Fetch a repo's Python files only — no scan, no review."""
        return self._fetcher.fetch_python_files(url, branch=branch, max_files=max_files)

    def scan_files(self, files: list[FileResult]) -> ScanReport:
        """Run Semgrep on an already-fetched list of files only."""
        return self._semgrep.scan(files)

    def generate_review(self, files: list[FileResult], scan_report: ScanReport) -> ReviewReport:
        """Ask Gemini to review an already-fetched list of files, optionally
        grounded by an already-computed ScanReport — no fetch, no scan."""
        return self._reviewer.review(files, scan_report)

    # --- PR diff entry point -----------------------------------------------

    def fetch_pr_files(self, pr_url: str, max_files: int = DEFAULT_MAX_FILES) -> tuple:
        """Fetch Python files changed in a GitHub PR only — no scan, no review."""
        return self._fetcher.fetch_pr_files(pr_url, max_files=max_files)

    def validate_review_findings(self, issues, files) -> list[dict]:
        """Cross-check already-produced review issues against source files for false positives."""
        return self._reviewer.validate_findings(issues, files)

    # --- Additional, "interesting" tools -----------------------------------
    # Each of these is a distinct capability beyond the core fetch/scan/review
    # pipeline, intended to give the ADK agent more genuine planning choices.

    def get_repo_metadata(self, url: str) -> dict:
        """Look up a repo's language, size, stars, and default branch
        without fetching any file contents."""
        return self._fetcher.get_repo_metadata(url)

    def search_code(
        self, files: list[FileResult], pattern: str, case_sensitive: bool = False
    ) -> list[dict]:
        """Search already-fetched files for a regex pattern, returning each
        matching line. Pure local string search — no extra API/LLM calls."""
        if not pattern:
            raise ValueError("pattern must not be empty")

        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern: {exc}") from exc

        matches: list[dict] = []
        for f in files:
            for line_no, line in enumerate(f.content.splitlines(), start=1):
                if compiled.search(line):
                    matches.append({"path": f.path, "line": line_no, "snippet": line.strip()})
        return matches

    def explain_finding(
        self,
        path: str,
        title: str,
        description: str,
        severity: str = "MEDIUM",
        snippet: str = "",
        rule_id: str | None = None,
    ) -> str:
        """Ask Gemini for a deeper, focused explanation of one already-known
        issue — separate from the bulk generate_review() call."""
        return self._reviewer.explain_issue(
            path=path, title=title, description=description,
            severity=severity, snippet=snippet, rule_id=rule_id,
        )

    def save_report(
        self,
        repo_url: str,
        files: list[FileResult],
        findings: list[Finding],
        issues,
        summary: str,
        model: str,
        output_path: str = "review_report.md",
    ) -> str:
        """Render an already-assembled review as Markdown and write it to
        disk, reusing report_generator.py's renderer. Builds a minimal
        PipelineResult-shaped object from already-known pieces — no fetch,
        scan, or review call of its own."""
        fetch_result = FetchResult(files=files, truncated=False)
        scan_report = ScanReport(findings=findings, scanned=len(files), skipped=[], duration_s=0.0)
        review_report = ReviewReport(issues=issues, summary=summary, model=model,
                                      files_reviewed=len(files), duration_s=0.0)
        result = PipelineResult(
            repo_url=repo_url,
            fetch_result=fetch_result,
            scan_report=scan_report,
            review_report=review_report,
            stage_errors=[],
            duration_s=0.0,
        )
        return report_generator.write_report(result, output_path)


# ---------------------------------------------------------------------------
# ADK tool wrapper
# ---------------------------------------------------------------------------

def _pipeline_result_to_dict(result: PipelineResult) -> dict:
    """
    Explicit field mapping from PipelineResult to a JSON-serializable dict.
    Never dumps dataclasses via vars()/__dict__ wholesale, so adding a new
    internal field later can't accidentally leak into the tool's output.
    """
    return {
        "repo_url": result.repo_url,
        "files_fetched": len(result.fetch_result.files),
        "truncated": result.fetch_result.truncated,
        "findings_count": len(result.scan_report.findings),
        "scan_skipped": list(result.scan_report.skipped),
        "issues": [
            {
                "path": issue.path,
                "line": issue.line,
                "severity": issue.severity,
                "title": issue.title,
                "description": issue.description,
                "suggested_fix": issue.suggested_fix,
                "rule_id": issue.rule_id,
            }
            for issue in result.review_report.issues
        ],
        "summary": result.review_report.summary,
        "model": result.review_report.model,
        "stage_errors": [
            {"stage": e.stage, "message": e.message} for e in result.stage_errors
        ],
        "duration_s": result.duration_s,
    }


def make_review_repo_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """
    Build the ADK-callable tool function bound to a specific CodeReviewAgent
    instance. Real validation of the URL itself is delegated entirely to
    GitHubFetcher.parse_repo_url (single source of truth) — this function
    only checks that the basic argument shape is sane.
    """

    def review_repo_tool(repo_url: str, branch: str = DEFAULT_BRANCH) -> dict:
        """Review a GitHub repository's Python code and return a summary of findings."""
        if not isinstance(repo_url, str) or not repo_url.strip():
            raise ValueError("repo_url must be a non-empty string")

        result = agent.review_repo(repo_url, branch=branch)
        return _pipeline_result_to_dict(result)

    return review_repo_tool


def make_fetch_repo_files_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a standalone 'fetch only' ADK tool bound to a CodeReviewAgent instance."""

    def fetch_repo_files_tool(
        repo_url: str, branch: str = DEFAULT_BRANCH, max_files: int = DEFAULT_MAX_FILES
    ) -> dict:
        """Fetch a GitHub repository's Python files (path + content) without
        scanning or reviewing them. Use this when the user only wants to see
        what files exist, or as the first step of a multi-step review."""
        if not isinstance(repo_url, str) or not repo_url.strip():
            raise ValueError("repo_url must be a non-empty string")

        result = agent.fetch_files(repo_url, branch=branch, max_files=max_files)
        return {
            "repo_url": repo_url,
            "files": [{"path": f.path, "content": f.content} for f in result.files],
            "files_count": len(result.files),
            "truncated": result.truncated,
        }

    return fetch_repo_files_tool


def make_scan_code_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a standalone 'scan only' ADK tool bound to a CodeReviewAgent instance."""

    def scan_code_tool(files: list[dict]) -> dict:
        """Run Semgrep static analysis on a list of files, each given as
        {"path": ..., "content": ...}. Use this on files already fetched by
        fetch_repo_files_tool when the user wants static-analysis findings
        on their own, without an LLM review."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list of {path, content} objects")

        file_results = [
            FileResult(path=f["path"], content=f.get("content", ""), sha="", size=len(f.get("content", "")), url="")
            for f in files
        ]
        scan_report = agent.scan_files(file_results)
        return {
            "findings": [
                {
                    "path": finding.path,
                    "line_start": finding.line_start,
                    "line_end": finding.line_end,
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "message": finding.message,
                    "snippet": finding.snippet,
                }
                for finding in scan_report.findings
            ],
            "scanned": scan_report.scanned,
            "skipped": list(scan_report.skipped),
        }

    return scan_code_tool


def make_generate_review_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a standalone 'review only' ADK tool bound to a CodeReviewAgent instance."""

    def generate_review_tool(files: list[dict], findings: list[dict] | None = None) -> dict:
        """Ask Gemini to produce a structured, severity-ranked code review for
        a list of files, each given as {"path": ..., "content": ...}, optionally
        grounded by Semgrep findings (each {"path", "line_start", "line_end",
        "rule_id", "severity", "message", "snippet"}) from scan_code_tool.
        Use this when files and/or findings were already gathered by the
        other tools and only the review step is still needed."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list of {path, content} objects")

        file_results = [
            FileResult(path=f["path"], content=f.get("content", ""), sha="", size=len(f.get("content", "")), url="")
            for f in files
        ]
        finding_objs = [
            Finding(
                path=finding["path"],
                line_start=finding.get("line_start", 0),
                line_end=finding.get("line_end", 0),
                rule_id=finding.get("rule_id", ""),
                severity=finding.get("severity", "MEDIUM"),
                message=finding.get("message", ""),
                snippet=finding.get("snippet", ""),
            )
            for finding in (findings or [])
        ]
        scan_report = ScanReport(findings=finding_objs, scanned=len(file_results), skipped=[], duration_s=0.0)

        review_report = agent.generate_review(file_results, scan_report)
        return {
            "issues": [
                {
                    "path": issue.path,
                    "line": issue.line,
                    "severity": issue.severity,
                    "title": issue.title,
                    "description": issue.description,
                    "suggested_fix": issue.suggested_fix,
                    "rule_id": issue.rule_id,
                }
                for issue in review_report.issues
            ],
            "summary": review_report.summary,
            "model": review_report.model,
        }

    return generate_review_tool


def make_get_repo_metadata_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a standalone repo-metadata ADK tool bound to a CodeReviewAgent instance."""

    def get_repo_metadata_tool(repo_url: str) -> dict:
        """Look up a GitHub repository's language, size, star count, open
        issue count, and default branch — a fast, lightweight check, useful
        before deciding whether/how deeply to review a repo. Does not fetch
        any file contents."""
        if not isinstance(repo_url, str) or not repo_url.strip():
            raise ValueError("repo_url must be a non-empty string")
        return agent.get_repo_metadata(repo_url)

    return get_repo_metadata_tool


def make_search_code_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a standalone code-search ADK tool bound to a CodeReviewAgent instance."""

    def search_code_in_files_tool(
        files: list[dict], pattern: str, case_sensitive: bool = False
    ) -> dict:
        """Search a list of already-fetched files (each {"path", "content"})
        for a regex pattern, e.g. 'eval(' or 'TODO'. Returns every matching
        line with its path and line number. Use this when the user asks to
        find specific code, not for a full review."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list of {path, content} objects")

        file_results = [
            FileResult(path=f["path"], content=f.get("content", ""), sha="", size=len(f.get("content", "")), url="")
            for f in files
        ]
        matches = agent.search_code(file_results, pattern, case_sensitive=case_sensitive)
        return {"pattern": pattern, "matches": matches, "match_count": len(matches)}

    return search_code_in_files_tool


def make_explain_finding_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a standalone deep-dive-explanation ADK tool bound to a CodeReviewAgent instance."""

    def explain_finding_tool(
        path: str,
        title: str,
        description: str,
        severity: str = "MEDIUM",
        snippet: str = "",
        rule_id: str | None = None,
    ) -> dict:
        """Ask Gemini for a deeper, focused explanation of one specific,
        already-known issue (why it matters concretely, exact fix). Use this
        for follow-up questions like 'explain issue #3 in more detail' —
        not for generating a full review from scratch."""
        if not title and not description:
            raise ValueError("title or description must be provided")

        explanation = agent.explain_finding(
            path=path, title=title, description=description,
            severity=severity, snippet=snippet, rule_id=rule_id,
        )
        return {"path": path, "title": title, "explanation": explanation}

    return explain_finding_tool


def make_generate_report_file_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a standalone report-saving ADK tool bound to a CodeReviewAgent instance."""

    def generate_report_file_tool(
        repo_url: str,
        files: list[dict],
        issues: list[dict],
        summary: str = "",
        model: str = "",
        findings: list[dict] | None = None,
        output_path: str = "review_report.md",
    ) -> dict:
        """Render an already-produced review (files + issues + summary) as a
        Markdown report and save it to disk at output_path. Use this when the
        user wants a saved file, not just a chat summary."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list of {path, content} objects")
        if not isinstance(issues, list):
            raise ValueError("issues must be a list (can be empty)")

        file_results = [
            FileResult(path=f["path"], content=f.get("content", ""), sha="", size=len(f.get("content", "")), url="")
            for f in files
        ]
        issue_objs = [
            ReviewIssue(
                path=i["path"], line=i.get("line", 0), severity=i.get("severity", "MEDIUM"),
                title=i.get("title", ""), description=i.get("description", ""),
                suggested_fix=i.get("suggested_fix", ""), rule_id=i.get("rule_id"),
            )
            for i in issues
        ]
        finding_objs = [
            Finding(
                path=fnd["path"], line_start=fnd.get("line_start", 0), line_end=fnd.get("line_end", 0),
                rule_id=fnd.get("rule_id", ""), severity=fnd.get("severity", "MEDIUM"),
                message=fnd.get("message", ""), snippet=fnd.get("snippet", ""),
            )
            for fnd in (findings or [])
        ]

        path = agent.save_report(
            repo_url=repo_url, files=file_results, findings=finding_objs,
            issues=issue_objs, summary=summary, model=model, output_path=output_path,
        )
        return {"output_path": path}

    return generate_report_file_tool


def build_adk_agent(
    github_token: str,
    gemini_api_key: str,
    semgrep_config: str = DEFAULT_SEMGREP_CONFIG,
) -> Agent:
    """Construct the Google ADK Agent definition wrapping the review pipeline.

    Exposes a one-shot tool (review_repo_tool), three granular pipeline-stage
    tools (fetch_repo_files_tool, scan_code_tool, generate_review_tool), and
    four standalone capability tools (get_repo_metadata_tool,
    search_code_in_files_tool, explain_finding_tool,
    generate_report_file_tool) — eight tools total — so the model can run the
    whole pipeline in one call, plan a multi-step sequence itself, or reach
    for a narrower capability outside the review pipeline entirely.
    """
    code_review_agent = CodeReviewAgent(
        github_token=github_token,
        gemini_api_key=gemini_api_key,
        semgrep_config=semgrep_config,
    )

    review_repo_tool = make_review_repo_tool(code_review_agent)
    review_repo_tool.__name__ = "review_repo_tool"

    fetch_repo_files_tool = make_fetch_repo_files_tool(code_review_agent)
    fetch_repo_files_tool.__name__ = "fetch_repo_files_tool"

    scan_code_tool = make_scan_code_tool(code_review_agent)
    scan_code_tool.__name__ = "scan_code_tool"

    generate_review_tool = make_generate_review_tool(code_review_agent)
    generate_review_tool.__name__ = "generate_review_tool"

    get_repo_metadata_tool = make_get_repo_metadata_tool(code_review_agent)
    get_repo_metadata_tool.__name__ = "get_repo_metadata_tool"

    search_code_in_files_tool = make_search_code_tool(code_review_agent)
    search_code_in_files_tool.__name__ = "search_code_in_files_tool"

    explain_finding_tool = make_explain_finding_tool(code_review_agent)
    explain_finding_tool.__name__ = "explain_finding_tool"

    generate_report_file_tool = make_generate_report_file_tool(code_review_agent)
    generate_report_file_tool.__name__ = "generate_report_file_tool"

    return Agent(
        name="code_review_agent",
        model=DEFAULT_MODEL,
        description=(
            "Reviews a GitHub repository's Python code for security and "
            "quality issues using static analysis and an LLM."
        ),
        instruction=(
            "You are a code review agent. Your scope is reviewing GitHub "
            "repositories' Python code for security and quality issues — "
            "nothing else. If the user asks something unrelated to that scope "
            "(general chit-chat, unrelated trivia, requests to do something "
            "outside code review), politely say that's outside what you do "
            "and offer to review a repo instead. Do not call any tool for an "
            "out-of-scope request.\n\n"
            "When the user asks for a full review of a GitHub repository, call "
            "review_repo_tool with the repository URL (and branch, if given) — "
            "it runs fetch, scan, and review in one step and is the fastest path "
            "for a typical request.\n\n"
            "If the user asks for just a quick look at a repo before committing to "
            "a full review (e.g. 'what kind of repo is this', 'how big is it'), "
            "use get_repo_metadata_tool first.\n\n"
            "If the user explicitly asks for just one part of the process (e.g. "
            "'just show me the files', 'just run static analysis', 'just review "
            "this code I'm giving you'), use the individual fetch_repo_files_tool, "
            "scan_code_tool, and generate_review_tool, passing the files and "
            "findings returned by one tool into the next as needed.\n\n"
            "If the user wants to find specific code (a pattern, function, or "
            "keyword) rather than a full review, use search_code_in_files_tool "
            "on files you already fetched.\n\n"
            "If the user asks you to go deeper on one specific issue you already "
            "reported (e.g. 'explain issue #3'), use explain_finding_tool instead "
            "of re-running the whole review.\n\n"
            "If the user wants the review saved as a file rather than just "
            "summarized in chat, use generate_report_file_tool with the files, "
            "issues, and summary you already have.\n\n"
            "Always summarize the resulting issues for the user, prioritized by "
            "severity, and mention any stage_errors plainly if present."
        ),
        tools=[
            FunctionTool(review_repo_tool),
            FunctionTool(fetch_repo_files_tool),
            FunctionTool(scan_code_tool),
            FunctionTool(generate_review_tool),
            FunctionTool(get_repo_metadata_tool),
            FunctionTool(search_code_in_files_tool),
            FunctionTool(explain_finding_tool),
            FunctionTool(generate_report_file_tool),
        ],
    )


def make_fetch_pr_files_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a PR-diff fetch tool bound to a CodeReviewAgent instance."""

    def fetch_pr_files_tool(pr_url: str, max_files: int = DEFAULT_MAX_FILES) -> dict:
        """Fetch Python files that were added or modified in a GitHub Pull Request.
        Accepts a PR URL (https://github.com/owner/repo/pull/123).
        Returns the changed files with full content, the PR number, and a
        truncated flag. Use this as the first step of a PR review instead of
        fetch_repo_files_tool, which fetches the whole repo."""
        if not isinstance(pr_url, str) or not pr_url.strip():
            raise ValueError("pr_url must be a non-empty string")
        fetch_result, pr_number = agent.fetch_pr_files(pr_url, max_files=max_files)
        return {
            "pr_url": pr_url,
            "pr_number": pr_number,
            "files": [{"path": f.path, "content": f.content} for f in fetch_result.files],
            "files_count": len(fetch_result.files),
            "truncated": fetch_result.truncated,
        }

    return fetch_pr_files_tool


def make_validate_findings_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a findings-validator tool bound to a CodeReviewAgent instance."""

    def validate_findings_tool(issues: list[dict], files: list[dict]) -> dict:
        """Cross-check a list of already-produced review issues against the actual
        source files to identify likely false positives. Each issue must have
        {path, line, severity, title, description}. Each file must have
        {path, content}. Returns a list of validations, one per issue, each with
        {index, confidence (HIGH/MEDIUM/LOW), false_positive (bool), note}.
        Use this after generate_review_tool to filter out weak findings before
        presenting results to the user."""
        if not isinstance(issues, list) or not issues:
            raise ValueError("issues must be a non-empty list")
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list")

        issue_objs = [
            ReviewIssue(
                path=i["path"], line=i.get("line", 0),
                severity=i.get("severity", "MEDIUM"),
                title=i.get("title", ""), description=i.get("description", ""),
                suggested_fix=i.get("suggested_fix", ""), rule_id=i.get("rule_id"),
            )
            for i in issues
        ]
        file_objs = [
            FileResult(path=f["path"], content=f.get("content", ""),
                       sha="", size=len(f.get("content", "")), url="")
            for f in files
        ]
        validations = agent.validate_review_findings(issue_objs, file_objs)
        confirmed = sum(1 for v in validations if not v.get("false_positive"))
        false_positives = sum(1 for v in validations if v.get("false_positive"))
        return {
            "validations": validations,
            "total": len(validations),
            "confirmed": confirmed,
            "false_positives": false_positives,
        }

    return validate_findings_tool


def make_post_pr_review_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a tool that posts review findings as inline comments on a GitHub PR."""

    def post_pr_review_tool(
        pr_url: str,
        issues: list[dict],
        summary: str = "",
        event: str = "COMMENT",
    ) -> dict:
        """Post review findings as inline comments on a GitHub Pull Request.

        pr_url: the PR URL (https://github.com/owner/repo/pull/123).
        issues: list of findings from generate_review_tool, each with
                {path, line, severity, title, description, suggested_fix}.
        summary: overall review summary posted as the PR review body text.
        event: "COMMENT" (default, non-blocking) | "REQUEST_CHANGES" | "APPROVE".

        Returns {review_id, html_url, state, comments_posted, fallback}.
        If inline comments fail because the lines are not in the diff, the tool
        automatically falls back to posting a single general PR comment instead.
        Always call this as the last step of a PR review workflow."""
        if not isinstance(pr_url, str) or not pr_url.strip():
            raise ValueError("pr_url must be a non-empty string")
        if not isinstance(issues, list):
            raise ValueError("issues must be a list of dicts")
        return agent._fetcher.post_pr_review(pr_url, issues, summary, event)

    return post_pr_review_tool


def build_multi_agent_system(
    github_token: str,
    gemini_api_key: str,
    semgrep_config: str = DEFAULT_SEMGREP_CONFIG,
) -> Agent:
    """Build a 3-layer multi-agent graph for the ADK playground.

    Architecture
    ------------
    Layer 0 — root_agent (Orchestrator)
        Has one direct tool (review_repo_tool) for quick one-shot reviews,
        plus three Layer-1 sub-agents for deeper, specialized work.

    Layer 1 — three domain specialists:
        - scout_agent          : lightweight repo inspection (no LLM review)
        - analysis_coordinator : decides security vs quality vs both, delegates
        - report_agent         : explanations + saved Markdown files

    Layer 2 — two analysis specialists (children of analysis_coordinator):
        - security_agent : Semgrep + LLM security review + issue deep-dive
        - quality_agent  : LLM quality/style review (no Semgrep)

    All six agents share a single CodeReviewAgent instance underneath — each
    just gets a different subset of the eight available tool functions.
    """

    # ── One shared pipeline instance for all agents ─────────────────────────
    pipeline = CodeReviewAgent(
        github_token=github_token,
        gemini_api_key=gemini_api_key,
        semgrep_config=semgrep_config,
    )

    def _ft(factory) -> FunctionTool:
        """Create a fresh FunctionTool from a tool factory, bound to `pipeline`."""
        return FunctionTool(factory(pipeline))

    # ── Layer 2c: Validator Agent ────────────────────────────────────────────
    validator_agent = Agent(
        name="validator_agent",
        model=DEFAULT_MODEL,
        description=(
            "Findings Validator: cross-checks security review findings against "
            "the actual source code to identify false positives before reporting."
        ),
        instruction=(
            "You are the Findings Validator. You act as a peer reviewer for the "
            "security_agent's output — your job is to catch false positives before "
            "they reach the user.\n\n"
            "WORKFLOW:\n"
            "1. You receive a list of security findings and the source files they "
            "   reference (passed from the analysis_coordinator after security_agent "
            "   completes).\n"
            "2. Call validate_findings_tool with those issues and files.\n"
            "3. Report the validation results: how many findings were confirmed "
            "   (HIGH/MEDIUM confidence) vs. flagged as probable false positives (LOW).\n"
            "4. List any false-positive findings by index with the validator's note.\n"
            "5. Transfer back to analysis_coordinator.\n\n"
            "Be concise — one paragraph is enough. The goal is a quick confidence "
            "check, not a full re-review."
        ),
        tools=[
            _ft(make_validate_findings_tool),
        ],
    )

    # ── Layer 2a: Security Analyst ───────────────────────────────────────────
    security_agent = Agent(
        name="security_agent",
        model=DEFAULT_MODEL,
        description=(
            "Security Analyst: runs Semgrep static analysis and an LLM "
            "security-focused review; can explain individual findings in depth."
        ),
        instruction=(
            "You are the Security Analyst. Your job: find and explain security "
            "vulnerabilities in Python repositories.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — pull Python files from the repo.\n"
            "2. scan_code_tool — run Semgrep on those files.\n"
            "3. generate_review_tool — pass files + Semgrep findings to Gemini "
            "   for a security-focused structured review.\n"
            "4. explain_finding_tool — if asked to elaborate on a specific issue, "
            "   use this instead of re-running the full review.\n\n"
            "Always rank issues CRITICAL → HIGH → MEDIUM → LOW. Include file:line "
            "and rule_id for every finding. If Semgrep returns nothing, still run "
            "generate_review_tool — the LLM catches semantic issues Semgrep misses.\n\n"
            "Stay purely security-focused. When done, transfer back to your parent "
            "(analysis_coordinator) so it can decide whether quality review is also "
            "needed."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_scan_code_tool),
            _ft(make_generate_review_tool),
            _ft(make_explain_finding_tool),
        ],
    )

    # ── Layer 2b: Quality Reviewer ───────────────────────────────────────────
    quality_agent = Agent(
        name="quality_agent",
        model=DEFAULT_MODEL,
        description=(
            "Quality Reviewer: LLM-based code quality, readability, and best-practice "
            "assessment — no security angle, no Semgrep."
        ),
        instruction=(
            "You are the Quality Reviewer. You assess code quality, readability, and "
            "Python best practices — NOT security vulnerabilities.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — pull the Python files.\n"
            "2. (optional) search_code_in_files_tool — quickly spot anti-patterns "
            "   like bare 'except:', 'global', magic numbers, or deep nesting before "
            "   the LLM pass, so you can call them out specifically.\n"
            "3. generate_review_tool — LLM review covering: naming conventions, "
            "   function complexity, docstring coverage, DRY, error handling, PEP 8.\n\n"
            "Severity guide: LOW/MEDIUM for style; HIGH only when a quality flaw is "
            "likely to cause a runtime bug. Do NOT call scan_code_tool.\n\n"
            "When done, transfer back to your parent (analysis_coordinator)."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_generate_review_tool),
            _ft(make_search_code_tool),
        ],
    )

    # ── Layer 1a: Analysis Coordinator ──────────────────────────────────────
    analysis_coordinator = Agent(
        name="analysis_coordinator",
        model=DEFAULT_MODEL,
        description=(
            "Analysis Coordinator: decides whether to run a security review, a quality "
            "review, or both, then delegates to the right specialist and aggregates "
            "the combined results."
        ),
        instruction=(
            "You are the Analysis Coordinator. You manage two specialist agents:\n"
            "  • security_agent — Semgrep + LLM security review\n"
            "  • quality_agent  — LLM quality/readability review\n\n"
            "ROUTING:\n"
            "- 'Security review' / 'vulnerabilities' / 'CVE' / 'exploit' "
            "  → transfer to security_agent only.\n"
            "- 'Quality review' / 'style' / 'readability' / 'best practices' "
            "  → transfer to quality_agent only.\n"
            "- 'Full review' / 'both' / 'deep dive' / no clear preference "
            "  → transfer to security_agent first; after it returns, transfer to "
            "  quality_agent; then aggregate.\n\n"
            "AGGREGATION (after specialists return):\n"
            "Summarize the combined findings for the user:\n"
            "  1. Security issues (CRITICAL → HIGH → MEDIUM → LOW)\n"
            "  2. Quality issues (HIGH → MEDIUM → LOW)\n"
            "State how many total issues each specialist found."
        ),
        sub_agents=[security_agent, quality_agent, validator_agent],
    )

    # ── Layer 1b: Repo Scout ─────────────────────────────────────────────────
    scout_agent = Agent(
        name="scout_agent",
        model=DEFAULT_MODEL,
        description=(
            "Repo Scout: lightweight repository inspection — metadata, file listing, "
            "and pattern search — without running any LLM review."
        ),
        instruction=(
            "You are the Repo Scout. You inspect a GitHub repository at surface level "
            "so the user can decide whether and how to proceed — without a full review.\n\n"
            "TOOLS:\n"
            "- get_repo_metadata_tool: language, stars, size, open issues, default "
            "  branch. Always start here — it's fast and costs no LLM tokens.\n"
            "- fetch_repo_files_tool: retrieve actual Python file paths + contents.\n"
            "- search_code_in_files_tool: grep across fetched files for a regex "
            "  pattern (e.g. 'eval(', 'TODO', 'password').\n\n"
            "Suggested flow: metadata first, fetch if the user wants files, then "
            "search if they ask 'does it use X?'. Keep responses concise. You are "
            "NOT doing security or quality analysis — transfer back to the "
            "orchestrator if the user asks for that."
        ),
        tools=[
            _ft(make_get_repo_metadata_tool),
            _ft(make_fetch_repo_files_tool),
            _ft(make_search_code_tool),
        ],
    )

    # ── Layer 1d: PR Reviewer ────────────────────────────────────────────────
    pr_agent = Agent(
        name="pr_agent",
        model=DEFAULT_MODEL,
        description=(
            "PR Reviewer: reviews only the Python files changed in a GitHub Pull "
            "Request — not the entire repository."
        ),
        instruction=(
            "You are the PR Reviewer. You focus on changes introduced by a specific "
            "Pull Request, not the whole repository.\n\n"
            "WORKFLOW:\n"
            "1. fetch_pr_files_tool — given a PR URL "
            "(https://github.com/owner/repo/pull/123), fetch only the Python files "
            "that were added or modified in that PR.\n"
            "2. scan_code_tool — run Semgrep on those changed files.\n"
            "3. generate_review_tool — LLM review of the changed files + findings.\n"
            "4. (optional) validate_findings_tool — cross-check the findings against "
            "the actual code if the user wants a false-positive filter pass.\n"
            "5. (optional) post_pr_review_tool — post the findings as inline comments "
            "directly on the GitHub PR. Use when the user says 'post', 'comment', "
            "'post to GitHub', or 'post the review'. Pass the issues list from "
            "generate_review_tool and a brief summary.\n\n"
            "Always start your response by stating: which PR you reviewed, how many "
            "Python files changed, and the total issues found. Prioritize findings "
            "by CRITICAL → HIGH → MEDIUM → LOW."
        ),
        tools=[
            _ft(make_fetch_pr_files_tool),
            _ft(make_scan_code_tool),
            _ft(make_generate_review_tool),
            _ft(make_validate_findings_tool),
            _ft(make_post_pr_review_tool),
        ],
    )

    # ── Layer 1c: Report Writer ──────────────────────────────────────────────
    report_agent = Agent(
        name="report_agent",
        model=DEFAULT_MODEL,
        description=(
            "Report Writer: produces deep-dive explanations of specific findings "
            "and saves full Markdown review reports to disk."
        ),
        instruction=(
            "You are the Report Writer. You work with already-produced review results. "
            "You do NOT fetch files, run Semgrep, or generate new reviews.\n\n"
            "TOOLS:\n"
            "- explain_finding_tool: given one known finding (path, title, description, "
            "  severity, optional code snippet), ask Gemini for a focused 3-6 sentence "
            "  explanation — why it matters in practice, exact fix. Use for "
            "  'explain issue #N' or 'go deeper on that finding'.\n"
            "- generate_report_file_tool: render files + issues + summary as a "
            "  Markdown file and save to disk. Returns the output_path. Use when the "
            "  user says 'save the report' or 'write it to a file'.\n\n"
            "If no review has been done yet, tell the user to ask for a security or "
            "quality review first."
        ),
        tools=[
            _ft(make_explain_finding_tool),
            _ft(make_generate_report_file_tool),
        ],
    )

    # ── Layer 0: Root Orchestrator ───────────────────────────────────────────
    root = Agent(
        name="code_review_agent",
        model=DEFAULT_MODEL,
        description=(
            "Master orchestrator of a 3-layer multi-agent code review system. "
            "Routes user requests to specialist agents or runs a one-shot quick review."
        ),
        instruction=(
            "You are the master orchestrator of a 3-layer multi-agent code review "
            "system with 8 specialized agents.\n\n"
            "ARCHITECTURE:\n"
            "  Layer 0: you (orchestrator)\n"
            "  Layer 1: scout_agent | analysis_coordinator | report_agent | pr_agent\n"
            "  Layer 2: security_agent | quality_agent | validator_agent "
            "(inside analysis_coordinator)\n\n"
            "YOUR DIRECT TOOL (fastest path):\n"
            "- review_repo_tool: one-shot full review (fetch + Semgrep + LLM in one "
            "  call). Use when the user wants a quick complete review of a whole repo.\n\n"
            "SUB-AGENTS (delegate with transfer_to_agent):\n"
            "- scout_agent: lightweight repo inspection — metadata, file list, "
            "  pattern search. Use for 'what is this repo?', 'how big?', "
            "  'does it use X?'\n"
            "- analysis_coordinator: deep repo review — delegates to security_agent, "
            "  quality_agent, and validator_agent as needed. Use for 'security review',"
            "  'quality review', 'full deep review', 'find vulnerabilities'.\n"
            "- pr_agent: Pull Request review — reviews only changed files in a PR. "
            "  Use when the user provides a PR URL "
            "(https://github.com/owner/repo/pull/N) or asks to 'review this PR'.\n"
            "- report_agent: output and explanations. Use for 'explain issue #N', "
            "  'save the report', 'write it to a file'.\n\n"
            "ROUTING RULES:\n"
            "1. Repo URL + 'quick review' / no specific focus → review_repo_tool.\n"
            "2. 'What is this repo?' / 'scout' / 'list files' → scout_agent.\n"
            "3. 'Security review' / 'quality review' / 'deep dive' → "
            "   analysis_coordinator.\n"
            "4. PR URL or 'review this PR' / 'review the diff' → pr_agent.\n"
            "5. 'Explain issue' / 'save report' → report_agent.\n"
            "6. Off-topic requests → politely decline.\n\n"
            "Always tell the user which agent you are delegating to and why."
        ),
        tools=[
            FunctionTool(make_review_repo_tool(pipeline)),
        ],
        sub_agents=[scout_agent, analysis_coordinator, report_agent, pr_agent],
    )

    return root


# --- Expose root_agent for the loader ---------------------------------------
import os
from dotenv import load_dotenv

# Ensure environment variables are loaded and override any invalid/expired shell values
load_dotenv(override=True)

github_token = os.environ.get("GITHUB_TOKEN", "")
gemini_api_key = os.environ.get("GEMINI_API_KEY", "")

# ADK's own Agent/Gemini model call (used for the playground chat itself,
# separate from GeminiReviewer's own genai.Client) authenticates via
# GOOGLE_API_KEY, not GEMINI_API_KEY -- without this, "Hi" gets no response
# and the Traces panel stays empty because the model call fails auth silently.
if gemini_api_key and not os.environ.get("GOOGLE_API_KEY"):
    os.environ["GOOGLE_API_KEY"] = gemini_api_key

# Guard construction so that importing agent.py in tests (where
# GITHUB_TOKEN / GEMINI_API_KEY may be dummy CI values that fail
# genai.Client's key-format check) doesn't kill the whole test collection.
# adk web only needs root_agent when real credentials are present.
try:
    root_agent = build_multi_agent_system(
        github_token=github_token,
        gemini_api_key=gemini_api_key,
    )
except Exception as _build_exc:  # noqa: BLE001
    logger.warning(
        "ADK agent graph could not be built — running without root_agent "
        "(expected in CI or when credentials are absent): %s",
        _build_exc,
    )
    root_agent = None  # type: ignore[assignment]
