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
from dependency_scanner import scan_dependencies
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
DEFAULT_MODEL = "gemini-2.0-flash"
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

    def generate_threat_model(self, files: list[FileResult]) -> dict:
        """Produce a STRIDE threat model from a list of source files."""
        return self._reviewer.generate_threat_model(files)

    def generate_crypto_audit(self, files: list[FileResult]) -> dict:
        """Audit source files for weak or misused cryptography."""
        return self._reviewer.generate_crypto_audit(files)

    def scan_dependency_cves(self, requirements_content: str) -> dict:
        """Check requirements.txt content against the OSV vulnerability database."""
        return scan_dependencies(requirements_content)

    def generate_injection_audit(self, files: list[FileResult]) -> dict:
        """Audit source files for injection vulnerabilities (SQL, cmd, SSTI, XSS, SSRF)."""
        return self._reviewer.generate_injection_audit(files)

    def generate_auth_audit(self, files: list[FileResult]) -> dict:
        """Audit source files for authentication and authorization vulnerabilities."""
        return self._reviewer.generate_auth_audit(files)

    def generate_secrets_audit(self, files: list[FileResult]) -> dict:
        """Scan source files for hardcoded secrets, credentials, and sensitive values."""
        return self._reviewer.generate_secrets_audit(files)

    def generate_data_flow_analysis(self, files: list[FileResult]) -> dict:
        """Perform taint analysis: trace user input to dangerous sinks."""
        return self._reviewer.generate_data_flow_analysis(files)

    def generate_complexity_report(self, files: list[FileResult]) -> dict:
        """Analyze cyclomatic complexity, god classes, deep nesting, and duplication."""
        return self._reviewer.generate_complexity_report(files)

    def generate_test_coverage_report(
        self, source_files: list[FileResult], test_files: list[FileResult]
    ) -> dict:
        """Analyze test coverage gaps — untested functions, missing edge cases."""
        return self._reviewer.generate_test_coverage_report(source_files, test_files)

    def generate_doc_quality_report(self, files: list[FileResult]) -> dict:
        """Assess documentation quality — missing docstrings, type hints, stale comments."""
        return self._reviewer.generate_doc_quality_report(files)

    def map_to_owasp(self, findings: list[dict]) -> dict:
        """Map findings to OWASP Top 10 2021 categories."""
        return self._reviewer.map_to_owasp(findings)

    def map_to_cwe(self, findings: list[dict]) -> dict:
        """Map findings to CWE Top 25 entries."""
        return self._reviewer.map_to_cwe(findings)

    def deduplicate_findings(self, all_findings: list[dict]) -> dict:
        """Merge and deduplicate findings from multiple analysis agents."""
        return self._reviewer.deduplicate_findings(all_findings)

    def generate_risk_scores(self, findings: list[dict]) -> dict:
        """Generate CVSS-like composite risk scores for security findings."""
        return self._reviewer.generate_risk_scores(findings)

    def generate_remediation_patches(
        self, findings: list[dict], files: list[FileResult]
    ) -> dict:
        """Generate concrete, copy-pasteable fix patches for security findings."""
        return self._reviewer.generate_remediation_patches(findings, files)

    def analyze_context(self, files: list[FileResult]) -> dict:
        """Analyze the codebase to understand framework, architecture, and security surface."""
        return self._reviewer.analyze_context(files)

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


def make_fetch_requirements_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a tool that fetches requirements.txt from a GitHub repo."""

    def fetch_requirements_tool(repo_url: str, branch: str = DEFAULT_BRANCH) -> dict:
        """Fetch the requirements.txt file from a GitHub repository.

        repo_url: https://github.com/owner/repo
        Returns {content, found} where content is the raw requirements.txt text.
        If no requirements.txt is found, returns {found: false, content: ''}.
        Use this before dependency_scan_tool."""
        owner, repo = agent._fetcher.parse_repo_url(repo_url)
        base = agent._fetcher._base_url
        for filename in ("requirements.txt", "requirements/base.txt",
                         "requirements/prod.txt", "requirements-prod.txt"):
            url = f"{base}/repos/{owner}/{repo}/contents/{filename}?ref={branch}"
            try:
                import base64 as _b64
                data = agent._fetcher._get(url)
                content = _b64.b64decode(data.get("content", "")).decode("utf-8")
                return {"found": True, "filename": filename, "content": content}
            except Exception:
                continue
        return {"found": False, "filename": None, "content": ""}

    return fetch_requirements_tool


def make_dependency_scan_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a CVE dependency scanner tool."""

    def dependency_scan_tool(requirements_content: str) -> dict:
        """Check Python dependencies for known CVEs via the OSV database.

        requirements_content: raw text of a requirements.txt file (from
        fetch_requirements_tool).

        Returns {packages_checked, vulnerable, clean, no_version}.
        vulnerable is a list of {package, version, cve_count, cves: [
            {id, summary, severity, fixed_in}
        ]}.
        Always call fetch_requirements_tool first to get the content."""
        if not isinstance(requirements_content, str) or not requirements_content.strip():
            raise ValueError("requirements_content must be a non-empty string")
        return agent.scan_dependency_cves(requirements_content)

    return dependency_scan_tool


def make_crypto_audit_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a cryptography audit tool."""

    def crypto_audit_tool(files: list[dict]) -> dict:
        """Audit source files for weak, broken, or misused cryptography.

        files: list of {path, content} dicts from fetch_repo_files_tool.

        Detects: MD5/SHA1 password hashing, Python random for secrets,
        ECB cipher mode, hardcoded/weak IVs, disabled TLS verification,
        obsolete algorithms (DES, RC4), base64 as encryption, weak key
        derivation.

        Returns {findings: [{path, line, severity, pattern, current_code,
        why_dangerous, correct_alternative, attacker_effort}], summary}.
        Call fetch_repo_files_tool first, then pass the files here."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list")
        file_objs = [
            FileResult(path=f["path"], content=f.get("content", ""),
                       sha="", size=len(f.get("content", "")), url="")
            for f in files
        ]
        return agent.generate_crypto_audit(file_objs)

    return crypto_audit_tool


def make_threat_model_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    """Build a STRIDE threat model tool bound to a CodeReviewAgent instance."""

    def threat_model_tool(files: list[dict]) -> dict:
        """Generate a full STRIDE threat model from source files.

        files: list of {path, content} dicts — the output of fetch_repo_files_tool.

        Returns a structured threat model with:
        - assets: what is worth protecting in this system
        - entry_points: where attackers can send untrusted input
        - trust_boundaries: what is trusted vs untrusted
        - stride_threats: Spoofing, Tampering, Repudiation, Information
          Disclosure, Denial of Service, Elevation of Privilege — each
          mapped to a specific component and severity
        - attack_scenarios: top attack paths with step-by-step attacker
          actions, tools used, impact, and what defenses are missing
        - missing_defenses: list of controls the codebase lacks
        - risk_summary: overall risk assessment in 2-3 sentences

        Use fetch_repo_files_tool first, then pass the files here."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list")
        file_objs = [
            FileResult(
                path=f["path"],
                content=f.get("content", ""),
                sha="", size=len(f.get("content", "")), url="",
            )
            for f in files
        ]
        return agent.generate_threat_model(file_objs)

    return threat_model_tool


def make_injection_audit_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def injection_audit_tool(files: list[dict]) -> dict:
        """Audit source files for injection vulnerabilities: SQL injection, command injection,
        SSTI, XSS, SSRF, path traversal, LDAP, XXE, and header injection.
        files: list of {path, content} from fetch_repo_files_tool.
        Returns {findings: [{path, line, severity, injection_type, vulnerable_code,
        attack_vector, attack_chain, impact, fix}], summary}."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list")
        file_objs = [FileResult(path=f["path"], content=f.get("content",""),
                                sha="", size=len(f.get("content","")), url="") for f in files]
        return agent.generate_injection_audit(file_objs)
    return injection_audit_tool


def make_auth_audit_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def auth_audit_tool(files: list[dict]) -> dict:
        """Audit source files for authentication and authorization vulnerabilities:
        IDOR, broken auth, privilege escalation, missing access controls, JWT issues.
        files: list of {path, content} from fetch_repo_files_tool.
        Returns {findings: [{path, line, severity, category, vulnerable_code,
        scenario, impact, fix}], summary}."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list")
        file_objs = [FileResult(path=f["path"], content=f.get("content",""),
                                sha="", size=len(f.get("content","")), url="") for f in files]
        return agent.generate_auth_audit(file_objs)
    return auth_audit_tool


def make_secrets_audit_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def secrets_audit_tool(files: list[dict]) -> dict:
        """Scan source files for hardcoded secrets: API keys, passwords, private keys,
        JWT signing secrets, database credentials, OAuth client secrets.
        files: list of {path, content} from fetch_repo_files_tool.
        Returns {findings: [{path, line, severity, secret_type, description,
        redacted_value, risk, fix}], summary}."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list")
        file_objs = [FileResult(path=f["path"], content=f.get("content",""),
                                sha="", size=len(f.get("content","")), url="") for f in files]
        return agent.generate_secrets_audit(file_objs)
    return secrets_audit_tool


def make_data_flow_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def data_flow_tool(files: list[dict]) -> dict:
        """Perform taint analysis on source files: trace untrusted user input from
        sources (HTTP params, CLI args, file input) through the application to
        dangerous sinks (DB queries, shell commands, template rendering, SSRF).
        files: list of {path, content} from fetch_repo_files_tool.
        Returns {tainted_paths: [{path, source_line, sink_line, source, sink,
        sink_type, intermediate_steps, sanitizers_present, sanitization_adequate,
        severity, exploit}], safe_paths, summary}."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list")
        file_objs = [FileResult(path=f["path"], content=f.get("content",""),
                                sha="", size=len(f.get("content","")), url="") for f in files]
        return agent.generate_data_flow_analysis(file_objs)
    return data_flow_tool


def make_complexity_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def complexity_tool(files: list[dict]) -> dict:
        """Analyze code complexity: cyclomatic complexity per function, deep nesting,
        god classes, magic numbers, duplicated logic, long parameter lists.
        Files with complexity > 10 are flagged HIGH; > 20 CRITICAL.
        files: list of {path, content} from fetch_repo_files_tool.
        Returns {findings: [{path, line, severity, metric, function_or_class,
        measured_value, description, refactoring_hint}], most_complex_functions,
        summary}."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list")
        file_objs = [FileResult(path=f["path"], content=f.get("content",""),
                                sha="", size=len(f.get("content","")), url="") for f in files]
        return agent.generate_complexity_report(file_objs)
    return complexity_tool


def make_test_coverage_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def test_coverage_tool(source_files: list[dict], test_files: list[dict] | None = None) -> dict:
        """Analyze test coverage gaps by comparing source files against test files.
        Identifies untested functions, missing error path coverage, missing edge cases,
        and test quality issues (overly broad mocks, happy-path-only tests).
        source_files: list of {path, content} for source modules.
        test_files: list of {path, content} for test files (optional, pass empty list if none).
        Returns {untested_functions, coverage_gaps, test_quality_issues, summary}."""
        if not isinstance(source_files, list) or not source_files:
            raise ValueError("source_files must be a non-empty list")
        src_objs = [FileResult(path=f["path"], content=f.get("content",""),
                               sha="", size=len(f.get("content","")), url="")
                    for f in source_files]
        tst_objs = [FileResult(path=f["path"], content=f.get("content",""),
                               sha="", size=len(f.get("content","")), url="")
                    for f in (test_files or [])]
        return agent.generate_test_coverage_report(src_objs, tst_objs)
    return test_coverage_tool


def make_doc_quality_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def doc_quality_tool(files: list[dict]) -> dict:
        """Assess documentation quality: missing docstrings, missing type hints,
        stale comments, misleading variable/function/class names, TODO debt.
        files: list of {path, content} from fetch_repo_files_tool.
        Returns {findings: [{path, line, severity, doc_issue, target,
        description, suggested_docstring}], coverage_stats, summary}."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list")
        file_objs = [FileResult(path=f["path"], content=f.get("content",""),
                                sha="", size=len(f.get("content","")), url="") for f in files]
        return agent.generate_doc_quality_report(file_objs)
    return doc_quality_tool


def make_owasp_mapping_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def owasp_mapping_tool(findings: list[dict]) -> dict:
        """Map security findings to OWASP Top 10 2021 categories (A01-A10).
        findings: list of finding dicts with {severity, title, description}.
        Returns {mappings: [{finding_index, owasp_category, owasp_name,
        justification}], category_summary, top_risk_categories, summary}.
        Use after collecting findings from multiple security agents."""
        if not isinstance(findings, list) or not findings:
            raise ValueError("findings must be a non-empty list")
        return agent.map_to_owasp(findings)
    return owasp_mapping_tool


def make_cwe_mapping_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def cwe_mapping_tool(findings: list[dict]) -> dict:
        """Map security findings to CWE Top 25 Most Dangerous Software Weaknesses.
        findings: list of finding dicts with {severity, title, description}.
        Returns {mappings: [{finding_index, cwe_id, cwe_name, rank_in_top25,
        justification}], top_cwes_present, summary}.
        Use after collecting findings from multiple security agents."""
        if not isinstance(findings, list) or not findings:
            raise ValueError("findings must be a non-empty list")
        return agent.map_to_cwe(findings)
    return cwe_mapping_tool


def make_dedup_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def dedup_tool(all_findings: list[dict]) -> dict:
        """Deduplicate and merge findings from multiple security analysis agents.
        Identifies exact duplicates (same file+line+type), near-duplicates (same
        vulnerability at nearby lines), and semantic duplicates (same issue described
        differently). Produces one clean, merged finding per unique issue.
        all_findings: list of finding dicts, each with a 'source_agent' field.
        Returns {deduplicated_findings, original_count, deduplicated_count,
        merges_performed, summary}."""
        if not isinstance(all_findings, list) or not all_findings:
            raise ValueError("all_findings must be a non-empty list")
        return agent.deduplicate_findings(all_findings)
    return dedup_tool


def make_risk_score_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def risk_score_tool(findings: list[dict]) -> dict:
        """Generate CVSS-like composite risk scores for security findings.
        Scores each finding on Impact (0-10), Exploitability (0-10), Scope (0-10),
        and Detectability (0-10), then computes a weighted composite score.
        Ranks findings by priority and produces an overall project risk score.
        findings: list of finding dicts with {severity, title, description}.
        Returns {scored_findings: [{finding_index, composite_score, risk_level,
        priority_rank, rationale}], overall_project_score, overall_risk_level,
        immediate_action_required, summary}."""
        if not isinstance(findings, list) or not findings:
            raise ValueError("findings must be a non-empty list")
        return agent.generate_risk_scores(findings)
    return risk_score_tool


def make_remediation_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def remediation_tool(findings: list[dict], files: list[dict]) -> dict:
        """Generate concrete, copy-pasteable fix patches for security findings.
        Produces exact before/after code for each finding, not vague advice.
        findings: list of finding dicts with {path, line, title, description,
        vulnerable_code}.
        files: list of {path, content} source files for context.
        Returns {patches: [{finding_index, path, line, title, before, after,
        explanation, dependencies, breaking_change}], summary}."""
        if not isinstance(findings, list) or not findings:
            raise ValueError("findings must be a non-empty list")
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list")
        file_objs = [FileResult(path=f["path"], content=f.get("content",""),
                                sha="", size=len(f.get("content","")), url="") for f in files]
        return agent.generate_remediation_patches(findings, file_objs)
    return remediation_tool


def make_context_analysis_tool(agent: CodeReviewAgent) -> Callable[..., dict]:
    def context_analysis_tool(files: list[dict]) -> dict:
        """Analyze the codebase to understand its purpose, framework, architecture,
        entry points, authentication mechanism, and high-level security attack surface.
        Use this before deeper analysis to tailor the review to the tech stack.
        files: list of {path, content} from fetch_repo_files_tool (first 20 files).
        Returns {application_type, framework, entry_points, authentication,
        data_storage, external_services, async_pattern, architecture_notes,
        security_surface_summary}."""
        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list")
        file_objs = [FileResult(path=f["path"], content=f.get("content",""),
                                sha="", size=len(f.get("content","")), url="") for f in files]
        return agent.analyze_context(file_objs)
    return context_analysis_tool


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
    """Build a 5-layer multi-agent graph for the ADK playground.

    Architecture (29 agents total)
    --------------------------------
    L0 — root (code_review_agent)
         One-shot tool + routes to L1 agents.

    L1 — Strategic layer (8 agents):
         planner_agent, context_agent, scout_agent, pr_agent,
         report_agent, dedup_agent, risk_scorer_agent, remediation_agent

    L2 — Domain coordinators (3 agents):
         security_coordinator, quality_coordinator, intel_coordinator

    L3 — Specialist agents (14 agents):
         Under security_coordinator: sast_agent, injection_agent,
           auth_agent, crypto_agent, secrets_agent, data_flow_agent
         Under quality_coordinator: quality_agent, complexity_agent,
           test_agent, doc_agent
         Under intel_coordinator: dependency_agent, threat_model_agent,
           compliance_agent (+ owasp_agent/cwe_agent as L4 children)

    L4 — Sub-specialists (4 agents, innermost):
         validator_agent (under sast_agent)
         taint_validator_agent (under data_flow_agent)
         owasp_agent (under compliance_agent)
         cwe_agent (under compliance_agent)
    """

    pipeline = CodeReviewAgent(
        github_token=github_token,
        gemini_api_key=gemini_api_key,
        semgrep_config=semgrep_config,
    )

    def _ft(factory) -> FunctionTool:
        return FunctionTool(factory(pipeline))

    # ══════════════════════════════════════════════════════════════════════════
    # LAYER 4 — Sub-specialists (no sub_agents, innermost leaves)
    # ══════════════════════════════════════════════════════════════════════════

    validator_agent = Agent(
        name="validator_agent",
        model=DEFAULT_MODEL,
        description="Findings Validator: cross-checks security findings against source code to flag false positives.",
        instruction=(
            "You are the Findings Validator. Your sole job is catching false positives "
            "before they reach the user.\n\n"
            "WORKFLOW:\n"
            "1. Call validate_findings_tool with the issues and source files.\n"
            "2. Report: confirmed findings (HIGH/MEDIUM confidence) vs. probable false "
            "   positives (LOW confidence), with the validator's note for each.\n"
            "3. Transfer back to sast_agent.\n\n"
            "Be concise — one paragraph. This is a confidence check, not a re-review."
        ),
        tools=[_ft(make_validate_findings_tool)],
    )

    taint_validator_agent = Agent(
        name="taint_validator_agent",
        model=DEFAULT_MODEL,
        description="Taint Validator: confirms that data-flow taint paths are actually reachable and exploitable.",
        instruction=(
            "You are the Taint Path Validator. The data_flow_agent has identified "
            "potential taint paths. Your job: verify each path is actually reachable "
            "and the sink is genuinely dangerous in context.\n\n"
            "WORKFLOW:\n"
            "1. You receive tainted paths from data_flow_agent.\n"
            "2. For each path: check whether the source is actually reachable from an "
            "   external caller, whether any intermediate sanitizers (not noted by the "
            "   data_flow_agent) are present, and whether the sink is actually dangerous "
            "   given the surrounding code context.\n"
            "3. Classify each: CONFIRMED (real, exploitable), PARTIAL (real but harder "
            "   to exploit than stated), or FALSE_POSITIVE (not actually reachable).\n"
            "4. Transfer back to data_flow_agent.\n\n"
            "Be precise — cite the specific code that confirms or refutes each path."
        ),
        tools=[_ft(make_fetch_repo_files_tool), _ft(make_search_code_tool)],
    )

    owasp_agent = Agent(
        name="owasp_agent",
        model=DEFAULT_MODEL,
        description="OWASP Mapper: maps security findings to OWASP Top 10 2021 categories (A01–A10).",
        instruction=(
            "You are the OWASP Mapper. You receive a list of security findings and "
            "map each one to the most relevant OWASP Top 10 2021 category.\n\n"
            "WORKFLOW:\n"
            "1. Call owasp_mapping_tool with the findings list.\n"
            "2. Present the mapping table: finding → OWASP category, with justification.\n"
            "3. Show which OWASP categories are most heavily represented.\n"
            "4. Transfer back to compliance_agent.\n\n"
            "Categories: A01 Broken Access Control, A02 Cryptographic Failures, "
            "A03 Injection, A04 Insecure Design, A05 Security Misconfiguration, "
            "A06 Vulnerable and Outdated Components, A07 Auth Failures, "
            "A08 Software Integrity Failures, A09 Logging/Monitoring Failures, "
            "A10 SSRF."
        ),
        tools=[_ft(make_owasp_mapping_tool)],
    )

    cwe_agent = Agent(
        name="cwe_agent",
        model=DEFAULT_MODEL,
        description="CWE Mapper: maps security findings to CWE Top 25 Most Dangerous Software Weaknesses.",
        instruction=(
            "You are the CWE Mapper. You receive a list of security findings and "
            "map each one to the most relevant CWE Top 25 entry.\n\n"
            "WORKFLOW:\n"
            "1. Call cwe_mapping_tool with the findings list.\n"
            "2. Present: finding → CWE ID + name + rank in Top 25.\n"
            "3. Highlight if any findings map to CWE-89 (SQL Injection), CWE-79 (XSS), "
            "   CWE-78 (Command Injection), or CWE-798 (Hard-coded Credentials) — "
            "   these are the most commonly exploited.\n"
            "4. Transfer back to compliance_agent."
        ),
        tools=[_ft(make_cwe_mapping_tool)],
    )

    # ══════════════════════════════════════════════════════════════════════════
    # LAYER 3 — Specialist Agents
    # ══════════════════════════════════════════════════════════════════════════

    # ── Under security_coordinator ──────────────────────────────────────────

    sast_agent = Agent(
        name="sast_agent",
        model=DEFAULT_MODEL,
        description="SAST Analyst: Semgrep static analysis + LLM security review. Can delegate to validator_agent.",
        instruction=(
            "You are the SAST Analyst. You run deterministic static analysis (Semgrep) "
            "combined with an LLM security review to catch what Semgrep misses.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — pull Python files.\n"
            "2. scan_code_tool — run Semgrep (finds rule-matched vulnerabilities).\n"
            "3. generate_review_tool — LLM security pass on the same files.\n"
            "4. (optional) transfer to validator_agent to filter false positives.\n"
            "5. explain_finding_tool — for follow-up deep-dives on specific findings.\n\n"
            "CRITICAL → HIGH → MEDIUM → LOW priority. Include file:line and rule_id. "
            "If Semgrep finds nothing, still run the LLM review. "
            "Transfer back to security_coordinator when done."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_scan_code_tool),
            _ft(make_generate_review_tool),
            _ft(make_explain_finding_tool),
        ],
        sub_agents=[validator_agent],
    )

    injection_agent = Agent(
        name="injection_agent",
        model=DEFAULT_MODEL,
        description=(
            "Injection Specialist: finds SQL injection, command injection, SSTI, XSS, "
            "SSRF, path traversal, LDAP, XXE, and header injection vulnerabilities."
        ),
        instruction=(
            "You are the Injection Specialist. You go deeper than SAST on injection "
            "vulnerabilities — tracing every path where untrusted data enters a "
            "dangerous sink.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — pull Python files.\n"
            "2. injection_audit_tool — deep injection analysis: SQL, command, SSTI, "
            "   XSS, SSRF, path traversal, LDAP, XXE, header injection.\n\n"
            "For each finding: show the attack_vector (what an attacker sends), "
            "the attack_chain (step-by-step from input to exploit), the impact, "
            "and the exact fix. Be concrete — name the payload, name the sink.\n\n"
            "Transfer back to security_coordinator when done."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_injection_audit_tool),
        ],
    )

    auth_agent = Agent(
        name="auth_agent",
        model=DEFAULT_MODEL,
        description=(
            "Auth Specialist: finds broken authentication, IDOR, privilege escalation, "
            "missing access controls, JWT issues, and OAuth flaws."
        ),
        instruction=(
            "You are the Authentication & Authorization Specialist. You focus "
            "exclusively on identity: who is allowed to do what, and what happens "
            "when those checks are missing or bypassable.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — pull Python files.\n"
            "2. auth_audit_tool — deep auth/authz analysis: IDOR, broken auth, "
            "   privilege escalation, missing access controls, JWT, OAuth.\n\n"
            "For each finding: describe the concrete attack scenario (what does "
            "a logged-in attacker with basic access do?), the impact (access "
            "other users' data / escalate to admin / account takeover), and "
            "the precise fix.\n\n"
            "Transfer back to security_coordinator when done."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_auth_audit_tool),
        ],
    )

    crypto_agent = Agent(
        name="crypto_agent",
        model=DEFAULT_MODEL,
        description=(
            "Cryptography Auditor: detects weak, broken, or misused cryptography — "
            "MD5/SHA1 password hashing, predictable randomness, ECB mode, disabled TLS."
        ),
        instruction=(
            "You are the Cryptography Auditor. You find cryptographic mistakes "
            "that look correct to most developers but are actually exploitable.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — fetch the source files.\n"
            "2. crypto_audit_tool — pass the files for cryptographic analysis.\n\n"
            "For each finding: explain WHY it is dangerous (concrete attack, not just "
            "'it is weak'), the attacker effort, and the exact safe replacement.\n\n"
            "Transfer back to security_coordinator when done."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_crypto_audit_tool),
        ],
    )

    secrets_agent = Agent(
        name="secrets_agent",
        model=DEFAULT_MODEL,
        description=(
            "Secrets Scanner: finds hardcoded API keys, passwords, private keys, "
            "JWT secrets, and database credentials in source code."
        ),
        instruction=(
            "You are the Secrets Scanner. You look for sensitive values that have been "
            "accidentally committed to source code — the kind of thing that leads to "
            "breach headlines.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — fetch the source files.\n"
            "2. secrets_audit_tool — scan for hardcoded secrets: API keys, passwords, "
            "   private keys, JWT signing secrets, DB credentials, OAuth secrets.\n"
            "3. search_code_in_files_tool — additionally grep for common patterns "
            "   like 'password', 'secret', 'api_key', 'token', 'AKIA' to catch "
            "   anything the LLM might miss.\n\n"
            "For each finding: describe what the secret unlocks and the blast radius "
            "if an attacker finds it. NEVER print the full secret value — redact to "
            "first 4 chars + ***.\n\n"
            "Transfer back to security_coordinator when done."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_secrets_audit_tool),
            _ft(make_search_code_tool),
        ],
    )

    data_flow_agent = Agent(
        name="data_flow_agent",
        model=DEFAULT_MODEL,
        description=(
            "Taint Analyst: traces untrusted user input from entry points (HTTP params, "
            "CLI args) through the application to dangerous sinks (DB, shell, templates)."
        ),
        instruction=(
            "You are the Taint Analyst. You perform data flow analysis — tracing every "
            "path where untrusted input moves through the application without adequate "
            "sanitization.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — fetch the source files.\n"
            "2. data_flow_tool — full taint analysis: source → intermediate steps → "
            "   sink, with sanitizer adequacy assessment.\n"
            "3. (optional) transfer to taint_validator_agent to confirm reachability "
            "   of the highest-severity paths.\n\n"
            "For each tainted path: show the full chain from where user data enters "
            "to where it reaches a dangerous operation, the missing sanitizer, "
            "and the concrete exploit.\n\n"
            "Transfer back to security_coordinator when done."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_data_flow_tool),
        ],
        sub_agents=[taint_validator_agent],
    )

    # ── Under quality_coordinator ───────────────────────────────────────────

    quality_agent = Agent(
        name="quality_agent",
        model=DEFAULT_MODEL,
        description="Quality Reviewer: LLM code quality, readability, and best-practice review. No security angle.",
        instruction=(
            "You are the Quality Reviewer. You assess code quality, readability, and "
            "Python best practices — NOT security.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — pull the Python files.\n"
            "2. (optional) search_code_in_files_tool — spot anti-patterns like bare "
            "   'except:', 'global', magic numbers.\n"
            "3. generate_review_tool — LLM quality review: naming, complexity, "
            "   docstring coverage, DRY, error handling, PEP 8.\n\n"
            "Severity: LOW/MEDIUM for style; HIGH only when a quality flaw is likely "
            "to cause a runtime bug. Transfer back to quality_coordinator when done."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_generate_review_tool),
            _ft(make_search_code_tool),
        ],
    )

    complexity_agent = Agent(
        name="complexity_agent",
        model=DEFAULT_MODEL,
        description=(
            "Complexity Analyst: measures cyclomatic complexity, deep nesting, "
            "god classes, magic numbers, and code duplication."
        ),
        instruction=(
            "You are the Complexity Analyst. Overly complex code is hard to test, "
            "hard to review, and harbors bugs. Your job: find and measure it.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — fetch the source files.\n"
            "2. complexity_tool — analyze cyclomatic complexity per function, "
            "   nesting depth, function length, god classes, magic numbers, "
            "   duplicated logic, and long parameter lists.\n\n"
            "Present the most complex functions ranked by complexity score. "
            "Give a concrete refactoring hint for each (not vague 'simplify it', "
            "but specific: 'extract X into a helper', 'use early return to reduce "
            "nesting', 'replace magic number 86400 with SECONDS_PER_DAY constant').\n\n"
            "Transfer back to quality_coordinator when done."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_complexity_tool),
        ],
    )

    test_agent = Agent(
        name="test_agent",
        model=DEFAULT_MODEL,
        description=(
            "Test Coverage Analyst: identifies untested functions, missing edge cases, "
            "untested error paths, and test quality issues."
        ),
        instruction=(
            "You are the Test Coverage Analyst. Tests are the safety net for every "
            "change. Your job: find the holes in that net.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — fetch ALL files (source + tests).\n"
            "   Separate them: source files are in the main dirs, test files have "
            "   names starting with test_ or are in a tests/ directory.\n"
            "2. test_coverage_tool — pass source_files and test_files separately "
            "   to identify: untested functions, missing error path coverage, "
            "   missing boundary tests, broad mocks hiding real behavior.\n\n"
            "Highlight: which security-critical functions (auth checks, input "
            "validation) have NO tests — these are the highest-priority gaps.\n\n"
            "Transfer back to quality_coordinator when done."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_test_coverage_tool),
        ],
    )

    doc_agent = Agent(
        name="doc_agent",
        model=DEFAULT_MODEL,
        description=(
            "Documentation Auditor: finds missing docstrings, missing type hints, "
            "stale comments, misleading names, and TODO debt."
        ),
        instruction=(
            "You are the Documentation Auditor. Good documentation makes code "
            "reviewable and maintainable. Bad documentation hides bugs.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — fetch the source files.\n"
            "2. doc_quality_tool — assess: missing docstrings on public functions, "
            "   missing type hints, stale/contradictory comments, misleading names, "
            "   TODO/FIXME debt.\n\n"
            "Present the coverage_stats (% of public functions documented), "
            "list the most impactful gaps (missing docs on core business logic "
            "is worse than missing docs on a utility helper), and suggest concrete "
            "docstring examples for the top 3 missing ones.\n\n"
            "Transfer back to quality_coordinator when done."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_doc_quality_tool),
        ],
    )

    # ── Under intel_coordinator ─────────────────────────────────────────────

    dependency_agent = Agent(
        name="dependency_agent",
        model=DEFAULT_MODEL,
        description="Dependency CVE Scanner: checks requirements.txt against the OSV database for known CVEs.",
        instruction=(
            "You are the Dependency Security Scanner. You check the project's "
            "third-party libraries for known vulnerabilities.\n\n"
            "WORKFLOW:\n"
            "1. fetch_requirements_tool — fetch requirements.txt from the repo.\n"
            "   If not found, say so and stop.\n"
            "2. dependency_scan_tool — check each package against OSV.\n\n"
            "For each vulnerable package: CVE ID, severity, what the vulnerability "
            "allows, and the exact upgrade version. Group CRITICAL first. "
            "Transfer back to intel_coordinator when done."
        ),
        tools=[
            _ft(make_fetch_requirements_tool),
            _ft(make_dependency_scan_tool),
        ],
    )

    threat_model_agent = Agent(
        name="threat_model_agent",
        model=DEFAULT_MODEL,
        description="Threat Modeler: STRIDE threat model — assets, entry points, attack scenarios, missing defenses.",
        instruction=(
            "You are the Threat Modeler. You help developers think like attackers.\n\n"
            "WORKFLOW:\n"
            "1. fetch_repo_files_tool — fetch the source files.\n"
            "2. threat_model_tool — generate full STRIDE threat model: assets, "
            "   entry points, trust boundaries, threats per STRIDE category, "
            "   top attack scenarios with step-by-step attacker actions + tools, "
            "   and missing defenses.\n\n"
            "Be educational and concrete. Name real attack tools (sqlmap, burp, "
            "curl). Transfer back to intel_coordinator when done."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_threat_model_tool),
        ],
    )

    compliance_agent = Agent(
        name="compliance_agent",
        model=DEFAULT_MODEL,
        description=(
            "Compliance Checker: maps findings to OWASP Top 10 and CWE Top 25, "
            "producing a standards-based compliance view of the risk landscape."
        ),
        instruction=(
            "You are the Compliance Checker. You take the security findings produced "
            "by other agents and map them to industry standards.\n\n"
            "WORKFLOW:\n"
            "1. You receive a list of security findings (passed from intel_coordinator "
            "   after other agents have run).\n"
            "2. Transfer to owasp_agent — maps findings to OWASP Top 10 2021.\n"
            "3. After owasp_agent returns, transfer to cwe_agent — maps findings "
            "   to CWE Top 25.\n"
            "4. Aggregate both mappings into a consolidated compliance view:\n"
            "   - Which OWASP categories are violated and with what severity\n"
            "   - Which CWE Top 25 entries are present\n"
            "   - Overall compliance risk summary\n"
            "5. Transfer back to intel_coordinator.\n\n"
            "This is standards mapping, not new analysis. You do not fetch files "
            "or run new analyses yourself."
        ),
        tools=[_ft(make_owasp_mapping_tool), _ft(make_cwe_mapping_tool)],
        sub_agents=[owasp_agent, cwe_agent],
    )

    # ══════════════════════════════════════════════════════════════════════════
    # LAYER 2 — Domain Coordinators
    # ══════════════════════════════════════════════════════════════════════════

    security_coordinator = Agent(
        name="security_coordinator",
        model=DEFAULT_MODEL,
        description=(
            "Security Coordinator: orchestrates all 6 security specialist agents "
            "(SAST, injection, auth, crypto, secrets, data flow) and aggregates results."
        ),
        instruction=(
            "You are the Security Coordinator. You manage six security specialist "
            "agents and decide which ones to invoke based on the user's request.\n\n"
            "YOUR SPECIALISTS:\n"
            "  • sast_agent        — Semgrep + LLM general security review\n"
            "  • injection_agent   — SQL/cmd/SSTI/XSS/SSRF/path traversal\n"
            "  • auth_agent        — IDOR, broken auth, privilege escalation\n"
            "  • crypto_agent      — weak hashing, ECB, predictable randomness\n"
            "  • secrets_agent     — hardcoded API keys, passwords, private keys\n"
            "  • data_flow_agent   — taint analysis: input → dangerous sink\n\n"
            "ROUTING:\n"
            "- 'Full security review' / 'comprehensive' → all six agents sequentially\n"
            "- 'Injection' / 'SQL injection' / 'XSS' → injection_agent\n"
            "- 'Auth' / 'IDOR' / 'access control' → auth_agent\n"
            "- 'Crypto' / 'encryption' → crypto_agent\n"
            "- 'Secrets' / 'credentials' → secrets_agent\n"
            "- 'Data flow' / 'taint' → data_flow_agent\n"
            "- General 'security review' → sast_agent first, then injection + auth\n\n"
            "AGGREGATION: After specialists return, consolidate by severity. "
            "State which agents ran and how many findings each produced. "
            "Transfer back to planner_agent when done."
        ),
        sub_agents=[sast_agent, injection_agent, auth_agent, crypto_agent,
                    secrets_agent, data_flow_agent],
    )

    quality_coordinator = Agent(
        name="quality_coordinator",
        model=DEFAULT_MODEL,
        description=(
            "Quality Coordinator: orchestrates quality_agent, complexity_agent, "
            "test_agent, and doc_agent for a comprehensive quality assessment."
        ),
        instruction=(
            "You are the Quality Coordinator. You manage four quality specialist agents.\n\n"
            "YOUR SPECIALISTS:\n"
            "  • quality_agent    — general code quality + best practices\n"
            "  • complexity_agent — cyclomatic complexity, god classes, deep nesting\n"
            "  • test_agent       — test coverage gaps, missing edge cases\n"
            "  • doc_agent        — missing docstrings, type hints, TODO debt\n\n"
            "ROUTING:\n"
            "- 'Full quality review' → all four agents sequentially\n"
            "- 'Complexity' / 'refactoring' → complexity_agent\n"
            "- 'Tests' / 'coverage' → test_agent\n"
            "- 'Documentation' / 'docstrings' → doc_agent\n"
            "- General 'quality review' → quality_agent + complexity_agent\n\n"
            "AGGREGATION: After specialists return, summarize by category. "
            "Transfer back to planner_agent when done."
        ),
        sub_agents=[quality_agent, complexity_agent, test_agent, doc_agent],
    )

    intel_coordinator = Agent(
        name="intel_coordinator",
        model=DEFAULT_MODEL,
        description=(
            "Intel Coordinator: orchestrates threat intelligence agents — dependency CVE "
            "scanning, STRIDE threat modeling, and standards compliance (OWASP/CWE)."
        ),
        instruction=(
            "You are the Intelligence Coordinator. You manage threat intelligence, "
            "dependency scanning, and standards compliance.\n\n"
            "YOUR SPECIALISTS:\n"
            "  • dependency_agent   — OSV CVE scan on requirements.txt\n"
            "  • threat_model_agent — STRIDE threat model\n"
            "  • compliance_agent   — OWASP Top 10 + CWE Top 25 mapping\n\n"
            "ROUTING:\n"
            "- 'Full intel' / 'comprehensive' → all three sequentially\n"
            "- 'Dependencies' / 'CVE' → dependency_agent\n"
            "- 'Threat model' / 'STRIDE' / 'attack surface' → threat_model_agent\n"
            "- 'OWASP' / 'CWE' / 'compliance' → compliance_agent\n\n"
            "AGGREGATION: After specialists return, summarize. "
            "Transfer back to planner_agent when done."
        ),
        sub_agents=[dependency_agent, threat_model_agent, compliance_agent],
    )

    # ══════════════════════════════════════════════════════════════════════════
    # LAYER 1 — Strategic / Cross-cutting Agents
    # ══════════════════════════════════════════════════════════════════════════

    context_agent = Agent(
        name="context_agent",
        model=DEFAULT_MODEL,
        description=(
            "Context Analyzer: identifies the codebase's framework, architecture, "
            "entry points, authentication mechanism, and security attack surface "
            "before deeper analysis begins."
        ),
        instruction=(
            "You are the Context Analyzer. Before running any security or quality "
            "analysis, it helps to understand WHAT the code is. Your job: characterize "
            "the codebase so downstream agents can give more targeted advice.\n\n"
            "WORKFLOW:\n"
            "1. get_repo_metadata_tool — fast check: language, size, stars.\n"
            "2. fetch_repo_files_tool — fetch up to 20 files (the first 20 are enough "
            "   to identify the framework and architecture).\n"
            "3. context_analysis_tool — structured analysis: application type, "
            "   framework (Flask/Django/FastAPI/etc.), entry points, auth mechanism, "
            "   data storage, external services, async pattern.\n\n"
            "Present: what is this codebase (1 sentence), what framework it uses, "
            "what the main attack surface is (2-3 sentences).\n\n"
            "Transfer back to the root orchestrator when done."
        ),
        tools=[
            _ft(make_get_repo_metadata_tool),
            _ft(make_fetch_repo_files_tool),
            _ft(make_context_analysis_tool),
        ],
    )

    planner_agent = Agent(
        name="planner_agent",
        model=DEFAULT_MODEL,
        description=(
            "Execution Planner: decides which coordinators to invoke for a given "
            "request and sequences them — security, quality, and/or intel. "
            "All three coordinators are its sub-agents."
        ),
        instruction=(
            "You are the Execution Planner. You receive a user request and decide "
            "which of the three domain coordinators to invoke, in what order.\n\n"
            "YOUR COORDINATORS:\n"
            "  • security_coordinator — 6 security agents (SAST, injection, auth, "
            "    crypto, secrets, data flow)\n"
            "  • quality_coordinator  — 4 quality agents (general, complexity, "
            "    test coverage, documentation)\n"
            "  • intel_coordinator    — 3 intel agents (CVE scan, threat model, "
            "    OWASP/CWE compliance)\n\n"
            "PLANNING RULES:\n"
            "- 'Full deep review' / 'everything' / 'comprehensive' → all three\n"
            "- 'Security review' / 'vulnerabilities' / 'pentesting' → security_coordinator\n"
            "- 'Quality review' / 'readability' / 'best practices' → quality_coordinator\n"
            "- 'Threat model' / 'CVE scan' / 'OWASP' / 'compliance' → intel_coordinator\n"
            "- Mixed: 'security and quality' → security_coordinator then quality_coordinator\n\n"
            "After all requested coordinators return, produce a consolidated "
            "EXECUTIVE SUMMARY:\n"
            "  - Total findings by severity\n"
            "  - Top 3 most critical issues to fix immediately\n"
            "  - Which agents ran and what each found\n"
            "Transfer back to the root orchestrator when done."
        ),
        sub_agents=[security_coordinator, quality_coordinator, intel_coordinator],
    )

    scout_agent = Agent(
        name="scout_agent",
        model=DEFAULT_MODEL,
        description="Repo Scout: lightweight metadata, file listing, and pattern search — no LLM review.",
        instruction=(
            "You are the Repo Scout. You inspect a GitHub repository at surface level.\n\n"
            "TOOLS:\n"
            "- get_repo_metadata_tool: language, stars, size, open issues, default branch.\n"
            "- fetch_repo_files_tool: retrieve file paths and contents.\n"
            "- search_code_in_files_tool: grep for a regex pattern.\n\n"
            "Start with metadata. Fetch files if needed. Search if asked. "
            "You are NOT doing analysis — transfer back to the orchestrator "
            "if the user asks for security or quality review."
        ),
        tools=[
            _ft(make_get_repo_metadata_tool),
            _ft(make_fetch_repo_files_tool),
            _ft(make_search_code_tool),
        ],
    )

    pr_agent = Agent(
        name="pr_agent",
        model=DEFAULT_MODEL,
        description="PR Reviewer: reviews only the Python files changed in a GitHub Pull Request.",
        instruction=(
            "You are the PR Reviewer. You focus on PR diffs only.\n\n"
            "WORKFLOW:\n"
            "1. fetch_pr_files_tool — changed files from the PR URL.\n"
            "2. scan_code_tool — Semgrep on changed files.\n"
            "3. generate_review_tool — LLM review.\n"
            "4. (optional) validate_findings_tool — false-positive filter.\n"
            "5. (optional) post_pr_review_tool — post inline GitHub comments.\n\n"
            "State which PR, how many files changed, and total issues. "
            "Prioritize CRITICAL → HIGH → MEDIUM → LOW."
        ),
        tools=[
            _ft(make_fetch_pr_files_tool),
            _ft(make_scan_code_tool),
            _ft(make_generate_review_tool),
            _ft(make_validate_findings_tool),
            _ft(make_post_pr_review_tool),
        ],
    )

    report_agent = Agent(
        name="report_agent",
        model=DEFAULT_MODEL,
        description="Report Writer: deep-dive explanations of findings and saves Markdown reports to disk.",
        instruction=(
            "You are the Report Writer. You work with already-produced findings.\n\n"
            "TOOLS:\n"
            "- explain_finding_tool: focused 3-6 sentence explanation of one issue.\n"
            "- generate_report_file_tool: render findings as Markdown and save.\n\n"
            "If no review has been done yet, tell the user to run a review first."
        ),
        tools=[
            _ft(make_explain_finding_tool),
            _ft(make_generate_report_file_tool),
        ],
    )

    dedup_agent = Agent(
        name="dedup_agent",
        model=DEFAULT_MODEL,
        description=(
            "Deduplication Agent: merges duplicate and overlapping findings from "
            "multiple analysis agents into one clean, consolidated list."
        ),
        instruction=(
            "You are the Deduplication Agent. When multiple security agents run on "
            "the same codebase, they often find the same vulnerabilities described "
            "differently. Your job: produce one clean list.\n\n"
            "WORKFLOW:\n"
            "1. You receive a combined list of findings from multiple agents, "
            "   each tagged with a 'source_agent' field.\n"
            "2. Call dedup_tool — identifies exact duplicates (same file+line+type), "
            "   near-duplicates (same vuln, nearby lines), and semantic duplicates "
            "   (same issue, different wording). Merges into one richer finding.\n"
            "3. Report: original count → deduplicated count, how many merges.\n\n"
            "Transfer back to the root orchestrator when done. Use trigger phrases: "
            "'deduplicate', 'merge findings', 'combine results'."
        ),
        tools=[_ft(make_dedup_tool)],
    )

    risk_scorer_agent = Agent(
        name="risk_scorer_agent",
        model=DEFAULT_MODEL,
        description=(
            "Risk Scorer: assigns CVSS-like composite risk scores to findings "
            "and produces an overall project risk rating."
        ),
        instruction=(
            "You are the Risk Scorer. Not all security findings are equal — "
            "your job is to quantify which ones matter most.\n\n"
            "WORKFLOW:\n"
            "1. You receive a list of (ideally deduplicated) security findings.\n"
            "2. Call risk_score_tool — scores each finding on Impact, Exploitability, "
            "   Scope, and Detectability (all 0-10), computes a weighted composite "
            "   score, and ranks findings by priority.\n"
            "3. Present: the top 5 highest-risk findings with their scores, "
            "   the overall project risk level, and which findings require "
            "   IMMEDIATE action.\n\n"
            "Transfer back to the root orchestrator when done. Use trigger phrases: "
            "'risk score', 'prioritize findings', 'CVSS', 'risk rating'."
        ),
        tools=[_ft(make_risk_score_tool)],
    )

    remediation_agent = Agent(
        name="remediation_agent",
        model=DEFAULT_MODEL,
        description=(
            "Remediation Agent: generates concrete, copy-pasteable code fix patches "
            "for security findings — not vague advice, but real before/after code."
        ),
        instruction=(
            "You are the Remediation Agent. Findings without fixes are just complaints. "
            "Your job: turn every security finding into actionable, copy-pasteable code.\n\n"
            "WORKFLOW:\n"
            "1. You receive a list of security findings AND the source files they "
            "   reference (passed from the orchestrator after analysis is complete).\n"
            "2. fetch_repo_files_tool — fetch any files needed for context.\n"
            "3. remediation_tool — generates exact before/after code patches for "
            "   each finding: vulnerable code → fixed code, one-line explanation, "
            "   required library changes, and whether it's a breaking change.\n"
            "4. Present the patches in order of priority (CRITICAL first).\n\n"
            "Patches must be syntactically correct Python. Address root causes, "
            "not symptoms. Transfer back when done. Use trigger phrases: "
            "'fix this', 'generate patches', 'how do I fix', 'remediation plan'."
        ),
        tools=[
            _ft(make_fetch_repo_files_tool),
            _ft(make_remediation_tool),
        ],
    )

    # ══════════════════════════════════════════════════════════════════════════
    # LAYER 0 — Root Orchestrator
    # ══════════════════════════════════════════════════════════════════════════

    root = Agent(
        name="code_review_agent",
        model=DEFAULT_MODEL,
        description=(
            "Master orchestrator of a 5-layer, 29-agent code security and quality "
            "analysis system. Routes requests to the right specialist or coordinator."
        ),
        instruction=(
            "You are the master orchestrator of a 5-layer multi-agent code review "
            "and security analysis system with 29 specialized agents.\n\n"
            "ARCHITECTURE OVERVIEW:\n"
            "  L0: you (root orchestrator)\n"
            "  L1: planner_agent | context_agent | scout_agent | pr_agent |\n"
            "      report_agent | dedup_agent | risk_scorer_agent | remediation_agent\n"
            "  L2: security_coordinator | quality_coordinator | intel_coordinator\n"
            "  L3: sast_agent | injection_agent | auth_agent | crypto_agent |\n"
            "      secrets_agent | data_flow_agent | quality_agent |\n"
            "      complexity_agent | test_agent | doc_agent |\n"
            "      dependency_agent | threat_model_agent | compliance_agent\n"
            "  L4: validator_agent | taint_validator_agent | owasp_agent | cwe_agent\n\n"
            "YOUR DIRECT TOOL:\n"
            "- review_repo_tool: one-shot quick review. Use when the user wants "
            "  a fast answer without deep analysis.\n\n"
            "ROUTING (delegate with transfer_to_agent):\n"
            "1. 'Quick review' / 'fast check' → review_repo_tool (direct)\n"
            "2. 'What is this repo?' / 'scout' / 'list files' → scout_agent\n"
            "3. 'Understand the architecture first' / 'what framework?' → context_agent\n"
            "4. 'Security review' / 'quality review' / 'full review' / 'everything'\n"
            "   → planner_agent (it decides which coordinators to invoke)\n"
            "5. PR URL or 'review this PR' → pr_agent\n"
            "6. 'Explain issue #N' / 'save the report' → report_agent\n"
            "7. 'Deduplicate findings' / 'merge results' → dedup_agent\n"
            "8. 'Risk score' / 'prioritize' / 'CVSS' → risk_scorer_agent\n"
            "9. 'Fix this' / 'generate patches' / 'remediation' → remediation_agent\n"
            "10. Off-topic requests → politely decline.\n\n"
            "Always tell the user which agent you are delegating to and why. "
            "For multi-step requests: context_agent first (optional), then "
            "planner_agent for analysis, then dedup_agent + risk_scorer_agent "
            "to consolidate, then remediation_agent for fixes."
        ),
        tools=[FunctionTool(make_review_repo_tool(pipeline))],
        sub_agents=[
            planner_agent, context_agent, scout_agent, pr_agent,
            report_agent, dedup_agent, risk_scorer_agent, remediation_agent,
        ],
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
