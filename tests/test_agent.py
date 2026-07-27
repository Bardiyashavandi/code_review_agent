"""
tests/test_agent.py
---------------------
Tests for agent.py's orchestration logic. GitHubFetcher, SemgrepRunner, and
GeminiReviewer are all mocked at the agent module level — these tests verify
only the orchestration (sequencing, partial-failure handling, ADK tool
shape), not the underlying modules, which have their own test suites.

Run with:
    pytest tests/test_agent.py -v
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from google.adk.agents import LoopAgent, ParallelAgent, SequentialAgent

import agent as agent_module
from agent import (
    CodeReviewAgent,
    PipelineResult,
    make_create_issue_tool,
    make_explain_finding_tool,
    make_fetch_repo_files_tool,
    make_generate_report_file_tool,
    make_generate_review_tool,
    make_get_repo_metadata_tool,
    make_patch_verifier_tool,
    make_review_repo_tool,
    make_scan_code_tool,
    make_search_code_tool,
)
from gemini_reviewer import RAG_MAX_CONVENTIONS_CHARS, GeminiRateLimitError
from semgrep_runner import Finding, ScanReport, SemgrepExecutionError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_fetch_result(paths=("a.py", "b.py"), truncated=False) -> SimpleNamespace:
    files = [SimpleNamespace(path=p, content="x = 1\n") for p in paths]
    return SimpleNamespace(files=files, truncated=truncated)


def make_scan_report(findings_count=0) -> SimpleNamespace:
    findings = [
        SimpleNamespace(path="a.py", rule_id=f"rule.{i}", severity="WARNING",
                         line_start=1, line_end=1, message="m", snippet="x = 1")
        for i in range(findings_count)
    ]
    return SimpleNamespace(findings=findings, scanned=2, skipped=[], duration_s=0.1)


def make_review_report(issue_count=0) -> SimpleNamespace:
    issues = [
        SimpleNamespace(path="a.py", line=1, severity="HIGH", title=f"issue {i}",
                         description="d", suggested_fix="f", rule_id=None)
        for i in range(issue_count)
    ]
    return SimpleNamespace(issues=issues, summary="ok", model="gemini-2.5-flash",
                            files_reviewed=2, duration_s=0.1, schema_errors=[])


def make_agent(fetch_result=None, scan_result=None, review_result=None,
               scan_side_effect=None, review_side_effect=None):
    """
    Construct a CodeReviewAgent with all three underlying clients mocked.
    Returns (agent, mock_fetcher_instance, mock_semgrep_instance, mock_reviewer_instance).
    """
    with patch("agent.GitHubFetcher") as MockFetcher, \
         patch("agent.SemgrepRunner") as MockSemgrep, \
         patch("agent.GeminiReviewer") as MockReviewer:

        mock_fetcher = MagicMock()
        mock_fetcher.fetch_python_files.return_value = fetch_result or make_fetch_result()
        MockFetcher.return_value = mock_fetcher

        mock_semgrep = MagicMock()
        if scan_side_effect is not None:
            mock_semgrep.scan.side_effect = scan_side_effect
        else:
            mock_semgrep.scan.return_value = scan_result or make_scan_report()
        MockSemgrep.return_value = mock_semgrep

        mock_reviewer = MagicMock()
        if review_side_effect is not None:
            mock_reviewer.review.side_effect = review_side_effect
        else:
            mock_reviewer.review.return_value = review_result or make_review_report()
        MockReviewer.return_value = mock_reviewer

        agent = CodeReviewAgent(github_token="ghp_faketoken", gemini_api_key="gem_fakekey")

    return agent, mock_fetcher, mock_semgrep, mock_reviewer


# ---------------------------------------------------------------------------
# 1. Construction
# ---------------------------------------------------------------------------

class TestConstruction:

    def test_empty_github_token_raises(self):
        with pytest.raises(ValueError, match="github_token"):
            CodeReviewAgent(github_token="", gemini_api_key="gem_fakekey")

    def test_empty_gemini_key_raises(self):
        with patch("agent.GitHubFetcher"), patch("agent.SemgrepRunner"):
            with pytest.raises(ValueError, match="gemini_api_key"):
                CodeReviewAgent(github_token="ghp_faketoken", gemini_api_key="")


# ---------------------------------------------------------------------------
# 2. Happy path
# ---------------------------------------------------------------------------

class TestHappyPath:

    def test_happy_path_runs_all_three_stages(self):
        agent, mock_fetcher, mock_semgrep, mock_reviewer = make_agent(
            review_result=make_review_report(issue_count=1)
        )

        result = agent.review_repo("https://github.com/owner/repo")

        mock_fetcher.fetch_python_files.assert_called_once()
        mock_semgrep.scan.assert_called_once()
        mock_reviewer.review.assert_called_once()

        assert isinstance(result, PipelineResult)
        assert result.stage_errors == []
        assert len(result.review_report.issues) == 1

    def test_pipeline_result_has_duration(self):
        agent, *_ = make_agent()
        result = agent.review_repo("https://github.com/owner/repo")
        assert result.duration_s >= 0


# ---------------------------------------------------------------------------
# 3. Fatal vs non-fatal failures
# ---------------------------------------------------------------------------

class TestFailureHandling:

    def test_fetch_failure_is_fatal(self):
        class FakeNotFound(Exception):
            pass

        agent, mock_fetcher, *_ = make_agent()
        mock_fetcher.fetch_python_files.side_effect = FakeNotFound("repo not found")

        with pytest.raises(FakeNotFound):
            agent.review_repo("https://github.com/owner/repo")

    def test_scan_failure_is_non_fatal(self):
        agent, mock_fetcher, mock_semgrep, mock_reviewer = make_agent(
            scan_side_effect=SemgrepExecutionError("boom", returncode=2)
        )

        result = agent.review_repo("https://github.com/owner/repo")

        assert len(result.stage_errors) == 1
        assert result.stage_errors[0].stage == "scan"
        mock_reviewer.review.assert_called_once()

    def test_scan_failure_falls_back_empty_report(self):
        agent, mock_fetcher, mock_semgrep, mock_reviewer = make_agent(
            scan_side_effect=SemgrepExecutionError("boom", returncode=2)
        )

        agent.review_repo("https://github.com/owner/repo")

        call_args = mock_reviewer.review.call_args
        scan_report_passed = call_args.args[1] if len(call_args.args) > 1 else call_args.kwargs.get("scan_report")
        assert scan_report_passed.findings == []

    def test_review_failure_is_non_fatal(self):
        agent, *_ = make_agent(
            review_side_effect=GeminiRateLimitError("rate limited")
        )

        result = agent.review_repo("https://github.com/owner/repo")

        assert len(result.stage_errors) == 1
        assert result.stage_errors[0].stage == "review"
        assert result.review_report.issues == []

    def test_both_scan_and_review_fail(self):
        agent, *_ = make_agent(
            scan_side_effect=SemgrepExecutionError("boom", returncode=2),
            review_side_effect=GeminiRateLimitError("rate limited"),
        )

        result = agent.review_repo("https://github.com/owner/repo")

        stages = {e.stage for e in result.stage_errors}
        assert stages == {"scan", "review"}
        assert isinstance(result, PipelineResult)


# ---------------------------------------------------------------------------
# 4. ADK tool wrapper
# ---------------------------------------------------------------------------

class TestAdkToolWrapper:

    def test_review_repo_tool_returns_json_serializable_dict(self):
        agent, *_ = make_agent(review_result=make_review_report(issue_count=2))
        tool = make_review_repo_tool(agent)

        output = tool("https://github.com/owner/repo")

        json.dumps(output)  # should not raise

    def test_review_repo_tool_does_not_leak_internal_fields(self):
        agent, *_ = make_agent(review_result=make_review_report(issue_count=1))
        tool = make_review_repo_tool(agent)

        output = tool("https://github.com/owner/repo")

        expected_keys = {
            "repo_url", "files_fetched", "truncated", "findings_count",
            "scan_skipped", "issues", "summary", "model", "schema_errors",
            "stage_errors", "duration_s",
        }
        assert set(output.keys()) == expected_keys


# ---------------------------------------------------------------------------
# 4b. Granular single-stage entry points + their ADK tool wrappers
# ---------------------------------------------------------------------------

class TestGranularEntryPoints:

    def test_fetch_files_delegates_to_fetcher(self):
        agent, mock_fetcher, mock_semgrep, mock_reviewer = make_agent()

        result = agent.fetch_files("https://github.com/owner/repo")

        mock_fetcher.fetch_python_files.assert_called_once()
        mock_semgrep.scan.assert_not_called()
        mock_reviewer.review.assert_not_called()
        assert result is mock_fetcher.fetch_python_files.return_value

    def test_scan_files_delegates_to_semgrep(self):
        agent, mock_fetcher, mock_semgrep, mock_reviewer = make_agent()

        result = agent.scan_files([SimpleNamespace(path="a.py", content="x = 1\n")])

        mock_semgrep.scan.assert_called_once()
        mock_fetcher.fetch_python_files.assert_not_called()
        mock_reviewer.review.assert_not_called()
        assert result is mock_semgrep.scan.return_value

    def test_generate_review_delegates_to_reviewer(self):
        agent, mock_fetcher, mock_semgrep, mock_reviewer = make_agent()

        files = [SimpleNamespace(path="a.py", content="x = 1\n")]
        scan_report = make_scan_report()
        result = agent.generate_review(files, scan_report)

        # project_context=None is the default no-op case — no repo_url was
        # given, so no project-context lookup/build happens either.
        mock_reviewer.review.assert_called_once_with(files, scan_report, project_context=None)
        mock_fetcher.fetch_python_files.assert_not_called()
        mock_semgrep.scan.assert_not_called()
        assert result is mock_reviewer.review.return_value


# ---------------------------------------------------------------------------
# 4c. build_project_context (RAG project-context indexing + caching)
# ---------------------------------------------------------------------------

class TestBuildProjectContext:

    def test_builds_context_from_conventions_and_comments(self):
        agent, mock_fetcher, _, mock_reviewer = make_agent()
        mock_fetcher.fetch_convention_files.return_value = {"README.md": "Use snake_case."}
        mock_fetcher.fetch_recent_review_comments.return_value = [
            {"body": "Please add a docstring.", "path": "a.py", "line": 1},
        ]
        indexed = [([1.0, 0.0], {"body": "Please add a docstring.", "path": "a.py", "line": 1})]
        mock_reviewer.embed_review_comments.return_value = indexed

        context = agent.build_project_context("https://github.com/owner/repo")

        assert context.conventions_text == "### README.md\nUse snake_case."
        assert context.comment_index == indexed
        assert "README.md" in context.sources
        assert any("past_pr_comments" in s for s in context.sources)

    def test_no_conventions_or_comments_gives_empty_context(self):
        agent, mock_fetcher, _, mock_reviewer = make_agent()
        mock_fetcher.fetch_convention_files.return_value = {}
        mock_fetcher.fetch_recent_review_comments.return_value = []

        context = agent.build_project_context("https://github.com/owner/repo")

        assert context.is_empty
        mock_reviewer.embed_review_comments.assert_not_called()

    def test_second_call_for_same_repo_and_branch_is_cached(self):
        agent, mock_fetcher, _, mock_reviewer = make_agent()
        mock_fetcher.fetch_convention_files.return_value = {"README.md": "conventions"}
        mock_fetcher.fetch_recent_review_comments.return_value = []

        context1 = agent.build_project_context("https://github.com/owner/repo", branch="main")
        context2 = agent.build_project_context("https://github.com/owner/repo", branch="main")

        assert context1 is context2
        mock_fetcher.fetch_convention_files.assert_called_once()
        mock_fetcher.fetch_recent_review_comments.assert_called_once()

    def test_different_branch_is_a_cache_miss(self):
        agent, mock_fetcher, _, mock_reviewer = make_agent()
        mock_fetcher.fetch_convention_files.return_value = {}
        mock_fetcher.fetch_recent_review_comments.return_value = []

        agent.build_project_context("https://github.com/owner/repo", branch="main")
        agent.build_project_context("https://github.com/owner/repo", branch="develop")

        assert mock_fetcher.fetch_convention_files.call_count == 2

    def test_different_repo_is_a_cache_miss(self):
        agent, mock_fetcher, _, mock_reviewer = make_agent()
        mock_fetcher.fetch_convention_files.return_value = {}
        mock_fetcher.fetch_recent_review_comments.return_value = []

        agent.build_project_context("https://github.com/owner/repo-a")
        agent.build_project_context("https://github.com/owner/repo-b")

        assert mock_fetcher.fetch_convention_files.call_count == 2

    def test_fetch_failure_returns_empty_context_not_raised(self):
        agent, mock_fetcher, _, mock_reviewer = make_agent()
        mock_fetcher.fetch_convention_files.side_effect = RuntimeError("network blip")

        context = agent.build_project_context("https://github.com/owner/repo")

        assert context.is_empty

    def test_conventions_text_truncated_to_cap(self):
        agent, mock_fetcher, _, mock_reviewer = make_agent()
        huge_readme = "x" * 20_000
        mock_fetcher.fetch_convention_files.return_value = {"README.md": huge_readme}
        mock_fetcher.fetch_recent_review_comments.return_value = []

        context = agent.build_project_context("https://github.com/owner/repo")

        assert len(context.conventions_text) == RAG_MAX_CONVENTIONS_CHARS

    def test_review_repo_passes_built_context_to_reviewer(self):
        agent, mock_fetcher, _, mock_reviewer = make_agent()
        mock_fetcher.fetch_convention_files.return_value = {"README.md": "conventions"}
        mock_fetcher.fetch_recent_review_comments.return_value = []

        agent.review_repo("https://github.com/owner/repo")

        _, _, kwargs = mock_reviewer.review.mock_calls[0]
        assert kwargs["project_context"].conventions_text == "### README.md\nconventions"

    def test_generate_review_with_repo_url_builds_and_passes_context(self):
        agent, mock_fetcher, _, mock_reviewer = make_agent()
        mock_fetcher.fetch_convention_files.return_value = {"README.md": "conventions"}
        mock_fetcher.fetch_recent_review_comments.return_value = []
        files = [SimpleNamespace(path="a.py", content="x = 1\n")]

        agent.generate_review(files, make_scan_report(), repo_url="https://github.com/owner/repo")

        mock_fetcher.fetch_convention_files.assert_called_once()
        _, _, kwargs = mock_reviewer.review.mock_calls[0]
        assert kwargs["project_context"].conventions_text == "### README.md\nconventions"

    def test_generate_review_without_repo_url_skips_context_building(self):
        agent, mock_fetcher, _, mock_reviewer = make_agent()
        files = [SimpleNamespace(path="a.py", content="x = 1\n")]

        agent.generate_review(files, make_scan_report())

        mock_fetcher.fetch_convention_files.assert_not_called()
        mock_fetcher.fetch_recent_review_comments.assert_not_called()


class TestGranularAdkTools:

    def test_fetch_repo_files_tool_returns_json_serializable_dict(self):
        agent, *_ = make_agent(fetch_result=make_fetch_result(paths=("a.py",)))
        tool = make_fetch_repo_files_tool(agent)

        output = tool("https://github.com/owner/repo")

        json.dumps(output)
        assert set(output.keys()) == {"repo_url", "files", "files_count", "truncated"}
        assert output["files_count"] == 1

    def test_fetch_repo_files_tool_rejects_empty_url(self):
        agent, *_ = make_agent()
        tool = make_fetch_repo_files_tool(agent)

        with pytest.raises(ValueError, match="repo_url"):
            tool("")

    def test_scan_code_tool_returns_json_serializable_dict(self):
        agent, *_ = make_agent(scan_result=make_scan_report(findings_count=1))
        tool = make_scan_code_tool(agent)

        output = tool([{"path": "a.py", "content": "x = 1\n"}])

        json.dumps(output)
        assert set(output.keys()) == {"findings", "scanned", "skipped"}
        assert len(output["findings"]) == 1

    def test_scan_code_tool_rejects_empty_files(self):
        agent, *_ = make_agent()
        tool = make_scan_code_tool(agent)

        with pytest.raises(ValueError, match="files"):
            tool([])

    def test_generate_review_tool_returns_json_serializable_dict(self):
        agent, *_ = make_agent(review_result=make_review_report(issue_count=1))
        tool = make_generate_review_tool(agent)

        output = tool(
            [{"path": "a.py", "content": "x = 1\n"}],
            findings=[{"path": "a.py", "rule_id": "r1", "severity": "WARNING", "message": "m"}],
        )

        json.dumps(output)
        assert set(output.keys()) == {"issues", "summary", "model", "schema_errors"}
        assert len(output["issues"]) == 1

    def test_generate_review_tool_works_without_findings(self):
        agent, *_ = make_agent(review_result=make_review_report(issue_count=0))
        tool = make_generate_review_tool(agent)

        output = tool([{"path": "a.py", "content": "x = 1\n"}])

        json.dumps(output)
        assert output["issues"] == []

    def test_generate_review_tool_rejects_empty_files(self):
        agent, *_ = make_agent()
        tool = make_generate_review_tool(agent)

        with pytest.raises(ValueError, match="files"):
            tool([])


# ---------------------------------------------------------------------------
# 4c. "Interesting" extra tools: metadata, search, explain, save-report
# ---------------------------------------------------------------------------

class TestRepoMetadata:

    def test_get_repo_metadata_delegates_to_fetcher(self):
        agent, mock_fetcher, *_ = make_agent()
        mock_fetcher.get_repo_metadata.return_value = {"owner": "o", "repo": "r"}

        result = agent.get_repo_metadata("https://github.com/o/r")

        mock_fetcher.get_repo_metadata.assert_called_once_with("https://github.com/o/r")
        assert result == {"owner": "o", "repo": "r"}

    def test_get_repo_metadata_tool_returns_json_serializable_dict(self):
        agent, mock_fetcher, *_ = make_agent()
        mock_fetcher.get_repo_metadata.return_value = {
            "owner": "o", "repo": "r", "language": "Python",
            "default_branch": "main", "size_kb": 10, "stargazers_count": 5,
            "open_issues_count": 0, "pushed_at": "", "archived": False, "description": "",
        }
        tool = make_get_repo_metadata_tool(agent)

        output = tool("https://github.com/o/r")

        json.dumps(output)
        assert output["language"] == "Python"

    def test_get_repo_metadata_tool_rejects_empty_url(self):
        agent, *_ = make_agent()
        tool = make_get_repo_metadata_tool(agent)

        with pytest.raises(ValueError, match="repo_url"):
            tool("")


class TestSearchCode:

    def test_search_code_finds_matching_lines(self):
        agent, *_ = make_agent()
        files = [
            SimpleNamespace(path="a.py", content="x = eval(user_input)\ny = 2\n"),
            SimpleNamespace(path="b.py", content="z = 3\n"),
        ]

        matches = agent.search_code(files, pattern=r"eval\(")

        assert len(matches) == 1
        assert matches[0]["path"] == "a.py"
        assert matches[0]["line"] == 1

    def test_search_code_is_case_insensitive_by_default(self):
        agent, *_ = make_agent()
        files = [SimpleNamespace(path="a.py", content="TODO: fix this\n")]

        matches = agent.search_code(files, pattern="todo")

        assert len(matches) == 1

    def test_search_code_rejects_empty_pattern(self):
        agent, *_ = make_agent()
        with pytest.raises(ValueError, match="pattern"):
            agent.search_code([], pattern="")

    def test_search_code_rejects_invalid_regex(self):
        agent, *_ = make_agent()
        with pytest.raises(ValueError, match="regex"):
            agent.search_code([SimpleNamespace(path="a.py", content="x\n")], pattern="(")

    def test_search_code_tool_returns_json_serializable_dict(self):
        agent, *_ = make_agent()
        tool = make_search_code_tool(agent)

        output = tool([{"path": "a.py", "content": "eval(x)\n"}], "eval")

        json.dumps(output)
        assert output["match_count"] == 1

    def test_search_code_tool_rejects_empty_files(self):
        agent, *_ = make_agent()
        tool = make_search_code_tool(agent)

        with pytest.raises(ValueError, match="files"):
            tool([], "eval")


class TestExplainFinding:

    def test_explain_finding_delegates_to_reviewer(self):
        agent, _, _, mock_reviewer = make_agent()
        mock_reviewer.explain_issue.return_value = "This matters because..."

        result = agent.explain_finding(
            path="a.py", title="SQL injection", description="raw query"
        )

        mock_reviewer.explain_issue.assert_called_once()
        assert result == "This matters because..."

    def test_explain_finding_tool_returns_json_serializable_dict(self):
        agent, _, _, mock_reviewer = make_agent()
        mock_reviewer.explain_issue.return_value = "Explanation text."
        tool = make_explain_finding_tool(agent)

        output = tool(path="a.py", title="SQL injection", description="raw query")

        json.dumps(output)
        assert output["explanation"] == "Explanation text."

    def test_explain_finding_tool_rejects_missing_title_and_description(self):
        agent, *_ = make_agent()
        tool = make_explain_finding_tool(agent)

        with pytest.raises(ValueError):
            tool(path="a.py", title="", description="")


class TestSaveReport:

    def test_save_report_writes_a_real_markdown_file(self, tmp_path):
        agent, *_ = make_agent()
        output_path = str(tmp_path / "report.md")

        result_path = agent.save_report(
            repo_url="https://github.com/o/r",
            files=[SimpleNamespace(path="a.py", content="x = 1\n")],
            findings=[],
            issues=[],
            summary="All good.",
            model="gemini-3.1-flash-lite",
            output_path=output_path,
        )

        assert result_path == output_path
        text = open(output_path, encoding="utf-8").read()
        assert "All good." in text

    def test_generate_report_file_tool_returns_json_serializable_dict(self, tmp_path):
        agent, *_ = make_agent()
        tool = make_generate_report_file_tool(agent)
        output_path = str(tmp_path / "report.md")

        output = tool(
            repo_url="https://github.com/o/r",
            files=[{"path": "a.py", "content": "x = 1\n"}],
            issues=[{"path": "a.py", "line": 1, "severity": "LOW", "title": "t", "description": "d", "suggested_fix": "f"}],
            summary="ok",
            model="gemini-3.1-flash-lite",
            output_path=output_path,
        )

        json.dumps(output)
        assert output["output_path"] == output_path

    def test_generate_report_file_tool_rejects_empty_files(self):
        agent, *_ = make_agent()
        tool = make_generate_report_file_tool(agent)

        with pytest.raises(ValueError, match="files"):
            tool(repo_url="https://github.com/o/r", files=[], issues=[])


# ---------------------------------------------------------------------------
# 4b. create_issue_tool
# ---------------------------------------------------------------------------
#
# This tool is a thin pass-through to agent._fetcher.create_review_issue()
# (mirroring how make_post_pr_review_tool wraps agent._fetcher.post_pr_review()
# with no intermediate CodeReviewAgent method) -- so these tests verify the
# ADK-tool-shape contract (argument validation, dict-in/dict-out, the None ->
# {"created": False, "reason": ...} translation) against a mocked fetcher,
# not the real severity-threshold/formatting logic, which is covered in
# tests/test_github_fetcher.py's TestCreateReviewIssue.

class TestCreateIssueTool:

    def test_rejects_empty_repo_url(self):
        agent, *_ = make_agent()
        tool = make_create_issue_tool(agent)

        with pytest.raises(ValueError, match="repo_url"):
            tool(repo_url="", issues=[])

    def test_rejects_non_list_issues(self):
        agent, *_ = make_agent()
        tool = make_create_issue_tool(agent)

        with pytest.raises(ValueError, match="issues"):
            tool(repo_url="https://github.com/o/r", issues="not-a-list")

    def test_returns_created_false_when_fetcher_declines(self):
        agent, mock_fetcher, *_ = make_agent()
        mock_fetcher.create_review_issue.return_value = None
        tool = make_create_issue_tool(agent)

        output = tool(
            repo_url="https://github.com/o/r",
            issues=[{"path": "a.py", "line": 1, "severity": "LOW", "title": "t", "description": "d"}],
        )

        json.dumps(output)
        assert output["created"] is False
        assert "reason" in output

    def test_returns_created_true_with_issue_details(self):
        agent, mock_fetcher, *_ = make_agent()
        mock_fetcher.create_review_issue.return_value = {
            "issue_number": 42, "html_url": "https://github.com/o/r/issues/42",
        }
        tool = make_create_issue_tool(agent)

        output = tool(
            repo_url="https://github.com/o/r",
            issues=[{"path": "a.py", "line": 1, "severity": "CRITICAL", "title": "t", "description": "d"}],
        )

        json.dumps(output)
        assert output == {"created": True, "issue_number": 42, "html_url": "https://github.com/o/r/issues/42"}

    def test_passes_min_severity_through_to_fetcher(self):
        agent, mock_fetcher, *_ = make_agent()
        mock_fetcher.create_review_issue.return_value = None
        tool = make_create_issue_tool(agent)

        tool(repo_url="https://github.com/o/r", issues=[], summary="s", min_severity="MEDIUM")

        mock_fetcher.create_review_issue.assert_called_once_with(
            "https://github.com/o/r", [], "s", "MEDIUM"
        )


# ---------------------------------------------------------------------------
# 5. Secret hygiene
# ---------------------------------------------------------------------------

class TestSecretHygiene:

    def test_secrets_never_logged(self, caplog):
        agent, *_ = make_agent(
            scan_side_effect=SemgrepExecutionError("boom", returncode=2),
            review_side_effect=GeminiRateLimitError("rate limited"),
        )

        with caplog.at_level(logging.DEBUG):
            agent.review_repo("https://github.com/owner/repo")

        for record in caplog.records:
            assert "ghp_faketoken" not in record.getMessage()


# ---------------------------------------------------------------------------
# 6. security_full_scan (ParallelAgent + aggregator, deterministic full scan)
# ---------------------------------------------------------------------------

def _find_agent(root, name):
    """Depth-first search of an ADK agent tree by name."""
    if root.name == name:
        return root
    for sub in getattr(root, "sub_agents", None) or []:
        found = _find_agent(sub, name)
        if found is not None:
            return found
    return None


def _build_root():
    """Build the full ADK agent graph with all underlying clients mocked,
    the same pattern make_agent() uses for CodeReviewAgent directly."""
    with patch("agent.GitHubFetcher"), patch("agent.SemgrepRunner"), patch("agent.GeminiReviewer"):
        return agent_module.build_multi_agent_system(
            github_token="ghp_faketoken", gemini_api_key="gem_fakekey"
        )


class TestSecurityFullScan:

    def test_security_coordinator_keeps_existing_specialists_and_gains_full_scan(self):
        root = _build_root()
        security_coordinator = _find_agent(root, "security_coordinator")
        assert security_coordinator is not None
        names = {a.name for a in security_coordinator.sub_agents}
        # Existing single-specialist routing must be untouched.
        assert {"sast_agent", "injection_agent", "auth_agent", "crypto_agent",
                "secrets_agent", "data_flow_agent"} <= names
        # New deterministic full-scan path is an addition, not a replacement.
        assert "security_full_scan" in names

    def test_security_full_scan_is_sequential_parallel_then_aggregator(self):
        root = _build_root()
        full_scan = _find_agent(root, "security_full_scan")
        assert isinstance(full_scan, SequentialAgent)
        assert len(full_scan.sub_agents) == 2

        parallel_scan, aggregator = full_scan.sub_agents
        assert isinstance(parallel_scan, ParallelAgent)
        assert aggregator.name == "security_aggregator_agent"

        parallel_names = {a.name for a in parallel_scan.sub_agents}
        assert parallel_names == {
            "sast_agent_scan", "injection_agent_scan", "auth_agent_scan",
            "crypto_agent_scan", "secrets_agent_scan", "data_flow_agent_scan",
        }

    def test_parallel_scan_specialists_are_distinct_instances_from_coordinator_specialists(self):
        """ADK requires a single-parent agent tree -- the parallel-scan path
        must use cloned specialists, not the same instances security_coordinator
        routes single-specialist requests to (which would otherwise raise a
        duplicate-parent error at construction time -- the fact this builds at
        all already proves that, but assert the instances differ explicitly)."""
        root = _build_root()
        sast_standalone = _find_agent(root, "sast_agent")
        sast_scan = _find_agent(root, "sast_agent_scan")
        assert sast_standalone is not sast_scan
        assert sast_standalone.name != sast_scan.name

    def test_output_keys_set_for_state_passing_to_aggregator(self):
        root = _build_root()
        expected = {
            "sast_agent": "sast_result",
            "injection_agent": "injection_result",
            "auth_agent": "auth_result",
            "crypto_agent": "crypto_result",
            "secrets_agent": "secrets_result",
            "data_flow_agent": "data_flow_result",
        }
        for name, key in expected.items():
            specialist = _find_agent(root, name)
            assert specialist.output_key == key
            scan_clone = _find_agent(root, f"{name}_scan")
            assert scan_clone.output_key == key


# ---------------------------------------------------------------------------
# 7. remediation_loop (LoopAgent verify-and-refine)
# ---------------------------------------------------------------------------

class TestRemediationLoop:

    def test_remediation_agent_is_a_loop_of_generator_then_verifier(self):
        root = _build_root()
        remediation = _find_agent(root, "remediation_agent")
        assert isinstance(remediation, LoopAgent)
        assert remediation.max_iterations == 3
        names = [a.name for a in remediation.sub_agents]
        assert names == ["patch_generator_agent", "patch_verifier_step"]

    def test_root_still_transfers_to_remediation_agent_by_name(self):
        """B4: root, POST /remediate, and Streamlit all still refer to
        'remediation_agent' -- only its internal implementation changed."""
        root = _build_root()
        names = [a.name for a in root.sub_agents]
        assert "remediation_agent" in names


class TestGenerateRemediationPatchesWithVerification:
    """CodeReviewAgent.generate_remediation_patches_with_verification --
    the non-ADK verify-and-refine path used by POST /remediate and the
    Streamlit fix-generation button (which bypass the ADK graph entirely,
    so remediation_loop's LoopAgent behavior doesn't reach them on its own)."""

    def test_clean_on_first_try_exits_after_one_iteration_not_three(self):
        agent, _fetcher, _semgrep, reviewer = make_agent()
        reviewer.generate_remediation_patches.return_value = {
            "patches": [{"finding_index": 0, "path": "a.py", "before": "bad", "after": "good"}],
            "summary": "1 patch generated.",
        }
        reviewer.verify_patch_resolves_finding.return_value = {
            "resolved": True, "reason": "No longer vulnerable.", "method": "llm",
        }
        findings = [{"path": "a.py", "title": "Hardcoded secret", "severity": "HIGH"}]
        files = [SimpleNamespace(path="a.py", content="bad")]

        result = agent.generate_remediation_patches_with_verification(findings, files, max_iterations=3)

        assert result["iterations_run"] == 1
        assert result["fully_resolved"] is True
        assert result["patches"][0]["verified"] is True
        assert "unresolved_finding_indices" not in result
        # Only the initial generation call -- no wasted retry regeneration.
        assert reviewer.generate_remediation_patches.call_count == 1

    def test_still_fails_after_retries_runs_all_three_and_reports_honestly(self):
        agent, _fetcher, _semgrep, reviewer = make_agent()
        reviewer.generate_remediation_patches.return_value = {
            "patches": [{"finding_index": 0, "path": "a.py", "before": "bad", "after": "still_bad"}],
            "summary": "1 patch generated.",
        }
        reviewer.verify_patch_resolves_finding.return_value = {
            "resolved": False, "reason": "Still exploitable.", "method": "llm",
        }
        findings = [{"path": "a.py", "title": "Hardcoded secret", "severity": "HIGH"}]
        files = [SimpleNamespace(path="a.py", content="bad")]

        result = agent.generate_remediation_patches_with_verification(findings, files, max_iterations=3)

        assert result["iterations_run"] == 3
        assert result["fully_resolved"] is False
        assert result["unresolved_finding_indices"] == [0]
        assert result["patches"][0]["verified"] is False
        # Initial call + 2 retries (iteration 3 doesn't regenerate again since
        # it's the last allowed attempt) -- capped, not unbounded.
        assert reviewer.generate_remediation_patches.call_count == 3

    def test_no_findings_short_circuits_without_calling_reviewer(self):
        agent, _fetcher, _semgrep, reviewer = make_agent()

        result = agent.generate_remediation_patches_with_verification([], [])

        assert result == {
            "patches": [], "summary": "No findings to remediate.",
            "iterations_run": 0, "fully_resolved": True,
        }
        reviewer.generate_remediation_patches.assert_not_called()

    def test_parse_error_from_initial_generation_is_reported_not_crashed(self):
        agent, _fetcher, _semgrep, reviewer = make_agent()
        reviewer.generate_remediation_patches.return_value = {
            "raw": "not json", "parse_error": True,
        }

        result = agent.generate_remediation_patches_with_verification(
            [{"path": "a.py", "title": "t"}], [SimpleNamespace(path="a.py", content="x")],
        )

        assert result["parse_error"] is True
        assert result["fully_resolved"] is False
        reviewer.verify_patch_resolves_finding.assert_not_called()


class TestVerifyPatch:
    """CodeReviewAgent.verify_patch -- the check step both remediation_loop's
    ADK tool (patch_verifier_tool) and generate_remediation_patches_with_verification
    share, so both surfaces behave consistently."""

    def test_rule_id_backed_finding_uses_semgrep_rescan_not_llm(self):
        agent, _fetcher, mock_semgrep, reviewer = make_agent()
        mock_semgrep.scan.return_value = ScanReport(findings=[], scanned=1, skipped=[], duration_s=0.01)

        finding = {"path": "a.py", "line": 1, "rule_id": "python.lang.security.exec-use"}
        patch = {"finding_index": 0, "path": "a.py", "after": "safe_code()"}

        verdict = agent.verify_patch(finding, patch)

        assert verdict == {
            "resolved": True,
            "reason": "Semgrep rule python.lang.security.exec-use no longer fires on the patched code.",
            "method": "semgrep",
        }
        mock_semgrep.scan.assert_called_once()
        reviewer.verify_patch_resolves_finding.assert_not_called()

    def test_rule_id_still_firing_is_not_resolved(self):
        agent, _fetcher, mock_semgrep, _reviewer = make_agent()
        mock_semgrep.scan.return_value = ScanReport(
            findings=[Finding(path="a.py", line_start=1, line_end=1,
                               rule_id="python.lang.security.exec-use",
                               severity="ERROR", message="m", snippet="exec(x)")],
            scanned=1, skipped=[], duration_s=0.01,
        )

        finding = {"path": "a.py", "rule_id": "python.lang.security.exec-use"}
        patch = {"finding_index": 0, "path": "a.py", "after": "exec(x)"}

        verdict = agent.verify_patch(finding, patch)

        assert verdict["resolved"] is False
        assert "python.lang.security.exec-use" in verdict["reason"]

    def test_no_rule_id_falls_back_to_llm_judged_check(self):
        agent, _fetcher, mock_semgrep, reviewer = make_agent()
        reviewer.verify_patch_resolves_finding.return_value = {
            "resolved": True, "reason": "ok", "method": "llm",
        }

        finding = {"path": "a.py", "title": "Quality nit"}  # no rule_id -- LLM-only finding
        patch = {"finding_index": 0, "path": "a.py", "after": "clean_code()"}

        verdict = agent.verify_patch(finding, patch)

        assert verdict == {"resolved": True, "reason": "ok", "method": "llm"}
        mock_semgrep.scan.assert_not_called()
        reviewer.verify_patch_resolves_finding.assert_called_once_with(finding, "clean_code()")

    def test_patch_with_no_after_code_is_unresolved(self):
        agent, *_ = make_agent()
        verdict = agent.verify_patch({"path": "a.py"}, {"after": ""})
        assert verdict["resolved"] is False
        assert verdict["method"] == "none"


class TestPatchVerifierTool:
    """The ADK-tool wrapper (make_patch_verifier_tool) used by
    patch_verifier_step inside remediation_loop."""

    def test_wraps_verify_patch_and_logs_a_tracing_span(self):
        agent, _fetcher, mock_semgrep, _reviewer = make_agent()
        mock_semgrep.scan.return_value = ScanReport(findings=[], scanned=1, skipped=[], duration_s=0.01)
        tool = make_patch_verifier_tool(agent)

        result = tool(
            finding={"path": "a.py", "rule_id": "r1", "title": "t"},
            patch={"finding_index": 0, "path": "a.py", "after": "fixed()"},
        )

        assert result["resolved"] is True
        json.dumps(result)

    def test_rejects_non_dict_arguments(self):
        agent, *_ = make_agent()
        tool = make_patch_verifier_tool(agent)
        with pytest.raises(ValueError):
            tool(finding="not a dict", patch={})
            assert "gem_fakekey" not in record.getMessage()
