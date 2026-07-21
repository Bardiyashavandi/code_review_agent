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

from agent import (
    CodeReviewAgent,
    PipelineResult,
    make_explain_finding_tool,
    make_fetch_repo_files_tool,
    make_generate_report_file_tool,
    make_generate_review_tool,
    make_get_repo_metadata_tool,
    make_review_repo_tool,
    make_scan_code_tool,
    make_search_code_tool,
)
from gemini_reviewer import GeminiRateLimitError
from semgrep_runner import SemgrepExecutionError

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

        mock_reviewer.review.assert_called_once_with(files, scan_report)
        mock_fetcher.fetch_python_files.assert_not_called()
        mock_semgrep.scan.assert_not_called()
        assert result is mock_reviewer.review.return_value


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
            assert "gem_fakekey" not in record.getMessage()
