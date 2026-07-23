"""
tests/test_server.py
---------------------
Route-level tests for server.py's POST /remediate endpoint, using FastAPI's
TestClient.

Unlike test_server_traces.py (which tests server.py's pure aggregation
functions directly, deliberately avoiding TestClient/app.state.agent — see
its docstring), these tests exercise the actual HTTP route end to end:
request validation, status codes, and response shape.

TestClient(app) is constructed WITHOUT entering it as a context manager
(no `with TestClient(app) as client:`), which means the real `lifespan`
never runs. That matters here because the real lifespan builds a real
CodeReviewAgent, which in turn constructs a real SemgrepRunner that checks
for the semgrep binary on PATH at __init__ time and raises if it's
missing — a real dependency this test environment may not have, and one
these tests have no reason to need since they're testing server.py's
routing/validation, not Semgrep. Instead, app.state.agent is set directly
to a MagicMock (or a purpose-built fake), following the same "mock the
external client, test our own logic" convention test_agent.py already
uses for CodeReviewAgent's own orchestration tests.

Run with:
    pytest tests/test_server.py -v
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# Must be set before `import server` — server.py reads these at module load
# time via load_dotenv()/os.environ.get(), even though the values are never
# actually used since the real lifespan never runs in these tests.
os.environ.setdefault("GITHUB_TOKEN", "test-token")
os.environ.setdefault("GEMINI_API_KEY", "test-key")

from fastapi.testclient import TestClient

import server
from github_fetcher import (
    AuthenticationError,
    GitHubAPIError,
    PayloadTooLargeError,
    RateLimitError,
    RepoNotFoundError,
)

VALID_REPO = "https://github.com/octocat/Hello-World"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_fetch_result(paths=("app.py",), truncated=False) -> SimpleNamespace:
    files = [SimpleNamespace(path=p, content=f"# {p}\nprint('hi')\n") for p in paths]
    return SimpleNamespace(files=files, truncated=truncated)


def make_finding(path="app.py", line=10, **overrides) -> dict:
    finding = {
        "path": path, "line": line, "severity": "HIGH", "title": "Finding",
        "description": "d", "suggested_fix": "f", "rule_id": None,
    }
    finding.update(overrides)
    return finding


def make_patch(**overrides) -> dict:
    patch = {
        "finding_index": 0, "path": "app.py", "line": 10, "title": "Finding",
        "before": "bad code", "after": "good code", "explanation": "why",
        "dependencies": [], "breaking_change": False, "breaking_change_note": None,
    }
    patch.update(overrides)
    return patch


@pytest.fixture
def mock_agent():
    return MagicMock()


@pytest.fixture
def client(mock_agent):
    server.app.state.agent = mock_agent
    return TestClient(server.app)


# ---------------------------------------------------------------------------
# Success paths
# ---------------------------------------------------------------------------

class TestRemediateSuccess:

    def test_returns_patches_for_a_single_finding(self, client, mock_agent):
        mock_agent.fetch_files.return_value = make_fetch_result(paths=("app.py",))
        mock_agent.generate_remediation_patches.return_value = {
            "patches": [make_patch()],
            "summary": "1 patch generated.",
        }

        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO,
            "branch": "main",
            "findings": [make_finding()],
        })

        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"] == "1 patch generated."
        assert len(data["patches"]) == 1
        assert data["patches"][0]["before"] == "bad code"
        assert data["patches"][0]["after"] == "good code"
        assert data["missing_paths"] == []
        assert data["schema_errors"] == []
        assert data["parse_error"] is False

    def test_fetches_with_requested_branch_and_max_files(self, client, mock_agent):
        mock_agent.fetch_files.return_value = make_fetch_result(paths=("app.py",))
        mock_agent.generate_remediation_patches.return_value = {"patches": [], "summary": ""}

        client.post("/remediate", json={
            "repo_url": VALID_REPO,
            "branch": "develop",
            "max_files": 42,
            "findings": [make_finding()],
        })

        mock_agent.fetch_files.assert_called_once_with(VALID_REPO, branch="develop", max_files=42)

    def test_reimplements_nothing_passes_findings_and_files_through_unchanged(self, client, mock_agent):
        """The endpoint's whole job is to expose generate_remediation_patches(),
        not reimplement it — assert the exact findings dict and exact filtered
        file objects reach it."""
        mock_agent.fetch_files.return_value = make_fetch_result(paths=("app.py", "unrelated.py"))
        mock_agent.generate_remediation_patches.return_value = {"patches": [], "summary": ""}

        client.post("/remediate", json={
            "repo_url": VALID_REPO,
            "findings": [make_finding(path="app.py", title="SQL Injection")],
        })

        mock_agent.generate_remediation_patches.assert_called_once()
        call_findings, call_files = mock_agent.generate_remediation_patches.call_args[0]
        assert call_findings == [make_finding(path="app.py", title="SQL Injection")]
        # Only the referenced file is passed through — not the unrelated one.
        assert [f.path for f in call_files] == ["app.py"]

    def test_missing_path_reported_but_others_still_proceed(self, client, mock_agent):
        mock_agent.fetch_files.return_value = make_fetch_result(paths=("app.py",))
        mock_agent.generate_remediation_patches.return_value = {"patches": [], "summary": "ok"}

        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO,
            "findings": [make_finding(path="app.py"), make_finding(path="gone.py", line=2)],
        })

        assert resp.status_code == 200
        assert resp.json()["missing_paths"] == ["gone.py"]
        # Only the found file reaches the remediation call.
        call_files = mock_agent.generate_remediation_patches.call_args[0][1]
        assert [f.path for f in call_files] == ["app.py"]

    def test_malformed_patch_dropped_and_recorded_not_500(self, client, mock_agent):
        mock_agent.fetch_files.return_value = make_fetch_result(paths=("app.py",))
        mock_agent.generate_remediation_patches.return_value = {
            "patches": [
                make_patch(),
                {"path": "app.py", "line": "not-an-int"},  # malformed: line must be int
            ],
            "summary": "s",
        }

        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO,
            "findings": [make_finding()],
        })

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["patches"]) == 1
        assert len(data["schema_errors"]) == 1

    def test_parse_error_surfaced_not_500(self, client, mock_agent):
        mock_agent.fetch_files.return_value = make_fetch_result(paths=("app.py",))
        mock_agent.generate_remediation_patches.return_value = {"raw": "not json", "parse_error": True}

        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO,
            "findings": [make_finding()],
        })

        assert resp.status_code == 200
        data = resp.json()
        assert data["parse_error"] is True
        assert data["patches"] == []
        assert data["schema_errors"] == ["Gemini response was not valid JSON"]


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

class TestRemediateErrors:

    def test_all_paths_missing_returns_400_and_skips_remediation_call(self, client, mock_agent):
        mock_agent.fetch_files.return_value = make_fetch_result(paths=("other.py",))

        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO,
            "findings": [make_finding(path="gone.py")],
        })

        assert resp.status_code == 400
        assert "gone.py" in resp.json()["detail"]
        mock_agent.generate_remediation_patches.assert_not_called()

    def test_repo_not_found_returns_404(self, client, mock_agent):
        mock_agent.fetch_files.side_effect = RepoNotFoundError("no such repo")
        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO, "findings": [make_finding()],
        })
        assert resp.status_code == 404

    def test_bad_token_returns_401(self, client, mock_agent):
        mock_agent.fetch_files.side_effect = AuthenticationError("bad token")
        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO, "findings": [make_finding()],
        })
        assert resp.status_code == 401

    def test_rate_limit_returns_429(self, client, mock_agent):
        mock_agent.fetch_files.side_effect = RateLimitError("rate limited")
        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO, "findings": [make_finding()],
        })
        assert resp.status_code == 429

    def test_payload_too_large_returns_413(self, client, mock_agent):
        mock_agent.fetch_files.side_effect = PayloadTooLargeError("too big")
        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO, "findings": [make_finding()],
        })
        assert resp.status_code == 413

    def test_github_api_error_returns_502(self, client, mock_agent):
        mock_agent.fetch_files.side_effect = GitHubAPIError("upstream broke")
        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO, "findings": [make_finding()],
        })
        assert resp.status_code == 502

    def test_unexpected_exception_returns_500_not_raw_traceback(self, client, mock_agent):
        mock_agent.fetch_files.side_effect = RuntimeError("boom")
        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO, "findings": [make_finding()],
        })
        assert resp.status_code == 500
        mock_agent.generate_remediation_patches.assert_not_called()


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------

class TestRemediateValidation:

    def test_rejects_non_github_url(self, client, mock_agent):
        resp = client.post("/remediate", json={
            "repo_url": "https://example.com/owner/repo",
            "findings": [make_finding()],
        })
        assert resp.status_code == 422
        mock_agent.fetch_files.assert_not_called()

    def test_rejects_empty_findings_list(self, client, mock_agent):
        resp = client.post("/remediate", json={"repo_url": VALID_REPO, "findings": []})
        assert resp.status_code == 422
        mock_agent.fetch_files.assert_not_called()

    def test_rejects_missing_findings_path(self, client, mock_agent):
        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO,
            "findings": [{"title": "no path field"}],
        })
        assert resp.status_code == 422

    def test_max_files_out_of_range_rejected(self, client, mock_agent):
        resp = client.post("/remediate", json={
            "repo_url": VALID_REPO,
            "max_files": 1000,
            "findings": [make_finding()],
        })
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Pure helper functions (mirroring test_server_traces.py's style)
# ---------------------------------------------------------------------------

class TestFilterRelevantFiles:

    def test_keeps_only_requested_paths(self):
        files = [SimpleNamespace(path="a.py"), SimpleNamespace(path="b.py")]
        relevant, missing = server._filter_relevant_files(files, {"a.py"})
        assert [f.path for f in relevant] == ["a.py"]
        assert missing == []

    def test_reports_requested_paths_not_found(self):
        files = [SimpleNamespace(path="a.py")]
        relevant, missing = server._filter_relevant_files(files, {"a.py", "z.py"})
        assert [f.path for f in relevant] == ["a.py"]
        assert missing == ["z.py"]

    def test_all_missing_returns_empty_relevant(self):
        files = [SimpleNamespace(path="a.py")]
        relevant, missing = server._filter_relevant_files(files, {"z.py"})
        assert relevant == []
        assert missing == ["z.py"]


class TestBuildRemediateResponse:

    def test_builds_patches_from_raw_dict(self):
        response = server._build_remediate_response({
            "patches": [make_patch()], "summary": "s",
        })
        assert len(response.patches) == 1
        assert response.summary == "s"
        assert response.parse_error is False
        assert response.schema_errors == []

    def test_parse_error_short_circuits(self):
        response = server._build_remediate_response({"raw": "x", "parse_error": True})
        assert response.parse_error is True
        assert response.patches == []
        assert response.schema_errors == ["Gemini response was not valid JSON"]

    def test_malformed_patch_recorded_not_raised(self):
        response = server._build_remediate_response({
            "patches": [make_patch(), {"line": "nope"}],
            "summary": "s",
        })
        assert len(response.patches) == 1
        assert len(response.schema_errors) == 1

    def test_empty_patches_list_is_fine(self):
        response = server._build_remediate_response({"patches": [], "summary": "none"})
        assert response.patches == []
        assert response.summary == "none"
