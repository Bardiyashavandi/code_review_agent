"""
tests/test_github_fetcher.py
----------------------------
Full test suite for github_fetcher.py.
All HTTP calls are stubbed — no live API calls are made.

Run with:
    pytest tests/test_github_fetcher.py -v
"""

from __future__ import annotations

import base64
import json
import time
from unittest.mock import patch

import httpx
import pytest

from github_fetcher import (
    AuthenticationError,
    GitHubAPIError,
    GitHubFetcher,
    PayloadTooLargeError,
    RateLimitError,
    RepoNotFoundError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_URL = "http://fake-github.test"


def make_fetcher(**kwargs) -> GitHubFetcher:
    return GitHubFetcher(token="ghp_faketoken123", base_url=BASE_URL, **kwargs)


def b64(text: str) -> str:
    """Return base64-encoded version of text (as GitHub API does)."""
    return base64.b64encode(text.encode()).decode()


def tree_response(files: list[dict]) -> dict:
    """Build a GitHub tree API response payload."""
    return {
        "sha": "abc123",
        "tree": [
            {
                "path": f["path"],
                "type": "blob",
                "sha": f.get("sha", "deadbeef"),
                "size": f.get("size", len(f.get("content", "hello"))),
                "url": f"{BASE_URL}/blob/{f['path']}",
            }
            for f in files
        ],
        "truncated": False,
    }


def contents_response(path: str, content: str) -> dict:
    """Build a GitHub contents API response payload."""
    encoded = b64(content)
    return {
        "path": path,
        "sha": "deadbeef",
        "size": len(content),
        "content": encoded,
        "encoding": "base64",
    }


def mock_transport(routes: dict[str, tuple[int, dict]]) -> httpx.MockTransport:
    """
    Build an httpx MockTransport from a dict of {url: (status_code, body)}.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        for pattern, (status, body) in routes.items():
            if pattern in url:
                return httpx.Response(
                    status_code=status,
                    json=body,
                    headers={"X-RateLimit-Remaining": "60", "X-RateLimit-Reset": "9999999999"},
                )
        return httpx.Response(404, json={"message": "Not Found"})

    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# 1. URL Parsing
# ---------------------------------------------------------------------------

class TestParseRepoUrl:

    def test_parse_valid_url(self):
        fetcher = make_fetcher()
        assert fetcher.parse_repo_url("https://github.com/owner/repo") == ("owner", "repo")

    def test_parse_strips_git_suffix(self):
        fetcher = make_fetcher()
        assert fetcher.parse_repo_url("https://github.com/owner/repo.git") == ("owner", "repo")

    def test_parse_www_github(self):
        fetcher = make_fetcher()
        assert fetcher.parse_repo_url("https://www.github.com/owner/repo") == ("owner", "repo")

    def test_parse_rejects_subpath(self):
        fetcher = make_fetcher()
        with pytest.raises(ValueError, match="must be exactly"):
            fetcher.parse_repo_url("https://github.com/owner/repo/tree/main")

    def test_parse_rejects_non_github(self):
        fetcher = make_fetcher()
        with pytest.raises(ValueError, match="Only github.com"):
            fetcher.parse_repo_url("https://gitlab.com/owner/repo")

    def test_parse_rejects_query_string(self):
        fetcher = make_fetcher()
        with pytest.raises(ValueError, match="query strings"):
            fetcher.parse_repo_url("https://github.com/owner/repo?tab=readme")

    def test_parse_rejects_fragment(self):
        fetcher = make_fetcher()
        with pytest.raises(ValueError, match="query strings"):
            fetcher.parse_repo_url("https://github.com/owner/repo#readme")

    def test_parse_rejects_no_repo(self):
        fetcher = make_fetcher()
        with pytest.raises(ValueError):
            fetcher.parse_repo_url("https://github.com/owner")

    def test_parse_rejects_bare_host(self):
        fetcher = make_fetcher()
        with pytest.raises(ValueError):
            fetcher.parse_repo_url("https://github.com/")


# ---------------------------------------------------------------------------
# 2. Token Validation
# ---------------------------------------------------------------------------

class TestTokenValidation:

    def test_empty_token_raises(self):
        with pytest.raises(ValueError, match="GITHUB_TOKEN must not be empty"):
            GitHubFetcher(token="")

    def test_whitespace_token_raises(self):
        with pytest.raises(ValueError, match="GITHUB_TOKEN must not be empty"):
            GitHubFetcher(token="   ")

    def test_valid_token_accepted(self):
        fetcher = GitHubFetcher(token="ghp_validtoken")
        assert fetcher is not None


# ---------------------------------------------------------------------------
# 3. File Filtering
# ---------------------------------------------------------------------------

class TestFiltering:

    def _fetcher_with_tree(self, tree_payload: dict, contents: dict[str, str]) -> GitHubFetcher:
        """Build a fetcher whose HTTP calls return the given tree + contents."""
        routes = {"/git/trees/": (200, tree_payload)}
        for path, body in contents.items():
            routes[f"/contents/{path}"] = (200, contents_response(path, body))

        fetcher = make_fetcher()
        fetcher._client = httpx.Client(
            transport=mock_transport(routes),
            headers={"Authorization": "Bearer ghp_faketoken123"},
        )
        return fetcher

    def test_fetch_filters_non_python(self):
        tree = tree_response([
            {"path": "src/main.py", "content": "print()"},
            {"path": "src/app.js", "content": "console.log()"},
            {"path": "README.md", "content": "# Readme"},
        ])
        fetcher = self._fetcher_with_tree(tree, {"src/main.py": "print()"})
        result = fetcher.fetch_python_files("https://github.com/owner/repo")
        assert len(result.files) == 1
        assert result.files[0].path == "src/main.py"

    def test_fetch_skips_excluded_dirs(self):
        tree = tree_response([
            {"path": "tests/test_foo.py", "content": "def test(): pass"},
            {"path": "src/bar.py", "content": "x = 1"},
        ])
        fetcher = self._fetcher_with_tree(tree, {"src/bar.py": "x = 1"})
        result = fetcher.fetch_python_files("https://github.com/owner/repo")
        paths = [f.path for f in result.files]
        assert "src/bar.py" in paths
        assert "tests/test_foo.py" not in paths

    def test_fetch_skips_oversized_file(self, caplog):
        import logging
        tree = tree_response([
            {"path": "big.py", "size": 600_000, "content": "x = 1"},
            {"path": "small.py", "size": 100, "content": "y = 2"},
        ])
        fetcher = self._fetcher_with_tree(tree, {"small.py": "y = 2"})
        with caplog.at_level(logging.WARNING, logger="github_fetcher"):
            result = fetcher.fetch_python_files("https://github.com/owner/repo")
        paths = [f.path for f in result.files]
        assert "big.py" not in paths
        assert "small.py" in paths
        assert any("big.py" in msg for msg in caplog.messages)

    def test_fetch_truncates_at_max_files(self):
        many_files = [{"path": f"src/mod_{i}.py", "content": "x=1"} for i in range(20)]
        tree = tree_response(many_files)
        contents = {f["path"]: "x=1" for f in many_files}
        fetcher = self._fetcher_with_tree(tree, contents)
        result = fetcher.fetch_python_files("https://github.com/owner/repo", max_files=5)
        assert len(result.files) == 5
        assert result.truncated is True

    def test_no_truncation_when_under_limit(self):
        files = [{"path": f"src/mod_{i}.py", "content": "x=1"} for i in range(3)]
        tree = tree_response(files)
        contents = {f["path"]: "x=1" for f in files}
        fetcher = self._fetcher_with_tree(tree, contents)
        result = fetcher.fetch_python_files("https://github.com/owner/repo", max_files=10)
        assert len(result.files) == 3
        assert result.truncated is False


# ---------------------------------------------------------------------------
# 4. HTTP Error Handling
# ---------------------------------------------------------------------------

def _fetcher_with_status(status: int, body: dict, url_pattern: str = "") -> GitHubFetcher:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=status,
            json=body,
            headers={"X-RateLimit-Remaining": "60", "X-RateLimit-Reset": "9999999999"},
        )
    fetcher = make_fetcher()
    fetcher._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer ghp_faketoken123"},
    )
    return fetcher


class TestHTTPErrors:

    def test_404_raises_repo_not_found(self):
        fetcher = _fetcher_with_status(404, {"message": "Not Found"})
        with pytest.raises(RepoNotFoundError):
            fetcher.fetch_python_files("https://github.com/owner/repo")

    def test_401_raises_auth_error(self):
        fetcher = _fetcher_with_status(401, {"message": "Bad credentials"})
        with pytest.raises(AuthenticationError):
            fetcher.fetch_python_files("https://github.com/owner/repo")

    def test_500_raises_github_api_error(self):
        fetcher = _fetcher_with_status(500, {"message": "Internal Server Error"})
        with pytest.raises(GitHubAPIError) as exc_info:
            fetcher.fetch_python_files("https://github.com/owner/repo")
        assert exc_info.value.http_status == 500

    def test_token_not_in_exception_message(self):
        fetcher = _fetcher_with_status(401, {"message": "Bad credentials"})
        with pytest.raises(AuthenticationError) as exc_info:
            fetcher.fetch_python_files("https://github.com/owner/repo")
        assert "ghp_faketoken123" not in str(exc_info.value)
        assert "ghp_faketoken123" not in exc_info.value.message


# ---------------------------------------------------------------------------
# 5. Rate Limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:

    def test_rate_limit_retry_then_success(self):
        """First call returns 429, second returns 200 with tree data."""
        call_count = 0
        tree = tree_response([{"path": "src/app.py", "content": "x=1"}])
        contents = contents_response("src/app.py", "x=1")

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            url = str(request.url)
            if call_count == 1:
                return httpx.Response(
                    429,
                    json={"message": "rate limit"},
                    headers={
                        "Retry-After": "1",
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(time.time()) + 1),
                    },
                )
            if "/git/trees/" in url:
                return httpx.Response(200, json=tree, headers={"X-RateLimit-Remaining": "60"})
            if "/contents/" in url:
                return httpx.Response(200, json=contents, headers={"X-RateLimit-Remaining": "60"})
            return httpx.Response(404, json={})

        fetcher = make_fetcher()
        fetcher._client = httpx.Client(
            transport=httpx.MockTransport(handler),
            headers={"Authorization": "Bearer ghp_faketoken123"},
        )
        with patch("time.sleep"):  # Don't actually sleep in tests
            result = fetcher.fetch_python_files("https://github.com/owner/repo")
        assert len(result.files) == 1

    def test_rate_limit_exhausted_raises(self):
        """All retries return 429 → RateLimitError."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                429,
                json={"message": "rate limit"},
                headers={"Retry-After": "1", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "9999999999"},
            )
        fetcher = make_fetcher()
        fetcher._client = httpx.Client(
            transport=httpx.MockTransport(handler),
            headers={"Authorization": "Bearer ghp_faketoken123"},
        )
        with patch("time.sleep"):
            with pytest.raises(RateLimitError):
                fetcher.fetch_python_files("https://github.com/owner/repo")


# ---------------------------------------------------------------------------
# 6. Content Decoding
# ---------------------------------------------------------------------------

class TestContentDecoding:

    def test_invalid_base64_skipped(self, caplog):
        import logging
        tree = tree_response([{"path": "bad.py", "content": "not-valid-b64!!!"}])
        bad_contents = {
            "path": "bad.py",
            "sha": "abc",
            "size": 10,
            "content": "@@@@NOT_VALID_BASE64@@@@",
            "encoding": "base64",
        }
        routes: dict[str, tuple[int, dict]] = {
            "/git/trees/": (200, tree),
            "/contents/bad.py": (200, bad_contents),
        }
        fetcher = make_fetcher()
        fetcher._client = httpx.Client(
            transport=mock_transport(routes),
            headers={"Authorization": "Bearer ghp_faketoken123"},
        )
        with caplog.at_level(logging.WARNING, logger="github_fetcher"):
            result = fetcher.fetch_python_files("https://github.com/owner/repo")
        assert len(result.files) == 0
        assert any("bad.py" in msg for msg in caplog.messages)

    def test_valid_content_decoded_correctly(self):
        source = "def hello():\n    return 'world'\n"
        tree = tree_response([{"path": "src/hello.py", "content": source}])
        contents_payload = contents_response("src/hello.py", source)
        routes: dict[str, tuple[int, dict]] = {
            "/git/trees/": (200, tree),
            "/contents/src/hello.py": (200, contents_payload),
        }
        fetcher = make_fetcher()
        fetcher._client = httpx.Client(
            transport=mock_transport(routes),
            headers={"Authorization": "Bearer ghp_faketoken123"},
        )
        result = fetcher.fetch_python_files("https://github.com/owner/repo")
        assert len(result.files) == 1
        assert result.files[0].content == source


# ---------------------------------------------------------------------------
# 7. create_review_issue
# ---------------------------------------------------------------------------
#
# No pre-existing tests to model these on -- post_pr_review (the method
# this feature was explicitly asked to mirror) turns out to have zero test
# coverage of its own anywhere in tests/, same as fetch_pr_files. These
# follow this file's general conventions (mock_transport / MockTransport,
# TestXxx class-per-feature) instead.

class TestCreateReviewIssue:

    def _fetcher_with_issue_response(self, status: int, body: dict) -> GitHubFetcher:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code=status, json=body)
        fetcher = make_fetcher()
        fetcher._client = httpx.Client(
            transport=httpx.MockTransport(handler),
            headers={"Authorization": "Bearer ghp_faketoken123"},
        )
        return fetcher

    def _fetcher_capturing_request(self, captured: dict) -> GitHubFetcher:
        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            captured["url"] = str(request.url)
            return httpx.Response(201, json={"number": 42, "html_url": "https://github.com/owner/repo/issues/42"})
        fetcher = make_fetcher()
        fetcher._client = httpx.Client(
            transport=httpx.MockTransport(handler),
            headers={"Authorization": "Bearer ghp_faketoken123"},
        )
        return fetcher

    def test_returns_none_when_no_issues(self):
        fetcher = make_fetcher()
        result = fetcher.create_review_issue("https://github.com/owner/repo", issues=[])
        assert result is None

    def test_returns_none_when_below_default_threshold(self):
        # Default min_severity is HIGH -- MEDIUM/LOW-only shouldn't open an issue.
        fetcher = make_fetcher()
        issues = [
            {"path": "a.py", "line": 1, "severity": "MEDIUM", "title": "t", "description": "d"},
            {"path": "b.py", "line": 2, "severity": "LOW", "title": "t2", "description": "d2"},
        ]
        result = fetcher.create_review_issue("https://github.com/owner/repo", issues=issues)
        assert result is None

    def test_creates_issue_when_high_present(self):
        fetcher = self._fetcher_with_issue_response(
            201, {"number": 42, "html_url": "https://github.com/owner/repo/issues/42"}
        )
        issues = [{
            "path": "a.py", "line": 10, "severity": "HIGH", "title": "SQL Injection",
            "description": "d", "suggested_fix": "use params", "rule_id": "r1",
        }]
        result = fetcher.create_review_issue("https://github.com/owner/repo", issues=issues, summary="1 issue found")
        assert result == {"issue_number": 42, "html_url": "https://github.com/owner/repo/issues/42"}

    def test_creates_issue_when_critical_present_among_lows(self):
        fetcher = self._fetcher_with_issue_response(
            201, {"number": 7, "html_url": "https://github.com/owner/repo/issues/7"}
        )
        issues = [
            {"path": "a.py", "line": 1, "severity": "LOW", "title": "l", "description": "d"},
            {"path": "b.py", "line": 2, "severity": "CRITICAL", "title": "c", "description": "d2"},
        ]
        result = fetcher.create_review_issue("https://github.com/owner/repo", issues=issues)
        assert result["issue_number"] == 7

    def test_custom_min_severity_threshold_allows_medium(self):
        fetcher = self._fetcher_with_issue_response(201, {"number": 1, "html_url": "url"})
        issues = [{"path": "a.py", "line": 1, "severity": "MEDIUM", "title": "t", "description": "d"}]
        result = fetcher.create_review_issue(
            "https://github.com/owner/repo", issues=issues, min_severity="MEDIUM"
        )
        assert result is not None

    def test_posts_to_repo_issues_endpoint(self):
        captured: dict = {}
        fetcher = self._fetcher_capturing_request(captured)
        issues = [{"path": "a.py", "line": 1, "severity": "CRITICAL", "title": "t", "description": "d"}]
        fetcher.create_review_issue("https://github.com/owner/repo", issues=issues)
        assert "/repos/owner/repo/issues" in captured["url"]

    def test_title_includes_total_and_severity_counts(self):
        captured: dict = {}
        fetcher = self._fetcher_capturing_request(captured)
        issues = [
            {"path": "a.py", "line": 1, "severity": "CRITICAL", "title": "t", "description": "d"},
            {"path": "b.py", "line": 2, "severity": "HIGH", "title": "t2", "description": "d2"},
        ]
        fetcher.create_review_issue("https://github.com/owner/repo", issues=issues)
        title = captured["body"]["title"]
        assert "2 issue(s)" in title
        assert "1 CRITICAL" in title
        assert "1 HIGH" in title

    def test_body_groups_findings_by_severity_critical_first(self):
        captured: dict = {}
        fetcher = self._fetcher_capturing_request(captured)
        issues = [
            {"path": "a.py", "line": 1, "severity": "HIGH", "title": "h", "description": "d"},
            {"path": "b.py", "line": 2, "severity": "CRITICAL", "title": "c", "description": "d2"},
        ]
        fetcher.create_review_issue("https://github.com/owner/repo", issues=issues, summary="s")
        body = captured["body"]["body"]
        assert "s" in body
        assert body.index("## CRITICAL") < body.index("## HIGH")

    def test_body_escapes_html_in_model_output(self):
        # Same untrusted-output concern as report_generator.py's _escape():
        # a finding's title/description come from Gemini and must not be
        # able to inject raw HTML/markup into the rendered GitHub issue.
        captured: dict = {}
        fetcher = self._fetcher_capturing_request(captured)
        issues = [{
            "path": "a.py", "line": 1, "severity": "CRITICAL",
            "title": "<script>alert(1)</script>", "description": "d",
        }]
        fetcher.create_review_issue("https://github.com/owner/repo", issues=issues)
        body = captured["body"]["body"]
        assert "&lt;script&gt;" in body
        assert "<script>" not in body

    def test_api_error_raises_runtime_error(self):
        fetcher = self._fetcher_with_issue_response(403, {"message": "Forbidden"})
        issues = [{"path": "a.py", "line": 1, "severity": "CRITICAL", "title": "t", "description": "d"}]
        with pytest.raises(RuntimeError):
            fetcher.create_review_issue("https://github.com/owner/repo", issues=issues)


# ---------------------------------------------------------------------------
# 8. Aggregate size cap (PayloadTooLargeError)
# ---------------------------------------------------------------------------

class TestAggregateSizeCap:
    """
    Distinct from the per-file DEFAULT_MAX_BYTES cap (TestFiltering,
    test_fetch_skips_oversized_file): this covers the total-across-all-files
    cap, which is the one that catches "many files each individually small"
    rather than "one huge file".
    """

    def test_fetch_rejects_when_total_size_exceeds_cap(self):
        # 5 files x 1000 bytes each = 5000 bytes total, well under the
        # per-file DEFAULT_MAX_BYTES cap individually, but over a small
        # max_total_bytes passed here.
        content = "x = 1\n" * 200  # ~1200 bytes
        many_files = [{"path": f"src/mod_{i}.py", "content": content} for i in range(5)]
        tree = tree_response(many_files)
        contents = {f["path"]: content for f in many_files}
        routes = {"/git/trees/": (200, tree)}
        for path, body in contents.items():
            routes[f"/contents/{path}"] = (200, contents_response(path, body))
        fetcher = make_fetcher()
        fetcher._client = httpx.Client(
            transport=mock_transport(routes),
            headers={"Authorization": "Bearer ghp_faketoken123"},
        )
        with pytest.raises(PayloadTooLargeError) as exc_info:
            fetcher.fetch_python_files("https://github.com/owner/repo", max_total_bytes=2000)
        assert "2,000" in exc_info.value.message or "2000" in exc_info.value.message

    def test_fetch_allows_when_total_size_under_cap(self):
        content = "x = 1\n"
        files = [{"path": f"src/mod_{i}.py", "content": content} for i in range(3)]
        tree = tree_response(files)
        contents = {f["path"]: content for f in files}
        routes = {"/git/trees/": (200, tree)}
        for path, body in contents.items():
            routes[f"/contents/{path}"] = (200, contents_response(path, body))
        fetcher = make_fetcher()
        fetcher._client = httpx.Client(
            transport=mock_transport(routes),
            headers={"Authorization": "Bearer ghp_faketoken123"},
        )
        result = fetcher.fetch_python_files("https://github.com/owner/repo", max_total_bytes=2_000_000)
        assert len(result.files) == 3

    def test_default_cap_does_not_reject_normal_sized_review(self):
        # Sanity check: DEFAULT_MAX_TOTAL_BYTES (2MB) shouldn't trip on a
        # perfectly ordinary small review — this test would fail loudly if
        # the default were accidentally set too low.
        content = "x = 1\n" * 100
        files = [{"path": f"src/mod_{i}.py", "content": content} for i in range(10)]
        tree = tree_response(files)
        contents = {f["path"]: content for f in files}
        routes = {"/git/trees/": (200, tree)}
        for path, body in contents.items():
            routes[f"/contents/{path}"] = (200, contents_response(path, body))
        fetcher = make_fetcher()
        fetcher._client = httpx.Client(
            transport=mock_transport(routes),
            headers={"Authorization": "Bearer ghp_faketoken123"},
        )
        result = fetcher.fetch_python_files("https://github.com/owner/repo")  # default cap
        assert len(result.files) == 10


# ---------------------------------------------------------------------------
# 9. Context Manager
# ---------------------------------------------------------------------------

class TestContextManager:

    def test_context_manager_closes_client(self):
        with make_fetcher() as fetcher:
            assert fetcher is not None
        # Should not raise; client is closed
        assert fetcher._client.is_closed
