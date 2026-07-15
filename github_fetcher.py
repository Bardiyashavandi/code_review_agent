"""
github_fetcher.py
-----------------
Fetches Python source files from a GitHub repository using the GitHub REST API v3.

Usage:
    import os
    from github_fetcher import GitHubFetcher

    fetcher = GitHubFetcher(token=os.environ["GITHUB_TOKEN"])
    files = fetcher.fetch_python_files("https://github.com/owner/repo")
    for f in files:
        print(f.path, len(f.content))
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class GitHubFetcherError(Exception):
    """Base error for all github_fetcher failures."""
    def __init__(self, message: str, http_status: int | None = None):
        super().__init__(message)
        self.message = message
        self.http_status = http_status


class RepoNotFoundError(GitHubFetcherError):
    """Raised when the repository does not exist or is inaccessible."""


class AuthenticationError(GitHubFetcherError):
    """Raised when the GitHub token is invalid or expired."""


class RateLimitError(GitHubFetcherError):
    """Raised when retries are exhausted due to rate limiting."""


class GitHubAPIError(GitHubFetcherError):
    """Raised for unexpected 4xx/5xx responses."""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FileResult:
    path: str
    content: str
    sha: str
    size: int
    url: str


@dataclass
class FetchResult:
    files: list[FileResult] = field(default_factory=list)
    truncated: bool = False


@dataclass
class TreeNode:
    path: str
    sha: str
    size: int
    url: str


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXCLUDE_DIRS = {
    "test", "tests", ".github", "venv", ".venv",
    "node_modules", "migrations", "__pycache__",
}

DEFAULT_BASE_URL = "https://api.github.com"
DEFAULT_BRANCH = "main"
DEFAULT_MAX_FILES = 100
DEFAULT_MAX_BYTES = 500_000
DEFAULT_TIMEOUT = 10
MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# Fetcher
# ---------------------------------------------------------------------------

class GitHubFetcher:
    """
    Fetches Python files from a GitHub repository.

    Parameters
    ----------
    token : str
        GitHub Personal Access Token. Read from the caller's environment —
        never hardcode this value.
    base_url : str
        GitHub API base URL. Override in tests to point at a mock server.
    timeout : int
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        token: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        if not token or not token.strip():
            raise ValueError("GITHUB_TOKEN must not be empty")
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._client = httpx.Client(
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=self._timeout,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_repo_url(self, url: str) -> tuple[str, str]:
        """
        Parse a GitHub repo URL into (owner, repo).

        Accepts:
            https://github.com/owner/repo
            https://github.com/owner/repo.git   (strips .git)

        Rejects:
            Any non-github.com host
            URLs with subpaths beyond /owner/repo
            URLs with query strings or fragments
        """
        parsed = urlparse(url.strip())

        if parsed.scheme not in ("https", "http"):
            raise ValueError(f"Invalid URL scheme: {parsed.scheme!r}. Must be https://github.com/owner/repo")

        if parsed.netloc not in ("github.com", "www.github.com"):
            raise ValueError(f"Invalid host: {parsed.netloc!r}. Only github.com is supported.")

        if parsed.query or parsed.fragment:
            raise ValueError("URL must not contain query strings or fragments.")

        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(parts) != 2:
            raise ValueError(
                f"URL must be exactly https://github.com/owner/repo — got path {parsed.path!r}"
            )

        owner, repo = parts
        repo = repo.removesuffix(".git")

        if not owner or not repo:
            raise ValueError("owner and repo must be non-empty strings.")

        return owner, repo

    def parse_pr_url(self, url: str) -> tuple[str, str, int]:
        """
        Parse a GitHub PR URL into (owner, repo, pr_number).

        Accepts:  https://github.com/owner/repo/pull/123
        Rejects:  anything that isn't that exact shape.
        """
        parsed = urlparse(url.strip())
        if parsed.netloc not in ("github.com", "www.github.com"):
            raise ValueError(f"Invalid host: {parsed.netloc!r}. Only github.com is supported.")
        parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(parts) != 4 or parts[2] != "pull":
            raise ValueError(
                "PR URL must be https://github.com/owner/repo/pull/123 "
                f"— got path {parsed.path!r}"
            )
        owner, repo, _, pr_number_str = parts
        try:
            pr_number = int(pr_number_str)
        except ValueError:
            raise ValueError(f"PR number must be an integer, got: {pr_number_str!r}")
        return owner, repo, pr_number

    def fetch_pr_files(
        self,
        pr_url: str,
        max_files: int = DEFAULT_MAX_FILES,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> tuple["FetchResult", int]:
        """
        Fetch Python files changed in a GitHub Pull Request.

        Only files that were *added* or *modified* (not deleted) are fetched;
        test files and excluded directories are skipped as usual.

        Returns
        -------
        (FetchResult, pr_number)
            FetchResult contains the changed Python files with full content.
            pr_number is the integer PR number parsed from the URL.
        """
        owner, repo, pr_number = self.parse_pr_url(pr_url)

        # GitHub returns up to 300 files per PR; pagination not needed here.
        files_url = f"{self._base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
        pr_files_data = self._get(files_url)

        files: list[FileResult] = []
        truncated = False

        for file_data in pr_files_data:
            filename = file_data.get("filename", "")
            status = file_data.get("status", "")

            # Python only, and skip deletions (nothing left to review)
            if not filename.endswith(".py") or status == "removed":
                continue

            # Respect same exclusion list as fetch_python_files
            top_dir = filename.split("/")[0].lower()
            if top_dir in EXCLUDE_DIRS:
                logger.debug("Skipping excluded directory in PR: %s", filename)
                continue

            if len(files) >= max_files:
                truncated = True
                logger.warning(
                    "PR has more than %d changed Python files; "
                    "only the first %d will be reviewed.",
                    max_files, max_files,
                )
                break

            content_url = f"{self._base_url}/repos/{owner}/{repo}/contents/{filename}"
            try:
                content_data = self._get(content_url)
            except GitHubFetcherError as exc:
                logger.warning("Could not fetch PR file %s: %s", filename, exc.message)
                continue

            raw_content = content_data.get("content", "")
            try:
                decoded = base64.b64decode(raw_content).decode("utf-8")
            except Exception:
                logger.warning("Could not decode content of %s — skipping.", filename)
                continue

            if len(decoded.encode("utf-8")) > max_bytes:
                logger.warning("Skipping %s — exceeds byte limit of %d.", filename, max_bytes)
                continue

            files.append(FileResult(
                path=filename,
                content=decoded,
                sha=content_data.get("sha", ""),
                size=len(decoded),
                url=content_url,
            ))

        return FetchResult(files=files, truncated=truncated), pr_number

    def get_repo_metadata(self, url: str) -> dict:
        """
        Fetch basic repo metadata (language, size, stars, last push, default
        branch) via GET /repos/{owner}/{repo} — a single lightweight call,
        useful for an agent to inspect a repo before deciding how deep to go.
        """
        owner, repo = self.parse_repo_url(url)
        data = self._get(f"{self._base_url}/repos/{owner}/{repo}")
        return {
            "owner": owner,
            "repo": repo,
            "description": data.get("description") or "",
            "language": data.get("language") or "",
            "default_branch": data.get("default_branch", DEFAULT_BRANCH),
            "size_kb": data.get("size", 0),
            "stargazers_count": data.get("stargazers_count", 0),
            "open_issues_count": data.get("open_issues_count", 0),
            "pushed_at": data.get("pushed_at") or "",
            "archived": bool(data.get("archived", False)),
        }

    def post_pr_review(
        self,
        pr_url: str,
        issues: list,
        summary: str = "",
        event: str = "COMMENT",
    ) -> dict:
        """Post a code review to a GitHub PR as inline comments.

        Tries to post each issue as an inline comment on the specific line.
        If GitHub rejects (e.g. the line is not in the diff), falls back to
        a single general PR comment containing all findings.

        event: "COMMENT" | "REQUEST_CHANGES" | "APPROVE"
        Returns {review_id, html_url, state, comments_posted, fallback?}.
        """
        import re as _re
        m = _re.match(
            r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)",
            pr_url.strip(),
        )
        if not m:
            raise ValueError(f"Invalid PR URL: {pr_url!r}")
        owner, repo, pr_number = m.group(1), m.group(2), int(m.group(3))

        # Fetch head commit SHA
        pr_data = self._get(f"{self._base_url}/repos/{owner}/{repo}/pulls/{pr_number}")
        head_sha = pr_data["head"]["sha"]

        # Build inline comment objects
        comments = []
        for issue in issues:
            path = (issue.get("path") or "").strip()
            line = int(issue.get("line") or 0)
            if not path or line < 1:
                continue
            body_parts = [
                f"**{issue.get('severity', 'MEDIUM')}**: {issue.get('title', '')}",
                "",
                issue.get("description", ""),
            ]
            if issue.get("suggested_fix"):
                body_parts += ["", f"*Suggested fix:* {issue['suggested_fix']}"]
            if issue.get("rule_id"):
                body_parts += [f"*Rule:* `{issue['rule_id']}`"]
            comments.append({
                "path": path,
                "line": line,
                "side": "RIGHT",
                "body": "\n".join(body_parts),
            })

        review_body = summary or "AI Code Review Agent — automated findings below."
        payload: dict = {
            "commit_id": head_sha,
            "body": review_body,
            "event": event,
            "comments": comments,
        }

        resp = self._client.post(
            f"{self._base_url}/repos/{owner}/{repo}/pulls/{pr_number}/reviews",
            json=payload,
        )

        if resp.status_code in (200, 201):
            data = resp.json()
            return {
                "review_id": data.get("id"),
                "html_url": data.get("html_url"),
                "state": data.get("state"),
                "comments_posted": len(comments),
                "fallback": False,
            }

        # 422 = one or more lines not in the diff; fall back to a single comment
        if resp.status_code == 422 or comments:
            lines = [review_body, "", "---", ""]
            for iss in issues:
                lines.append(
                    f"**{iss.get('severity','MEDIUM')}** "
                    f"`{iss.get('path','')}:{iss.get('line',0)}` — "
                    f"{iss.get('title','')}"
                )
                lines.append("")
                lines.append(iss.get("description", ""))
                if iss.get("suggested_fix"):
                    lines.append(f"*Suggested fix:* {iss['suggested_fix']}")
                lines.append("")
            fallback_body = "\n".join(lines)
            fb_resp = self._client.post(
                f"{self._base_url}/repos/{owner}/{repo}/issues/{pr_number}/comments",
                json={"body": fallback_body},
            )
            if fb_resp.status_code in (200, 201):
                data = fb_resp.json()
                return {
                    "review_id": data.get("id"),
                    "html_url": data.get("html_url"),
                    "state": "COMMENTED",
                    "comments_posted": 0,
                    "fallback": True,
                    "note": "Inline comments skipped (lines not in diff); posted as general comment.",
                }

        raise RuntimeError(
            f"GitHub API error {resp.status_code}: {resp.text[:300]}"
        )

    def fetch_python_files(
        self,
        url: str,
        branch: str = DEFAULT_BRANCH,
        max_files: int = DEFAULT_MAX_FILES,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> FetchResult:
        """
        Main entry point. Returns a FetchResult containing matched FileResult objects.

        Parameters
        ----------
        url       : GitHub repository URL.
        branch    : Branch or tag ref. Defaults to "main".
        max_files : Maximum number of .py files to return.
        max_bytes : Per-file byte size cap; larger files are skipped.
        """
        owner, repo = self.parse_repo_url(url)
        tree_nodes = self._fetch_tree(owner, repo, branch)

        python_nodes = self._filter_nodes(tree_nodes, max_bytes)

        truncated = len(python_nodes) > max_files
        python_nodes = python_nodes[:max_files]

        if truncated:
            logger.warning(
                "Repository has more than %d matching Python files; "
                "only the first %d will be reviewed.",
                max_files, max_files,
            )

        files: list[FileResult] = []
        for node in python_nodes:
            result = self._fetch_file(owner, repo, node)
            if result is not None:
                files.append(result)

        return FetchResult(files=files, truncated=truncated)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_tree(self, owner: str, repo: str, branch: str) -> list[TreeNode]:
        """Fetch the full recursive file tree for the given branch."""
        try:
            url = f"{self._base_url}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
            data = self._get(url)
        except RepoNotFoundError as exc:
            # If the requested branch was "main", let's try to query the repo details
            # to check if the default branch is actually "master" or something else.
            if branch == "main":
                try:
                    repo_url = f"{self._base_url}/repos/{owner}/{repo}"
                    repo_data = self._get(repo_url)
                    default_branch = repo_data.get("default_branch")
                    if default_branch and default_branch != "main":
                        logger.info("Branch 'main' not found. Falling back to default branch '%s'", default_branch)
                        url = f"{self._base_url}/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
                        data = self._get(url)
                    else:
                        raise exc
                except Exception:
                    raise exc
            else:
                raise exc

        nodes = []
        for item in data.get("tree", []):
            if item.get("type") != "blob":
                continue
            nodes.append(TreeNode(
                path=item["path"],
                sha=item["sha"],
                size=item.get("size", 0),
                url=item.get("url", ""),
            ))
        return nodes

    def _filter_nodes(self, nodes: list[TreeNode], max_bytes: int) -> list[TreeNode]:
        """Keep only .py files outside excluded directories and within size limit."""
        filtered = []
        for node in nodes:
            if not node.path.endswith(".py"):
                continue

            top_dir = node.path.split("/")[0].lower()
            if top_dir in EXCLUDE_DIRS:
                logger.debug("Skipping excluded directory: %s", node.path)
                continue

            if node.size > max_bytes:
                logger.warning(
                    "Skipping %s — size %d bytes exceeds limit of %d bytes.",
                    node.path, node.size, max_bytes,
                )
                continue

            filtered.append(node)
        return filtered

    def _fetch_file(self, owner: str, repo: str, node: TreeNode) -> FileResult | None:
        """Fetch and decode a single file's content."""
        url = f"{self._base_url}/repos/{owner}/{repo}/contents/{node.path}"
        try:
            data = self._get(url)
        except GitHubFetcherError as exc:
            logger.warning("Could not fetch %s: %s", node.path, exc.message)
            return None

        raw_content = data.get("content", "")
        try:
            decoded = base64.b64decode(raw_content).decode("utf-8")
        except Exception:
            logger.warning("Could not decode content of %s — skipping.", node.path)
            return None

        return FileResult(
            path=node.path,
            content=decoded,
            sha=data.get("sha", node.sha),
            size=node.size,
            url=url,
        )

    def _get(self, url: str) -> dict:
        """
        Perform a GET request with retry logic for rate limiting.
        Raises appropriate GitHubFetcherError subclasses on failure.
        Token is never included in exception messages.
        """
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self._client.get(url)
            except httpx.TimeoutException:
                raise GitHubAPIError(f"Request timed out: {url}")
            except httpx.RequestError as exc:
                raise GitHubAPIError(f"Network error: {exc}")

            self._handle_rate_limit_headers(response)

            if response.status_code == 200:
                return response.json()

            if response.status_code == 404:
                raise RepoNotFoundError(
                    f"Repository not found or inaccessible: {url}",
                    http_status=404,
                )

            if response.status_code == 401:
                raise AuthenticationError(
                    "Invalid or expired GitHub token. Check your GITHUB_TOKEN.",
                    http_status=401,
                )

            retry_after = self._get_retry_after(response)
            if response.status_code in (403, 429) and retry_after is not None:
                if attempt < MAX_RETRIES:
                    sleep_time = retry_after * (2 ** attempt)
                    logger.warning(
                        "Rate limited (HTTP %d). Sleeping %ss before retry %d/%d.",
                        response.status_code, sleep_time, attempt + 1, MAX_RETRIES,
                    )
                    time.sleep(sleep_time)
                    continue
                else:
                    raise RateLimitError(
                        f"Rate limit retries exhausted after {MAX_RETRIES} attempts.",
                        http_status=response.status_code,
                    )

            raise GitHubAPIError(
                f"Unexpected GitHub API response {response.status_code} for {url}",
                http_status=response.status_code,
            )

        raise GitHubAPIError("Exceeded maximum retries.")  # should be unreachable

    def _handle_rate_limit_headers(self, response: httpx.Response) -> None:
        """Sleep proactively if rate limit is nearly exhausted."""
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset = response.headers.get("X-RateLimit-Reset")
        if remaining is not None and reset is not None:
            try:
                if int(remaining) <= 5:
                    sleep_until = int(reset) + 1
                    sleep_for = max(0, sleep_until - time.time())
                    if sleep_for > 0:
                        logger.warning(
                            "Rate limit nearly exhausted (%s remaining). "
                            "Sleeping %.1fs until reset.",
                            remaining, sleep_for,
                        )
                        time.sleep(sleep_for)
            except ValueError:
                pass

    @staticmethod
    def _get_retry_after(response: httpx.Response) -> int | None:
        """Extract Retry-After header value in seconds, if present."""
        value = response.headers.get("Retry-After")
        if value:
            try:
                return int(value)
            except ValueError:
                return 1
        return 1 if response.status_code in (403, 429) else None

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> GitHubFetcher:
        return self

    def __exit__(self, *_) -> None:
        self.close()
