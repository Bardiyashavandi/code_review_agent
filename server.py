"""
server.py
---------
FastAPI HTTP wrapper around CodeReviewAgent.

The agent is instantiated once at startup from environment variables;
callers never pass credentials.  The single route POST /analyze runs the
existing review_repo() pipeline in a thread-pool executor (it is
synchronous/blocking) and maps its PipelineResult to a JSON response.

Run locally:
    uvicorn server:app --reload           # dev, auto-reload on save
    uvicorn server:app --host 0.0.0.0 --port 8080   # prod-like

Open API docs:  http://127.0.0.1:8000/docs

Example curl:
    curl -s -X POST http://127.0.0.1:8000/analyze \
         -H "Content-Type: application/json" \
         -d '{"repo_url": "https://github.com/octocat/Hello-World"}' | python3 -m json.tool
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Make sibling modules importable when server.py is the entry point
# (same trick as agent.py — ensures the project root is always on sys.path
# regardless of how uvicorn resolves the module).
# ---------------------------------------------------------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from agent import AgentError, CodeReviewAgent
from github_fetcher import (
    AuthenticationError,
    GitHubAPIError,
    GitHubFetcherError,
    RateLimitError,
    RepoNotFoundError,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Settings (from env — no hardcoded secrets or tuning values)
# ---------------------------------------------------------------------------

load_dotenv(override=True)

_GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
_GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
_AGENT_TIMEOUT_S = float(os.environ.get("AGENT_TIMEOUT_S", "180"))

# ---------------------------------------------------------------------------
# Pydantic models — request
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    repo_url: str = Field(
        ...,
        description="GitHub repository URL, e.g. https://github.com/owner/repo",
        examples=["https://github.com/octocat/Hello-World"],
    )
    branch: str = Field(default="main", description="Branch to review")
    max_files: int = Field(
        default=100,
        ge=1,
        le=500,
        description="Maximum Python files to fetch and review (1–500)",
    )

    @field_validator("repo_url")
    @classmethod
    def must_be_github_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or parsed.netloc != "github.com":
            raise ValueError("repo_url must be a github.com URL (https://github.com/owner/repo)")
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 2 or not all(parts[:2]):
            raise ValueError("repo_url must include owner and repo, e.g. https://github.com/owner/repo")
        return v


# ---------------------------------------------------------------------------
# Pydantic models — response
# ---------------------------------------------------------------------------

class IssueOut(BaseModel):
    path: str
    line: int
    severity: str
    title: str
    description: str
    suggested_fix: str
    rule_id: str | None = None


class FindingOut(BaseModel):
    path: str
    line_start: int
    line_end: int
    rule_id: str
    severity: str
    message: str
    snippet: str


class ReviewOut(BaseModel):
    summary: str
    model: str
    files_reviewed: int
    duration_s: float
    issues: list[IssueOut]


class ScanOut(BaseModel):
    scanned: int
    skipped: list[str]
    duration_s: float
    findings: list[FindingOut]


class StageErrorOut(BaseModel):
    stage: str
    message: str


class AnalyzeResponse(BaseModel):
    repo_url: str
    duration_s: float
    files_fetched: int
    truncated: bool
    review: ReviewOut
    scan: ScanOut
    stage_errors: list[StageErrorOut]


# ---------------------------------------------------------------------------
# App lifecycle — instantiate agent once at startup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    if not _GITHUB_TOKEN:
        raise RuntimeError("GITHUB_TOKEN is not set — check your .env or environment")
    if not _GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY is not set — check your .env or environment")
    try:
        app.state.agent = CodeReviewAgent(
            github_token=_GITHUB_TOKEN,
            gemini_api_key=_GEMINI_API_KEY,
        )
    except (AgentError, ValueError) as exc:
        raise RuntimeError(f"Failed to initialise CodeReviewAgent: {exc}") from exc
    logger.info("CodeReviewAgent ready")
    yield
    # Nothing to clean up


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI Code Review Agent",
    description=(
        "Wraps the AI Code Review Agent pipeline (GitHub fetch → Semgrep scan → "
        "Gemini review) behind a single HTTP endpoint."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["ops"])
async def health() -> dict[str, str]:
    """Quick liveness check — returns 200 if the server is up."""
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse, tags=["review"])
async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    """
    Run the full fetch → scan → review pipeline for a GitHub repository.

    Scan and review failures are non-fatal: the response is still returned
    with partial results and the failure surfaced in `stage_errors`.
    A fetch failure (repo not found, bad token, rate-limit) returns an
    appropriate 4xx/5xx HTTP error instead.

    The call runs in a thread-pool executor (the pipeline is synchronous).
    Timeout is controlled by the `AGENT_TIMEOUT_S` environment variable
    (default 180 s).
    """
    agent: CodeReviewAgent = app.state.agent
    loop = asyncio.get_event_loop()

    def _run():
        return agent.review_repo(req.repo_url, branch=req.branch, max_files=req.max_files)

    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _run),
            timeout=_AGENT_TIMEOUT_S,
        )

    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"Review timed out after {_AGENT_TIMEOUT_S:.0f}s. "
                   "Try a smaller max_files value or increase AGENT_TIMEOUT_S.",
        )
    except RepoNotFoundError as exc:
        raise HTTPException(status_code=404, detail=exc.message)
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=exc.message)
    except RateLimitError as exc:
        raise HTTPException(status_code=429, detail=exc.message)
    except GitHubAPIError as exc:
        raise HTTPException(status_code=502, detail=f"GitHub API error: {exc.message}")
    except GitHubFetcherError as exc:
        # Catch-all for any other fetcher subclass
        raise HTTPException(status_code=502, detail=f"GitHub fetch error: {exc.message}")
    except (AgentError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error during review of %s", req.repo_url)
        raise HTTPException(status_code=500, detail=f"Internal error: {exc}")

    return AnalyzeResponse(
        repo_url=result.repo_url,
        duration_s=round(result.duration_s, 3),
        files_fetched=len(result.fetch_result.files),
        truncated=result.fetch_result.truncated,
        review=ReviewOut(
            summary=result.review_report.summary,
            model=result.review_report.model,
            files_reviewed=result.review_report.files_reviewed,
            duration_s=round(result.review_report.duration_s, 3),
            issues=[
                IssueOut(
                    path=i.path,
                    line=i.line,
                    severity=i.severity,
                    title=i.title,
                    description=i.description,
                    suggested_fix=i.suggested_fix,
                    rule_id=i.rule_id,
                )
                for i in result.review_report.issues
            ],
        ),
        scan=ScanOut(
            scanned=result.scan_report.scanned,
            skipped=result.scan_report.skipped,
            duration_s=round(result.scan_report.duration_s, 3),
            findings=[
                FindingOut(
                    path=f.path,
                    line_start=f.line_start,
                    line_end=f.line_end,
                    rule_id=f.rule_id,
                    severity=f.severity,
                    message=f.message,
                    snippet=f.snippet,
                )
                for f in result.scan_report.findings
            ],
        ),
        stage_errors=[
            StageErrorOut(stage=e.stage, message=e.message)
            for e in result.stage_errors
        ],
    )
