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
import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
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
    PayloadTooLargeError,
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

# Free-tier Gemini requests-per-day cap, mirrored from view_trace.py so the
# /traces endpoint's RPD summary matches the CLI tool's number exactly for
# the same trace file.
_RPD_CAP = 500

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
    schema_errors: list[str] = []


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


def _today_prefix() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _build_llm_spans_by_run(all_spans: list[dict]) -> dict[str, list[dict]]:
    """
    Group llm_call spans by run_id.

    llm_call spans are tagged with the run_id of whichever "run" span was
    active when they were opened (see tracing.py), regardless of how many
    stage spans sit between them — so grouping by run_id, not parent_id,
    correctly picks up every LLM call made during a run.
    """
    by_run: dict[str, list[dict]] = {}
    for s in all_spans:
        if s.get("span_type") == "llm_call" and s.get("run_id"):
            by_run.setdefault(s["run_id"], []).append(s)
    return by_run


def _build_run_entry(run: dict, llm_spans_by_run: dict[str, list[dict]]) -> dict:
    """
    Build one /traces run entry: the run span's own fields, plus reliability
    stats aggregated from that run's llm_call spans (cache hits, fallback
    usage, token totals). Pure function of (run span, llm-spans-by-run map)
    so it's unit-testable without touching the filesystem or FastAPI.
    """
    fields = run.get("fields", {})
    run_id = run.get("span_id")
    run_llm_spans = llm_spans_by_run.get(run_id, [])

    llm_calls = len(run_llm_spans)
    cache_hits = sum(
        1 for s in run_llm_spans if s.get("fields", {}).get("cache_hit") is True
    )
    fallback_used_count = sum(
        1 for s in run_llm_spans if s.get("fields", {}).get("fallback_used") is True
    )
    total_tokens = sum(
        s.get("fields", {}).get("total_tokens") or 0
        for s in run_llm_spans
        if s.get("fields", {}).get("tokens_available")
    )

    return {
        "run_id":              run_id,
        "start_ts":            run.get("start_ts"),
        "duration_s":          run.get("duration_s"),
        "status":              run.get("status"),
        "repo_url":            fields.get("repo_url"),
        "files_fetched":       fields.get("files_fetched"),
        "semgrep_findings":    fields.get("semgrep_findings"),
        "review_issues":       fields.get("review_issues"),
        "stage_errors":        fields.get("stage_errors", []),
        "llm_calls":           llm_calls,
        "cache_hits":          cache_hits,
        "fallback_used_count": fallback_used_count,
        "total_tokens":        total_tokens,
    }


def _compute_rpd_summary(all_spans: list[dict]) -> dict:
    """
    Mirrors view_trace.py's _print_rpd(): count today's llm_call spans that
    actually reached the Gemini API (cache_hit is not True), against the
    free-tier daily cap. Computed from the FULL span list (not the
    limit-sliced run list) so the number matches `view_trace.py --list` for
    the same trace file regardless of the `limit` query param.
    """
    today = _today_prefix()
    todays_llm_spans = [
        s for s in all_spans
        if s.get("span_type") == "llm_call"
        and (s.get("start_ts") or "").startswith(today)
    ]
    cache_hits_today = sum(
        1 for s in todays_llm_spans
        if s.get("fields", {}).get("cache_hit") is True
    )
    calls_today = len(todays_llm_spans) - cache_hits_today
    pct = (calls_today / _RPD_CAP * 100) if _RPD_CAP else 0.0

    return {
        "calls_today":      calls_today,
        "cache_hits_today": cache_hits_today,
        "cap":              _RPD_CAP,
        "pct":              round(pct, 1),
    }


@app.get("/traces", tags=["ops"])
async def list_traces(
    limit: int = Query(default=20, ge=1, le=100, description="Max runs to return"),
) -> dict:
    """
    Return the last N pipeline runs from traces/trace.jsonl, each annotated
    with its LLM-call reliability stats, plus a top-level RPD summary.

    Each run entry includes: run_id, start_ts, duration_s, status, repo_url,
    files_fetched, semgrep_findings, review_issues, stage_errors, and —
    aggregated from that run's llm_call spans — llm_calls, cache_hits,
    fallback_used_count, and total_tokens.

    The top-level "rpd" block mirrors view_trace.py's RPD counter: today's
    real (non-cached) Gemini call count against the free-tier daily cap,
    computed across the whole trace file regardless of `limit`.

    Returns an empty list (and a zeroed rpd block) if no trace file exists yet.
    """
    trace_file = Path(os.environ.get("TRACE_FILE", "traces/trace.jsonl"))
    empty_rpd = {"calls_today": 0, "cache_hits_today": 0, "cap": _RPD_CAP, "pct": 0.0}
    if not trace_file.exists():
        return {"runs": [], "total": 0, "rpd": empty_rpd}

    spans: list[dict] = []
    try:
        with open(trace_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        spans.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError as exc:
        logger.warning("Could not read trace file: %s", exc)
        return {"runs": [], "total": 0, "rpd": empty_rpd}

    rpd_summary = _compute_rpd_summary(spans)

    run_spans = [s for s in spans if s.get("span_type") == "run"]
    total = len(run_spans)
    run_spans = run_spans[-limit:]

    llm_spans_by_run = _build_llm_spans_by_run(spans)
    runs = [_build_run_entry(run, llm_spans_by_run) for run in run_spans]

    return {"runs": runs, "total": total, "rpd": rpd_summary}


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
    except PayloadTooLargeError as exc:
        raise HTTPException(status_code=413, detail=exc.message)
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
            schema_errors=result.review_report.schema_errors,
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
