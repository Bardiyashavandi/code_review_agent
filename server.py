"""
server.py
---------
FastAPI HTTP wrapper around CodeReviewAgent.

The agent is instantiated once at startup from environment variables;
callers never pass credentials. Routes:

  POST /analyze     Runs the full review_repo() pipeline (fetch -> scan ->
                     review) in a thread-pool executor (synchronous/blocking)
                     and maps its PipelineResult to a JSON response.
  POST /remediate    Opt-in only — takes findings from a prior /analyze
                     response and returns concrete before/after code
                     patches, via the existing generate_remediation_patches()
                     tool logic. Re-fetches files from GitHub itself; never
                     triggered automatically by /analyze.
  GET  /traces      Reliability/cost stats (cache hit rate, RPD, etc.)
                     aggregated from traces/trace.jsonl.
  GET  /health      Liveness check.

Run locally:
    uvicorn server:app --reload           # dev, auto-reload on save
    uvicorn server:app --host 0.0.0.0 --port 8080   # prod-like

Open API docs:  http://127.0.0.1:8000/docs

Example curl:
    curl -s -X POST http://127.0.0.1:8000/analyze \
         -H "Content-Type: application/json" \
         -d '{"repo_url": "https://github.com/octocat/Hello-World"}' | python3 -m json.tool

    curl -s -X POST http://127.0.0.1:8000/remediate \
         -H "Content-Type: application/json" \
         -d '{"repo_url": "https://github.com/octocat/Hello-World",
              "findings": [{"path": "README", "line": 1, "severity": "HIGH",
                            "title": "example", "description": "...", "suggested_fix": "..."}]}' \
         | python3 -m json.tool
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
from pydantic import BaseModel, Field, ValidationError, field_validator

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

def _validate_github_repo_url(v: str) -> str:
    """Shared repo_url validation, used by both AnalyzeRequest and
    RemediateRequest so the two endpoints reject malformed URLs identically."""
    parsed = urlparse(v)
    if parsed.scheme not in ("http", "https") or parsed.netloc != "github.com":
        raise ValueError("repo_url must be a github.com URL (https://github.com/owner/repo)")
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2 or not all(parts[:2]):
        raise ValueError("repo_url must include owner and repo, e.g. https://github.com/owner/repo")
    return v


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
        return _validate_github_repo_url(v)


class FindingIn(BaseModel):
    """A finding to remediate. Same shape as IssueOut below, so a caller can
    pass back the exact `review.issues` array from a prior /analyze response
    (in full, or a hand-picked subset) without reshaping anything."""
    path: str
    line: int = 0
    severity: str = "MEDIUM"
    title: str = "Finding"
    description: str = ""
    suggested_fix: str = ""
    rule_id: str | None = None


class RemediateRequest(BaseModel):
    repo_url: str = Field(
        ...,
        description="Same GitHub repository URL the findings came from",
        examples=["https://github.com/octocat/Hello-World"],
    )
    branch: str = Field(default="main", description="Branch the findings were reviewed against")
    max_files: int = Field(
        default=100,
        ge=1,
        le=500,
        description=(
            "Cap on files re-fetched from GitHub — must be large enough that "
            "every path referenced in `findings` is actually re-fetched"
        ),
    )
    findings: list[FindingIn] = Field(
        ...,
        min_length=1,
        description="Findings to remediate — typically review.issues (or a subset) from a prior /analyze call",
    )

    @field_validator("repo_url")
    @classmethod
    def must_be_github_url(cls, v: str) -> str:
        return _validate_github_repo_url(v)


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


class PatchOut(BaseModel):
    finding_index: int | None = None
    path: str = ""
    line: int | None = None
    title: str = ""
    before: str = ""
    after: str = ""
    explanation: str = ""
    dependencies: list[str] = []
    breaking_change: bool = False
    breaking_change_note: str | None = None


class RemediateResponse(BaseModel):
    patches: list[PatchOut] = []
    summary: str = ""
    parse_error: bool = False
    missing_paths: list[str] = []
    schema_errors: list[str] = []


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

    "gemini_embed" spans (the semantic cache's own embedding calls — see
    GeminiReviewer._embed) are split out from the generation-call stats
    below: they never themselves "have issues" or count toward the
    generation model's RPD cap, and lumping them into llm_calls/total_tokens
    would conflate two different kinds of API cost. They're reported
    separately as embed_calls/embed_calls_failed.
    """
    fields = run.get("fields", {})
    run_id = run.get("span_id")
    run_llm_spans = llm_spans_by_run.get(run_id, [])

    embed_spans = [s for s in run_llm_spans if s.get("name") == "gemini_embed"]
    generation_spans = [s for s in run_llm_spans if s.get("name") != "gemini_embed"]

    llm_calls = len(generation_spans)
    # cache_hits stays a straight "cache_hit is True" count for backward
    # compatibility with trace data written before cache_hit_type existed.
    # exact_cache_hits/semantic_cache_hits are the new breakdown, additive on
    # top — both are 0 for old spans that predate this field, which is the
    # correct/honest answer ("we don't know which kind, if any").
    cache_hits = sum(
        1 for s in generation_spans if s.get("fields", {}).get("cache_hit") is True
    )
    exact_cache_hits = sum(
        1 for s in generation_spans if s.get("fields", {}).get("cache_hit_type") == "exact"
    )
    semantic_cache_hits = sum(
        1 for s in generation_spans if s.get("fields", {}).get("cache_hit_type") == "semantic"
    )
    fallback_used_count = sum(
        1 for s in generation_spans if s.get("fields", {}).get("fallback_used") is True
    )
    total_tokens = sum(
        s.get("fields", {}).get("total_tokens") or 0
        for s in generation_spans
        if s.get("fields", {}).get("tokens_available")
    )
    embed_calls = len(embed_spans)
    embed_calls_failed = sum(
        1 for s in embed_spans if s.get("fields", {}).get("embed_failed") is True
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
        "exact_cache_hits":    exact_cache_hits,
        "semantic_cache_hits": semantic_cache_hits,
        "embed_calls":         embed_calls,
        "embed_calls_failed":  embed_calls_failed,
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

    "gemini_embed" spans are excluded from this count: embedding calls sit
    in a separate free-tier quota bucket from generation calls, so counting
    them against the generation model's daily cap would overstate real
    usage. They're reported separately via embed_calls_today.
    """
    today = _today_prefix()
    todays_llm_spans = [
        s for s in all_spans
        if s.get("span_type") == "llm_call"
        and s.get("name") != "gemini_embed"
        and (s.get("start_ts") or "").startswith(today)
    ]
    cache_hits_today = sum(
        1 for s in todays_llm_spans
        if s.get("fields", {}).get("cache_hit") is True
    )
    calls_today = len(todays_llm_spans) - cache_hits_today
    pct = (calls_today / _RPD_CAP * 100) if _RPD_CAP else 0.0

    todays_embed_spans = [
        s for s in all_spans
        if s.get("span_type") == "llm_call"
        and s.get("name") == "gemini_embed"
        and (s.get("start_ts") or "").startswith(today)
    ]
    embed_calls_today = len(todays_embed_spans)

    return {
        "calls_today":       calls_today,
        "cache_hits_today":  cache_hits_today,
        "cap":               _RPD_CAP,
        "pct":               round(pct, 1),
        "embed_calls_today": embed_calls_today,
    }


def _compute_cache_savings_summary(all_spans: list[dict]) -> dict:
    """
    Project-wide (all-time, not just today) cache effectiveness summary
    across the whole trace file — how much the exact-match cache and the
    semantic cache are each contributing, and the net cost of running the
    semantic layer at all.

    estimated_tokens_saved is genuinely an estimate, not a measurement: a
    cache hit means no generate_content call was made, so there's no
    usage_metadata for that specific call. Instead it's (average tokens per
    *real* generation call this project has actually made) x (hit count) --
    labeled "estimated" throughout for that reason.

    net_calls_saved subtracts embed_calls from total hits, since every real
    semantic-cache-populating call also pays for one embedding call — this
    is the honest "did the semantic layer pay for itself" number, not just
    a raw hit count.
    """
    generation_spans = [
        s for s in all_spans
        if s.get("span_type") == "llm_call" and s.get("name") != "gemini_embed"
    ]
    embed_spans = [
        s for s in all_spans
        if s.get("span_type") == "llm_call" and s.get("name") == "gemini_embed"
    ]

    exact_hits = sum(
        1 for s in generation_spans if s.get("fields", {}).get("cache_hit_type") == "exact"
    )
    semantic_hits = sum(
        1 for s in generation_spans if s.get("fields", {}).get("cache_hit_type") == "semantic"
    )
    total_hits = exact_hits + semantic_hits
    real_calls = [
        s for s in generation_spans if s.get("fields", {}).get("cache_hit") is not True
    ]
    misses = len(real_calls)
    total_calls_seen = total_hits + misses

    hit_rate_pct = (total_hits / total_calls_seen * 100) if total_calls_seen else 0.0

    real_calls_with_tokens = [
        s for s in real_calls if s.get("fields", {}).get("tokens_available")
    ]
    if real_calls_with_tokens:
        avg_tokens_per_real_call = sum(
            s["fields"].get("total_tokens") or 0 for s in real_calls_with_tokens
        ) / len(real_calls_with_tokens)
    else:
        avg_tokens_per_real_call = 0.0
    estimated_tokens_saved = round(avg_tokens_per_real_call * total_hits)

    embed_calls = len(embed_spans)

    return {
        "exact_cache_hits":        exact_hits,
        "semantic_cache_hits":     semantic_hits,
        "total_cache_hits":        total_hits,
        "real_calls":              misses,
        "hit_rate_pct":            round(hit_rate_pct, 1),
        "estimated_tokens_saved":  estimated_tokens_saved,
        "embed_calls":             embed_calls,
        "net_calls_saved":         total_hits - embed_calls,
    }


@app.get("/traces", tags=["ops"])
async def list_traces(
    limit: int = Query(default=20, ge=1, le=100, description="Max runs to return"),
) -> dict:
    """
    Return the last N pipeline runs from traces/trace.jsonl, each annotated
    with its LLM-call reliability stats, plus a top-level RPD summary and a
    top-level cache-savings summary.

    Each run entry includes: run_id, start_ts, duration_s, status, repo_url,
    files_fetched, semgrep_findings, review_issues, stage_errors, and —
    aggregated from that run's llm_call spans — llm_calls, cache_hits,
    exact_cache_hits, semantic_cache_hits, embed_calls, embed_calls_failed,
    fallback_used_count, and total_tokens.

    The top-level "rpd" block mirrors view_trace.py's RPD counter: today's
    real (non-cached, non-embed) Gemini generation-call count against the
    free-tier daily cap, computed across the whole trace file regardless of
    `limit`, plus today's embed_calls_today (a separate quota bucket).

    The top-level "cache_savings" block is project-wide (not just today):
    exact vs. semantic hit counts, overall hit rate, an *estimated* tokens-
    saved figure (average tokens per real call x hit count — see
    _compute_cache_savings_summary's docstring for why this is an estimate,
    not a measurement), and net_calls_saved (total hits minus the embedding
    calls the semantic layer itself cost to run).

    Returns an empty list (and zeroed rpd/cache_savings blocks) if no trace
    file exists yet.
    """
    trace_file = Path(os.environ.get("TRACE_FILE", "traces/trace.jsonl"))
    empty_rpd = {"calls_today": 0, "cache_hits_today": 0, "cap": _RPD_CAP, "pct": 0.0, "embed_calls_today": 0}
    empty_cache_savings = {
        "exact_cache_hits": 0, "semantic_cache_hits": 0, "total_cache_hits": 0,
        "real_calls": 0, "hit_rate_pct": 0.0, "estimated_tokens_saved": 0,
        "embed_calls": 0, "net_calls_saved": 0,
    }
    if not trace_file.exists():
        return {"runs": [], "total": 0, "rpd": empty_rpd, "cache_savings": empty_cache_savings}

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
        return {"runs": [], "total": 0, "rpd": empty_rpd, "cache_savings": empty_cache_savings}

    rpd_summary = _compute_rpd_summary(spans)
    cache_savings_summary = _compute_cache_savings_summary(spans)

    run_spans = [s for s in spans if s.get("span_type") == "run"]
    total = len(run_spans)
    run_spans = run_spans[-limit:]

    llm_spans_by_run = _build_llm_spans_by_run(spans)
    runs = [_build_run_entry(run, llm_spans_by_run) for run in run_spans]

    return {"runs": runs, "total": total, "rpd": rpd_summary, "cache_savings": cache_savings_summary}


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


# ---------------------------------------------------------------------------
# /remediate — pure helper functions (tested directly, no HTTP needed)
# ---------------------------------------------------------------------------

def _filter_relevant_files(files: list, requested_paths: set[str]) -> tuple[list, list[str]]:
    """Filter a re-fetched file list down to just the paths referenced by a
    remediation request, and report which requested paths weren't found
    (stale repo_url/branch since the prior /analyze, or max_files too small
    to include them this time)."""
    relevant = [f for f in files if f.path in requested_paths]
    found_paths = {f.path for f in relevant}
    missing = sorted(requested_paths - found_paths)
    return relevant, missing


def _build_remediate_response(raw_result: dict) -> RemediateResponse:
    """Convert generate_remediation_patches()'s raw dict into a validated
    RemediateResponse.

    Mirrors the review pipeline's schema_errors pattern (see ReviewOut):
    generate_remediation_patches() itself does no schema validation, only a
    bare json.loads with a {"raw": ..., "parse_error": True} fallback on
    total failure. A single malformed patch inside an otherwise-valid
    response is dropped and recorded in schema_errors rather than 500-ing
    the whole request.
    """
    if raw_result.get("parse_error"):
        return RemediateResponse(
            patches=[], summary="", parse_error=True,
            schema_errors=["Gemini response was not valid JSON"],
        )

    patches: list[PatchOut] = []
    schema_errors: list[str] = []
    for i, p in enumerate(raw_result.get("patches", [])):
        try:
            patches.append(PatchOut(**p))
        except ValidationError as exc:
            schema_errors.append(f"patch {i}: {exc}")

    return RemediateResponse(
        patches=patches,
        summary=raw_result.get("summary", ""),
        parse_error=False,
        schema_errors=schema_errors,
    )


@app.post("/remediate", response_model=RemediateResponse, tags=["review"])
async def remediate(req: RemediateRequest) -> RemediateResponse:
    """
    Generate concrete before/after code patches for a set of findings.

    Opt-in only, mirroring post_pr_review_tool/create_issue_tool's design —
    never triggered automatically by /analyze. Re-fetches the repo's files
    via GitHub using the exact same fetch_python_files() call /analyze
    itself uses (no new fetch logic), filters down to just the paths
    referenced in `findings`, then hands both to the existing
    generate_remediation_patches() tool logic unchanged — this endpoint
    does not reimplement any patch-generation logic.

    `findings` is typically the exact `review.issues` array from a prior
    /analyze response for the same repo_url/branch (or a hand-picked
    subset of it, e.g. only the issues a user checked in the UI).

    Returns 400 if none of the requested findings' paths were found in the
    re-fetched files. `missing_paths` in a successful response lists any
    requested paths that weren't found but didn't block the rest.
    """
    agent: CodeReviewAgent = app.state.agent
    loop = asyncio.get_event_loop()

    def _fetch():
        return agent.fetch_files(req.repo_url, branch=req.branch, max_files=req.max_files)

    try:
        fetch_result = await asyncio.wait_for(
            loop.run_in_executor(None, _fetch),
            timeout=_AGENT_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"Fetch timed out after {_AGENT_TIMEOUT_S:.0f}s. "
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
        raise HTTPException(status_code=502, detail=f"GitHub fetch error: {exc.message}")
    except (AgentError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error re-fetching files for remediation of %s", req.repo_url)
        raise HTTPException(status_code=500, detail=f"Internal error: {exc}")

    requested_paths = {f.path for f in req.findings}
    relevant_files, missing_paths = _filter_relevant_files(fetch_result.files, requested_paths)

    if not relevant_files:
        raise HTTPException(
            status_code=400,
            detail=(
                "None of the requested findings' file paths were found in the "
                f"re-fetched repo: {', '.join(missing_paths)}. Check that repo_url/"
                "branch match the prior /analyze call, and that max_files is large "
                "enough to include them."
            ),
        )

    findings_dicts = [f.model_dump() for f in req.findings]

    def _remediate():
        return agent.generate_remediation_patches(findings_dicts, relevant_files)

    try:
        raw_result = await asyncio.wait_for(
            loop.run_in_executor(None, _remediate),
            timeout=_AGENT_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"Remediation timed out after {_AGENT_TIMEOUT_S:.0f}s.",
        )
    except (AgentError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected error generating remediation patches for %s", req.repo_url)
        raise HTTPException(status_code=500, detail=f"Internal error: {exc}")

    response = _build_remediate_response(raw_result)
    response.missing_paths = missing_paths
    return response
