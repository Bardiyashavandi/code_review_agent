"""
evals/trace_fixtures.py
-------------------------
Synthetic tracing spans for the cost-estimate eval cases. These match the
record shape tracing.py's Span.__exit__ writes to trace.jsonl, so they can
be fed directly to server.py's aggregation functions and to view_trace.py
(via a real trace.jsonl file on disk) without needing any Gemini call.

No network, no API key, no mocking required -- these cases are genuinely
testable in any environment, unlike the detection/FP/dedup/risk-scoring
cases which need a live Gemini call to mean anything.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def make_run_span(run_id: str, start_ts: str, status: str = "ok", **fields) -> dict:
    return {
        "span_id": run_id,
        "parent_id": None,
        "run_id": run_id,
        "span_type": "run",
        "name": "review_repo",
        "start_ts": start_ts,
        "end_ts": start_ts,
        "duration_s": fields.pop("duration_s", 1.0),
        "status": status,
        "error": None,
        "fields": fields,
    }


def make_llm_span(run_id: str, start_ts: str, span_id: str, **fields) -> dict:
    return {
        "span_id": span_id,
        "parent_id": run_id,
        "run_id": run_id,
        "span_type": "llm_call",
        "name": "gemini_call",
        "start_ts": start_ts,
        "end_ts": start_ts,
        "duration_s": 0.5,
        "status": "ok",
        "error": None,
        "fields": fields,
    }


def build_mixed_reliability_trace() -> tuple[list[dict], dict]:
    """
    Scenario for cost-estimate case #1: a run with a realistic mix of
    real calls, one call that reported no token usage, and one cache hit
    -- plus a second run from a different UTC day that must NOT be counted
    in "today"'s totals.

    Returns (spans, expected) where `expected` is the hand-computed answer
    key for the eval scorer to check both server.py and view_trace.py against.
    """
    now = datetime.now(timezone.utc)
    today_ts = _iso(now)
    yesterday_ts = _iso(now - timedelta(days=1, hours=1))

    run_today = make_run_span("run-today", today_ts, repo_url="https://github.com/o/r", files_fetched=3)
    run_yesterday = make_run_span("run-yesterday", yesterday_ts, repo_url="https://github.com/o/r2")

    spans = [
        run_today,
        # Real call, tokens reported.
        make_llm_span("run-today", today_ts, "s1", cache_hit=False, fallback_used=False,
                       tokens_available=True, total_tokens=120),
        # Real call, tokens reported.
        make_llm_span("run-today", today_ts, "s2", cache_hit=False, fallback_used=False,
                       tokens_available=True, total_tokens=340),
        # Real call, but the SDK didn't return usage_metadata this time --
        # tokens_available=False. Must contribute 0 to total_tokens, but
        # still counts as 1 real call against the RPD quota.
        make_llm_span("run-today", today_ts, "s3", cache_hit=False, fallback_used=False,
                       tokens_available=False),
        # Cache hit -- never touched the network. Must NOT count against
        # the RPD quota, and contributes no tokens.
        make_llm_span("run-today", today_ts, "s4", cache_hit=True),

        run_yesterday,
        # A real call from a different UTC day -- must be excluded from
        # "today"'s calls_today/cache_hits_today entirely.
        make_llm_span("run-yesterday", yesterday_ts, "s5", cache_hit=False,
                       tokens_available=True, total_tokens=9999),
    ]

    expected = {
        "calls_today": 3,          # s1, s2, s3 (s4 is a cache hit, s5 is yesterday)
        "cache_hits_today": 1,     # s4
        "run_today_llm_calls": 4,  # s1, s2, s3, s4
        "run_today_cache_hits": 1,
        "run_today_total_tokens": 460,  # 120 + 340; s3 excluded (tokens_available False)
    }
    return spans, expected


def build_stale_tokens_trace() -> tuple[list[dict], dict]:
    """
    Scenario for cost-estimate case #2: directly targets the masking risk
    called out in review -- a span with tokens_available=False that STILL
    has a (stale/garbage) total_tokens value set. The aggregation must key
    off tokens_available, not "is total_tokens present", or a leftover/
    malformed field would silently leak into the sum.
    """
    now = datetime.now(timezone.utc)
    ts = _iso(now)
    run = make_run_span("run-stale", ts, repo_url="https://github.com/o/r3")

    spans = [
        run,
        # tokens_available=False but total_tokens is still (incorrectly)
        # populated with a large stale value -- must be fully ignored.
        make_llm_span("run-stale", ts, "t1", cache_hit=False,
                       tokens_available=False, total_tokens=99_999),
        # tokens_available missing entirely (older span format, pre-dates
        # the field) -- must also be treated as 0, not crash on None.
        make_llm_span("run-stale", ts, "t2", cache_hit=False),
        # A genuinely valid call, for contrast.
        make_llm_span("run-stale", ts, "t3", cache_hit=False,
                       tokens_available=True, total_tokens=50),
    ]

    expected = {
        "run_stale_llm_calls": 3,
        "run_stale_cache_hits": 0,
        "run_stale_total_tokens": 50,  # only t3 -- the stale 99,999 must NOT appear
    }
    return spans, expected


def write_trace_file(spans: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for record in spans:
            f.write(json.dumps(record) + "\n")
