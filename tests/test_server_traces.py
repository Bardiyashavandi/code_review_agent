"""
tests/test_server_traces.py
-----------------------------
Tests for the /traces endpoint's reliability-stats aggregation, added to
surface caching/fallback/RPD data in the Streamlit History tab.

server.py exposes the aggregation as three pure functions
(_compute_rpd_summary, _build_llm_spans_by_run, _build_run_entry) so they
can be tested directly against hand-built span dicts -- no FastAPI
TestClient, no live app.state.agent, no GITHUB_TOKEN/GEMINI_API_KEY
required. Importing `server` itself is safe without credentials: the
RuntimeError for missing env vars only fires inside the `lifespan`
context manager, which only runs when the app actually starts.

Run with:
    pytest tests/test_server_traces.py -v
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from server import _build_llm_spans_by_run, _build_run_entry, _compute_rpd_summary

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _today_ts(offset_seconds: int = 0) -> str:
    dt = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return dt.isoformat().replace("+00:00", "Z")


def _yesterday_ts() -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=1)
    return dt.isoformat().replace("+00:00", "Z")


def make_run_span(run_id: str, status: str = "ok", start_ts: str | None = None,
                   **fields) -> dict:
    return {
        "span_id": run_id,
        "span_type": "run",
        "status": status,
        "start_ts": start_ts or _today_ts(),
        "duration_s": fields.pop("duration_s", 1.0),
        "fields": fields,
    }


def make_llm_span(run_id: str, start_ts: str | None = None, **fields) -> dict:
    return {
        "span_type": "llm_call",
        "run_id": run_id,
        "start_ts": start_ts or _today_ts(),
        "fields": fields,
    }


# ---------------------------------------------------------------------------
# _compute_rpd_summary
# ---------------------------------------------------------------------------

class TestComputeRpdSummary:

    def test_empty_spans_gives_zeroed_summary(self):
        summary = _compute_rpd_summary([])
        assert summary == {"calls_today": 0, "cache_hits_today": 0, "cap": 500, "pct": 0.0}

    def test_counts_only_real_calls_not_cache_hits(self):
        spans = [
            make_llm_span("r1", cache_hit=False),
            make_llm_span("r1", cache_hit=False),
            make_llm_span("r1", cache_hit=True),  # served from cache -- not a real call
        ]
        summary = _compute_rpd_summary(spans)
        assert summary["calls_today"] == 2
        assert summary["cache_hits_today"] == 1

    def test_excludes_spans_from_other_days(self):
        spans = [
            make_llm_span("r1", start_ts=_today_ts(), cache_hit=False),
            make_llm_span("r1", start_ts=_yesterday_ts(), cache_hit=False),
        ]
        summary = _compute_rpd_summary(spans)
        assert summary["calls_today"] == 1

    def test_ignores_non_llm_call_spans(self):
        spans = [
            make_run_span("r1"),
            {"span_type": "stage", "start_ts": _today_ts(), "fields": {}},
            make_llm_span("r1", cache_hit=False),
        ]
        summary = _compute_rpd_summary(spans)
        assert summary["calls_today"] == 1

    def test_pct_computed_against_cap(self):
        spans = [make_llm_span("r1", cache_hit=False) for _ in range(50)]
        summary = _compute_rpd_summary(spans)
        assert summary["calls_today"] == 50
        assert summary["cap"] == 500
        assert summary["pct"] == 10.0


# ---------------------------------------------------------------------------
# _build_llm_spans_by_run / _build_run_entry
# ---------------------------------------------------------------------------

class TestBuildRunEntry:

    def test_aggregates_llm_calls_cache_hits_and_fallbacks_for_its_own_run(self):
        run = make_run_span("run-A", repo_url="https://github.com/o/r", files_fetched=3)
        spans = [
            run,
            make_llm_span("run-A", cache_hit=False, fallback_used=False,
                           tokens_available=True, total_tokens=100),
            make_llm_span("run-A", cache_hit=True, fallback_used=False),
            make_llm_span("run-A", cache_hit=False, fallback_used=True,
                           tokens_available=True, total_tokens=50),
            # Different run -- must not leak into run-A's counts.
            make_llm_span("run-B", cache_hit=False, fallback_used=False,
                           tokens_available=True, total_tokens=9999),
        ]

        by_run = _build_llm_spans_by_run(spans)
        entry = _build_run_entry(run, by_run)

        assert entry["run_id"] == "run-A"
        assert entry["repo_url"] == "https://github.com/o/r"
        assert entry["llm_calls"] == 3
        assert entry["cache_hits"] == 1
        assert entry["fallback_used_count"] == 1
        assert entry["total_tokens"] == 150  # only run-A's tokens, 9999 excluded

    def test_run_with_no_llm_spans_gets_zeroed_fields(self):
        run = make_run_span("run-solo")
        by_run = _build_llm_spans_by_run([run])

        entry = _build_run_entry(run, by_run)

        assert entry["llm_calls"] == 0
        assert entry["cache_hits"] == 0
        assert entry["fallback_used_count"] == 0
        assert entry["total_tokens"] == 0

    def test_tokens_excluded_when_not_available(self):
        run = make_run_span("run-C")
        spans = [
            run,
            # tokens_available False (or missing) -- total_tokens must not
            # be counted even if present, since the field is meaningless
            # when the SDK didn't report usage_metadata.
            make_llm_span("run-C", cache_hit=False, tokens_available=False, total_tokens=42),
            make_llm_span("run-C", cache_hit=False),  # tokens_available absent entirely
        ]
        by_run = _build_llm_spans_by_run(spans)

        entry = _build_run_entry(run, by_run)

        assert entry["llm_calls"] == 2
        assert entry["total_tokens"] == 0

    def test_llm_spans_nested_under_stage_still_grouped_by_run_id(self):
        # llm_call spans are children of a stage span, not the run span
        # directly -- grouping must go by run_id (which tracing.py threads
        # through every descendant), not parent_id.
        run = make_run_span("run-D")
        spans = [
            run,
            {"span_type": "stage", "run_id": "run-D", "start_ts": _today_ts(), "fields": {}},
            make_llm_span("run-D", cache_hit=False),
        ]
        by_run = _build_llm_spans_by_run(spans)

        entry = _build_run_entry(run, by_run)

        assert entry["llm_calls"] == 1
