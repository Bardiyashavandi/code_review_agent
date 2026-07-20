"""
evals/cost_estimate_cases.py
------------------------------
The 2 cost-estimate eval cases. Unlike every other case in this suite,
these need no Gemini call and no CodeReviewAgent at all -- they exercise
server.py's _compute_rpd_summary / _build_run_entry against a synthetic
trace.jsonl, and cross-check the numbers against view_trace.py's _print_rpd
run on the exact same file, to catch silent drift between the two
independent parsers of the same data (per the review that scoped this
category: server.py:70-72 explicitly promises these stay in sync).

These are the only cases in evals/ that produce a genuinely meaningful,
deterministic pass/fail with zero network access or API key required.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from scorers import ScoreResult
from trace_fixtures import (
    build_mixed_reliability_trace,
    build_stale_tokens_trace,
    write_trace_file,
)

REPO_ROOT = Path(__file__).parent.parent


def _run_view_trace_list(trace_path: Path) -> str:
    result = subprocess.run(
        [sys.executable, "view_trace.py", "--file", str(trace_path), "--list"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
    )
    return result.stdout


def _parse_cli_rpd(cli_output: str) -> tuple[int, int]:
    match = re.search(r"Gemini calls today:\s*(\d+)\s*/\s*(\d+)", cli_output)
    if not match:
        raise ValueError(f"Could not find RPD line in view_trace.py output:\n{cli_output}")
    return int(match.group(1)), int(match.group(2))


def run_cost_estimate_case_1(tmp_dir: Path) -> ScoreResult:
    """Mixed trace: real calls with/without token usage, one cache hit,
    one call from a different UTC day. Checks server.py's numbers against
    hand-computed expectations AND against view_trace.py on the same file."""
    import server  # local import: server.py has module-level side effects best deferred

    spans, expected = build_mixed_reliability_trace()
    trace_path = tmp_dir / "mixed_reliability_trace.jsonl"
    write_trace_file(spans, trace_path)

    rpd = server._compute_rpd_summary(spans)
    by_run = server._build_llm_spans_by_run(spans)
    run_today_span = next(s for s in spans if s.get("span_type") == "run" and s["span_id"] == "run-today")
    run_entry = server._build_run_entry(run_today_span, by_run)

    problems = []

    if rpd["calls_today"] != expected["calls_today"]:
        problems.append(
            f"server._compute_rpd_summary calls_today={rpd['calls_today']}, "
            f"expected {expected['calls_today']}"
        )
    if rpd["cache_hits_today"] != expected["cache_hits_today"]:
        problems.append(
            f"server._compute_rpd_summary cache_hits_today={rpd['cache_hits_today']}, "
            f"expected {expected['cache_hits_today']}"
        )
    if run_entry["llm_calls"] != expected["run_today_llm_calls"]:
        problems.append(
            f"server._build_run_entry llm_calls={run_entry['llm_calls']}, "
            f"expected {expected['run_today_llm_calls']}"
        )
    if run_entry["cache_hits"] != expected["run_today_cache_hits"]:
        problems.append(
            f"server._build_run_entry cache_hits={run_entry['cache_hits']}, "
            f"expected {expected['run_today_cache_hits']}"
        )
    if run_entry["total_tokens"] != expected["run_today_total_tokens"]:
        problems.append(
            f"server._build_run_entry total_tokens={run_entry['total_tokens']}, "
            f"expected {expected['run_today_total_tokens']}"
        )

    # Cross-check against view_trace.py on the exact same file.
    cli_output = _run_view_trace_list(trace_path)
    cli_calls_today, cli_cap = _parse_cli_rpd(cli_output)
    if cli_calls_today != rpd["calls_today"]:
        problems.append(
            f"SIBLING DRIFT: view_trace.py reports calls_today={cli_calls_today}, "
            f"but server.py's _compute_rpd_summary reports {rpd['calls_today']} "
            f"for the identical trace file."
        )

    if problems:
        return ScoreResult(False, "; ".join(problems))
    return ScoreResult(
        True,
        f"server.py and view_trace.py agree: calls_today={rpd['calls_today']}, "
        f"cache_hits_today={rpd['cache_hits_today']}, run total_tokens={run_entry['total_tokens']}.",
    )


def run_cost_estimate_case_2(tmp_dir: Path) -> ScoreResult:
    """Targets the specific masking risk called out in review: a span with
    tokens_available=False but a stale/garbage total_tokens value still
    present must NOT leak into the sum. A span missing tokens_available
    entirely must also resolve to 0, not crash."""
    import server

    spans, expected = build_stale_tokens_trace()
    trace_path = tmp_dir / "stale_tokens_trace.jsonl"
    write_trace_file(spans, trace_path)

    by_run = server._build_llm_spans_by_run(spans)
    run_span = next(s for s in spans if s.get("span_type") == "run")
    run_entry = server._build_run_entry(run_span, by_run)

    problems = []
    if run_entry["llm_calls"] != expected["run_stale_llm_calls"]:
        problems.append(f"llm_calls={run_entry['llm_calls']}, expected {expected['run_stale_llm_calls']}")
    if run_entry["cache_hits"] != expected["run_stale_cache_hits"]:
        problems.append(f"cache_hits={run_entry['cache_hits']}, expected {expected['run_stale_cache_hits']}")
    if run_entry["total_tokens"] != expected["run_stale_total_tokens"]:
        problems.append(
            f"total_tokens={run_entry['total_tokens']}, expected "
            f"{expected['run_stale_total_tokens']} -- the stale 99,999 value on a "
            f"tokens_available=False span leaked into the sum."
        )

    if problems:
        return ScoreResult(False, "; ".join(problems))
    return ScoreResult(
        True,
        f"Stale/missing tokens_available fields correctly resolved to 0 contribution; "
        f"total_tokens={run_entry['total_tokens']} as expected.",
    )
