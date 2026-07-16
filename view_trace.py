"""
view_trace.py
-------------
Pretty-print traces from traces/trace.jsonl.

Default (no flags):
    Shows the last full run as an indented tree — run → stages → llm_calls —
    plus today's Gemini call count against the 500 RPD free-tier cap.

    python3 view_trace.py

Options:
    --tail N        Show the last N span lines as a flat list (ignores run
                    boundaries — useful for scanning across runs).
    --run RUN_ID    Show the full tree for a specific run_id.
    --file PATH     Read from a different trace file (default: traces/trace.jsonl).
    --list          List all run_ids in the file with their timestamps and status.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_RED    = "\033[31m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_CYAN   = "\033[36m"
_WHITE  = "\033[37m"

_TYPE_COLOR = {
    "run":      _BOLD + _CYAN,
    "stage":    _BOLD + _WHITE,
    "llm_call": _BOLD + _YELLOW,
}

_RPD_CAP = 500


def _c(text: str, code: str) -> str:
    """Wrap text in ANSI color code (skipped if stdout is not a TTY)."""
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{_RESET}"


def _status_icon(span: dict) -> str:
    return _c("✓", _GREEN) if span.get("status") == "ok" else _c("✗", _RED)


def _fmt_dur(s: float) -> str:
    if s >= 60:
        return f"{s / 60:.1f}m"
    return f"{s:.2f}s"


def _fmt_ts(iso: str | None) -> str:
    if not iso:
        return "?"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return iso


def _today_prefix() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Tree printer
# ---------------------------------------------------------------------------

def _print_run_tree(run_span: dict, children: list[dict]) -> None:
    f = run_span.get("fields", {})

    print()
    print(_c(f"▶ RUN  {run_span['name']}", _TYPE_COLOR["run"])
          + f"  {_status_icon(run_span)}  {_fmt_dur(run_span.get('duration_s', 0))}"
          + _c(f"  run_id={run_span['span_id']}", _DIM))
    print(_c(f"  {_fmt_ts(run_span.get('start_ts'))}", _DIM))

    if f.get("repo_url"):
        print(f"  repo_url:  {f['repo_url']}")
    parts = []
    if "branch" in f:
        parts.append(f"branch={f['branch']}")
    if "max_files" in f:
        parts.append(f"max_files={f['max_files']}")
    if parts:
        print(f"  {' · '.join(parts)}")
    results = []
    if "files_fetched" in f:
        results.append(f"{f['files_fetched']} files fetched")
    if "semgrep_findings" in f:
        results.append(f"{f['semgrep_findings']} semgrep findings")
    if "review_issues" in f:
        results.append(f"{f['review_issues']} issues")
    if results:
        print(f"  {' · '.join(results)}")
    if f.get("stage_errors"):
        print(_c(f"  stage errors: {f['stage_errors']}", _RED))
    if run_span.get("error"):
        print(_c(f"  error: {run_span['error']}", _RED))

    # Group children by type for ordering: stage spans, then their llm_call children
    stage_spans = [s for s in children if s.get("span_type") == "stage"]
    llm_spans   = [s for s in children if s.get("span_type") == "llm_call"]

    # Map llm_call parent_id → list of llm spans
    llm_by_parent: dict[str, list[dict]] = defaultdict(list)
    for s in llm_spans:
        llm_by_parent[s.get("parent_id", "")].append(s)

    for stage in stage_spans:
        _print_stage(stage, llm_by_parent.get(stage["span_id"], []))

    print()


def _print_stage(span: dict, llm_children: list[dict]) -> None:
    f = span.get("fields", {})
    dur = _fmt_dur(span.get("duration_s", 0))

    print()
    print(_c(f"  ├─ STAGE  {span['name']}", _TYPE_COLOR["stage"])
          + f"  {_status_icon(span)}  {dur}")

    name = span.get("name", "")
    if name == "fetch":
        parts = []
        if "files_fetched" in f:
            parts.append(f"files_fetched={f['files_fetched']}")
        if "truncated" in f:
            parts.append(f"truncated={f['truncated']}")
        if parts:
            print(f"  │    {' · '.join(parts)}")
    elif name == "scan":
        parts = []
        if "scanned" in f:
            parts.append(f"scanned={f['scanned']}")
        if "findings" in f:
            parts.append(f"findings={f['findings']}")
        if "skipped" in f:
            parts.append(f"skipped={f['skipped']}")
        if parts:
            print(f"  │    {' · '.join(parts)}")
    elif name == "review":
        parts = []
        if "files_reviewed" in f:
            parts.append(f"files_reviewed={f['files_reviewed']}")
        if "issues" in f:
            parts.append(f"issues={f['issues']}")
        if "model" in f:
            parts.append(f"model={f['model']}")
        if parts:
            print(f"  │    {' · '.join(parts)}")

    if span.get("error"):
        print(_c(f"  │    error: {span['error']}", _RED))

    for llm in llm_children:
        _print_llm(llm)


def _print_llm(span: dict) -> None:
    f = span.get("fields", {})
    dur = _fmt_dur(span.get("duration_s", 0))
    batch = f.get("batch_index", "?")
    name  = span.get("name", "gemini_call")

    cache_hit = f.get("cache_hit") is True
    tag = ""
    if cache_hit:
        tag = "  " + _c("[CACHE HIT]", _BOLD + _CYAN)
    elif f.get("fallback_used"):
        fb_model = f.get("fallback_model", "?")
        tag = "  " + _c(f"[FALLBACK → {fb_model}]", _BOLD + _YELLOW)

    print(_c(f"  │    └─ LLM  {name}", _TYPE_COLOR["llm_call"])
          + f"  batch={batch}  {_status_icon(span)}  {dur}" + tag)

    if cache_hit:
        # Cache hits skip the network call entirely — nothing else to show.
        print(f"  │         served from in-memory cache, no Gemini call made")
        if span.get("error"):
            print(_c(f"  │         error: {span['error']}", _RED))
        return

    parts = []
    if "prompt_chars" in f:
        parts.append(f"prompt_chars={f['prompt_chars']}")
    if f.get("tokens_available"):
        pt = f.get("prompt_tokens", "?")
        ct = f.get("candidates_tokens", "?")
        tt = f.get("total_tokens", "?")
        parts.append(f"tokens={pt}→{ct} ({tt} total)")
    else:
        parts.append("tokens=unavailable")
    if "retry_count" in f:
        parts.append(f"retries={f['retry_count']}")
    if parts:
        print(f"  │         {' · '.join(parts)}")

    if f.get("fallback_used"):
        fb_parts = []
        if "fallback_retry_count" in f:
            fb_parts.append(f"fallback_retries={f['fallback_retry_count']}")
        if f.get("fallback_failed"):
            fb_parts.append(_c("fallback also failed", _RED))
        elif "model_used" in f:
            fb_parts.append(f"served_by={f['model_used']}")
        if fb_parts:
            print(f"  │         {' · '.join(fb_parts)}")
    elif "model_used" in f and f["model_used"] != f.get("model"):
        print(f"  │         served_by={f['model_used']}")

    if span.get("error"):
        print(_c(f"  │         error: {span['error']}", _RED))


# ---------------------------------------------------------------------------
# Flat tail printer
# ---------------------------------------------------------------------------

def _print_flat(spans: list[dict]) -> None:
    for i, span in enumerate(spans, 1):
        f = span.get("fields", {})
        stype = span.get("span_type", "?").upper()
        name  = span.get("name", "?")
        dur   = _fmt_dur(span.get("duration_s", 0))
        ts    = _fmt_ts(span.get("start_ts"))
        color = _TYPE_COLOR.get(span.get("span_type", ""), _WHITE)

        print()
        print(f"[{i}] " + _c(f"{stype}  {name}", color)
              + f"  {_status_icon(span)}  {dur}"
              + _c(f"  {ts}", _DIM))
        print(f"     run_id={span.get('run_id', '?')}"
              + (f"  parent={span.get('parent_id', '?')}" if span.get("parent_id") else ""))

        # Print notable fields
        notable = {k: v for k, v in f.items()
                   if v is not None and v != [] and v != "" and v is not False}
        if notable:
            line = "     " + " · ".join(f"{k}={v}" for k, v in list(notable.items())[:8])
            print(line)
        if span.get("error"):
            print(_c(f"     error: {span['error']}", _RED))
    print()


# ---------------------------------------------------------------------------
# RPD counter
# ---------------------------------------------------------------------------

def _print_rpd(spans: list[dict]) -> None:
    today = _today_prefix()
    todays_llm_spans = [
        s for s in spans
        if s.get("span_type") == "llm_call"
        and (s.get("start_ts") or "").startswith(today)
    ]
    # Cache hits never touch the Gemini API, so they don't count against the
    # daily request quota — only spans that actually reached generate_content
    # (cache_hit is False or absent, for spans written before this field
    # existed) count here.
    cache_hits = sum(1 for s in todays_llm_spans if s.get("fields", {}).get("cache_hit") is True)
    count = len(todays_llm_spans) - cache_hits

    pct = count / _RPD_CAP * 100
    bar_filled = int(pct / 5)  # 20-char bar
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    color = _RED if pct >= 90 else _YELLOW if pct >= 70 else _GREEN
    print(_c(f"  Gemini calls today: {count} / {_RPD_CAP}  [{bar}]  {pct:.0f}%", color))
    if cache_hits:
        print(_c(f"  ({cache_hits} additional call(s) served from cache, not counted)", _DIM))
    print()


# ---------------------------------------------------------------------------
# Run lister
# ---------------------------------------------------------------------------

def _list_runs(spans: list[dict]) -> None:
    run_spans = [s for s in spans if s.get("span_type") == "run"]
    if not run_spans:
        print("No runs found.")
        return
    print(f"\n{'RUN_ID':<12}  {'TIMESTAMP':<24}  {'STATUS':<6}  {'DURATION':>8}  REPO")
    print("─" * 90)
    for s in run_spans:
        ts  = _fmt_ts(s.get("start_ts"))
        dur = _fmt_dur(s.get("duration_s", 0))
        url = s.get("fields", {}).get("repo_url", "?")
        icon = _status_icon(s)
        print(f"{s['span_id']:<12}  {ts:<24}  {icon}       {dur:>8}  {url}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _load_spans(path: Path) -> list[dict]:
    if not path.exists():
        print(f"Trace file not found: {path}")
        sys.exit(1)
    spans = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    spans.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return spans


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pretty-print traces from traces/trace.jsonl",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--tail",  type=int, metavar="N",
                        help="Show the last N spans as a flat list (ignores run boundaries)")
    parser.add_argument("--run",   metavar="RUN_ID",
                        help="Show a specific run by run_id prefix")
    parser.add_argument("--file",  default="traces/trace.jsonl",
                        help="Path to trace file (default: traces/trace.jsonl)")
    parser.add_argument("--list",  action="store_true",
                        help="List all run_ids with timestamps and status")
    args = parser.parse_args()

    trace_path = Path(args.file)
    all_spans  = _load_spans(trace_path)

    if not all_spans:
        print("No spans found in trace file.")
        sys.exit(0)

    # --- --list ---
    if args.list:
        _list_runs(all_spans)
        _print_rpd(all_spans)
        return

    # --- --tail N ---
    if args.tail is not None:
        tail_spans = all_spans[-args.tail:]
        print(f"\n{_c('Last ' + str(len(tail_spans)) + ' spans (flat)', _BOLD)}"
              f"  from {trace_path}\n")
        _print_flat(tail_spans)
        _print_rpd(all_spans)
        return

    # --- default: last full run (or --run <id>) ---
    run_spans = {s["span_id"]: s for s in all_spans if s.get("span_type") == "run"}

    if not run_spans:
        print("No run-level spans found. Try --tail N to see raw spans.")
        sys.exit(0)

    if args.run:
        # Allow prefix match
        matched = [rid for rid in run_spans if rid.startswith(args.run)]
        if not matched:
            print(f"No run found with id starting with '{args.run}'. Use --list to see all runs.")
            sys.exit(1)
        target_run_id = matched[-1]
    else:
        # Most recent run = last run span in the file
        run_span_list = [s for s in all_spans if s.get("span_type") == "run"]
        target_run_id = run_span_list[-1]["span_id"]

    run_span  = run_spans[target_run_id]
    children  = [s for s in all_spans if s.get("run_id") == target_run_id
                 and s.get("span_type") != "run"]

    total_runs = len(run_spans)
    print(f"\n{_c('Last run', _BOLD)}  ({total_runs} total run(s) in {trace_path})")
    _print_run_tree(run_span, children)
    _print_rpd(all_spans)


if __name__ == "__main__":
    main()
