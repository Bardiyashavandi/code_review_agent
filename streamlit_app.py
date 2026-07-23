"""
streamlit_app.py
----------------
Minimal Streamlit front end for the AI Code Review Agent.
Calls the FastAPI server (server.py) — that server must be running first.

Run:
    # Terminal 1 — API server
    uvicorn server:app --reload

    # Terminal 2 — UI
    streamlit run streamlit_app.py

The API base URL defaults to http://127.0.0.1:8000 and can be overridden
via the REVIEW_API_URL environment variable so pointing at a remote server
requires no code change.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import requests
import streamlit as st

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_URL = os.environ.get("REVIEW_API_URL", "http://127.0.0.1:8000").rstrip("/")

# Give ourselves a little headroom beyond the server's own timeout so the
# server's 504 response reaches us rather than the requests library cutting
# the connection first.
_SERVER_TIMEOUT = int(os.environ.get("AGENT_TIMEOUT_S", "180"))
REQUEST_TIMEOUT = _SERVER_TIMEOUT + 15

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

# Maps severity label → (background hex, text hex).
# Only these fixed strings are ever interpolated into HTML — never
# agent-generated text, which is always rendered through st.markdown/st.write.
_SEVERITY_STYLE: dict[str, tuple[str, str]] = {
    "CRITICAL": ("#b71c1c", "#ffffff"),
    "HIGH":     ("#e65100", "#ffffff"),
    "MEDIUM":   ("#f9a825", "#000000"),
    "LOW":      ("#1565c0", "#ffffff"),
    "INFO":     ("#546e7a", "#ffffff"),
}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# RPD progress bar color thresholds, mirroring view_trace.py's CLI coloring
# (green under 70%, yellow 70-89%, red 90%+).
def _rpd_color(pct: float) -> str:
    if pct >= 90:
        return "#c62828"
    if pct >= 70:
        return "#f9a825"
    return "#2e7d32"


def _badge(severity: str) -> str:
    """Return a small inline HTML badge for a severity level.

    The only value interpolated into the HTML string is the severity key
    itself — a fixed string we control, looked up from _SEVERITY_STYLE.
    Agent-generated content (titles, descriptions, etc.) is never passed
    through this function.
    """
    key = severity.upper()
    bg, fg = _SEVERITY_STYLE.get(key, ("#546e7a", "#ffffff"))
    return (
        f'<span style="background:{bg}; color:{fg}; padding:2px 10px; '
        f'border-radius:4px; font-size:0.78em; font-weight:700; '
        f'letter-spacing:0.04em; font-family:monospace;">{key}</span>'
    )


def _severity_rank(issue: dict) -> int:
    key = issue.get("severity", "").upper()
    try:
        return _SEVERITY_ORDER.index(key)
    except ValueError:
        return len(_SEVERITY_ORDER)


# ---------------------------------------------------------------------------
# Result renderers
# ---------------------------------------------------------------------------

def _render_issues(issues: list[dict]) -> list[dict]:
    """Render the issues list with a per-issue "include in fix" checkbox.

    Returns the subset of issues (in the same dict shape /remediate expects
    for `findings`) whose checkbox is currently checked, so the caller can
    wire up a single "generate fixes for selected issues" action without
    this function needing to know anything about repo_url/branch or the
    remediation endpoint itself.
    """
    if not issues:
        st.info("No review issues found.")
        return []

    sorted_issues = sorted(issues, key=_severity_rank)
    selected: list[dict] = []

    for idx, issue in enumerate(sorted_issues, 1):
        sev   = issue.get("severity", "INFO").upper()
        path  = issue.get("path", "")
        line  = issue.get("line", "")
        title = issue.get("title", "Untitled issue")

        # Expander label: plain text only
        label = f"#{idx}  {path}:{line}  —  {title}"
        with st.expander(label, expanded=(idx <= 3)):
            # Badge (controlled HTML) on its own line
            st.markdown(_badge(sev), unsafe_allow_html=True)
            st.markdown(f"**File:** `{path}` &nbsp;·&nbsp; **Line:** {line}")

            rule_id = issue.get("rule_id")
            if rule_id:
                st.markdown(f"**Rule:** `{rule_id}`")

            st.markdown("**Description**")
            # Agent text — rendered as markdown, not HTML
            st.markdown(issue.get("description", ""))

            st.markdown("**Suggested fix**")
            st.markdown(issue.get("suggested_fix", ""))

            # Stable-ish key: position + path + line survives reruns
            # triggered by other widgets (e.g. the remediation button
            # below), since sort order for the same issue list is stable.
            checkbox_key = f"remediate_select_{idx}_{path}_{line}"
            include = st.checkbox("Include in fix generation", key=checkbox_key)
            if include:
                selected.append(issue)

    return selected


def _render_patch(patch: dict) -> None:
    """Render a single before/after remediation patch."""
    path        = patch.get("path", "")
    line        = patch.get("line")
    title       = patch.get("title", "")
    explanation = patch.get("explanation", "")
    before      = patch.get("before", "")
    after       = patch.get("after", "")
    deps        = patch.get("dependencies", []) or []
    breaking    = patch.get("breaking_change", False)
    breaking_note = patch.get("breaking_change_note")

    label = f"{path}:{line} — {title}" if line else f"{path} — {title}"
    with st.expander(label, expanded=True):
        if explanation:
            st.markdown(f"**Why this fix:** {explanation}")

        col_before, col_after = st.columns(2)
        with col_before:
            st.markdown("**Before**")
            st.code(before, language="python")
        with col_after:
            st.markdown("**After**")
            st.code(after, language="python")

        if deps:
            st.caption(f"New dependencies: {', '.join(deps)}")
        if breaking:
            st.warning(f"⚠️ Breaking change: {breaking_note or 'callers may need to update.'}")


def _render_remediation_result(result: dict) -> None:
    """Render a /remediate response: summary, any warnings, then each patch."""
    patches       = result.get("patches", [])
    summary       = result.get("summary", "")
    missing_paths = result.get("missing_paths", []) or []
    schema_errors = result.get("schema_errors", []) or []
    parse_error   = result.get("parse_error", False)

    if parse_error:
        st.error("Gemini's remediation response couldn't be parsed as JSON. Try again.")
        return

    if summary:
        st.info(summary)
    if missing_paths:
        st.warning(
            "These paths weren't found in the re-fetched repo and were skipped: "
            + ", ".join(missing_paths)
        )
    if schema_errors:
        st.warning(f"{len(schema_errors)} patch(es) had an unexpected shape and were dropped.")

    if not patches:
        st.caption("No patches were generated for the selected issues.")
        return

    for patch in patches:
        _render_patch(patch)


def _render_remediation_section(issues: list[dict], repo_url: str, branch: str) -> None:
    """"Generate fixes" action: renders the issue checkboxes, a button to
    request patches for whatever's checked, and the resulting patches.

    Calls POST /remediate — opt-in only, never fired automatically after a
    review. Results are cached in st.session_state so they survive the
    rerun that Streamlit triggers on every widget interaction (including
    ticking another issue's checkbox).
    """
    st.subheader("Fix generation")
    st.caption(
        "Select the issues you want concrete before/after patches for, then "
        "generate fixes. This re-fetches the relevant files from GitHub and "
        "makes one additional Gemini call — nothing here runs automatically."
    )

    selected = _render_issues(issues)

    button_disabled = not selected
    button_label = (
        f"🔧 Generate fixes for {len(selected)} selected issue(s)"
        if selected else "🔧 Generate fixes for selected issues"
    )

    if st.button(button_label, disabled=button_disabled, type="primary"):
        findings = [
            {
                "path": i.get("path", ""),
                "line": i.get("line", 0),
                "severity": i.get("severity", "MEDIUM"),
                "title": i.get("title", "Finding"),
                "description": i.get("description", ""),
                "suggested_fix": i.get("suggested_fix", ""),
                "rule_id": i.get("rule_id"),
            }
            for i in selected
        ]
        with st.spinner("Generating patches…"):
            try:
                resp = requests.post(
                    f"{BASE_URL}/remediate",
                    json={
                        "repo_url": repo_url,
                        "branch": branch,
                        "findings": findings,
                    },
                    timeout=REQUEST_TIMEOUT,
                )
                if resp.status_code == 200:
                    st.session_state["remediation_result"] = resp.json()
                else:
                    try:
                        detail = resp.json().get("detail", resp.text)
                    except Exception:
                        detail = resp.text
                    st.session_state["remediation_result"] = None
                    st.error(f"Remediation failed ({resp.status_code}): {detail}")
            except requests.ConnectionError:
                st.session_state["remediation_result"] = None
                st.error(f"Cannot reach the review server at `{BASE_URL}`.")
            except requests.Timeout:
                st.session_state["remediation_result"] = None
                st.error("Remediation request timed out on the client side.")

    if st.session_state.get("remediation_result"):
        st.markdown("---")
        st.markdown("**Generated patches**")
        _render_remediation_result(st.session_state["remediation_result"])


def _render_scan(scan: dict) -> None:
    findings  = scan.get("findings", [])
    scanned   = scan.get("scanned", 0)
    skipped   = scan.get("skipped", [])
    duration  = scan.get("duration_s", 0.0)

    st.markdown(
        f"**{scanned}** file(s) scanned &nbsp;·&nbsp; "
        f"**{len(findings)}** finding(s) &nbsp;·&nbsp; {duration:.1f} s"
    )
    if skipped:
        st.caption(f"Skipped: {', '.join(skipped)}")

    if not findings:
        st.caption("No Semgrep findings.")
        return

    for finding in findings:
        path       = finding.get("path", "")
        line_start = finding.get("line_start", "")
        line_end   = finding.get("line_end", "")
        rule_id    = finding.get("rule_id", "")
        severity   = finding.get("severity", "INFO")
        message    = finding.get("message", "")
        snippet    = finding.get("snippet", "")

        label = f"{path}:{line_start} — {rule_id}"
        with st.expander(label):
            st.markdown(_badge(severity), unsafe_allow_html=True)
            st.markdown(f"**Lines {line_start}–{line_end}** &nbsp;·&nbsp; `{rule_id}`")
            st.markdown(message)
            if snippet:
                st.code(snippet, language="python")


def _render_results(data: dict, repo_url: str, branch: str) -> None:
    review       = data.get("review", {})
    scan         = data.get("scan", {})
    stage_errors = data.get("stage_errors", [])
    issues       = review.get("issues", [])

    # --- Metrics row ---
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Files fetched", data.get("files_fetched", 0))
    c2.metric("Issues found",  len(issues))
    c3.metric("Duration",      f"{data.get('duration_s', 0):.1f} s")
    c4.metric("Model",         review.get("model", "—"))

    if data.get("truncated"):
        st.warning(
            "⚠️ Not all files were fetched — result is truncated. "
            "Increase **max_files** to cover the full repo."
        )

    # --- Stage errors (non-fatal pipeline warnings) ---
    for err in stage_errors:
        stage = err.get("stage", "unknown").capitalize()
        st.warning(f"**{stage} stage warning:** {err.get('message', '')}")

    # --- Gemini summary ---
    st.subheader("Summary")
    st.info(review.get("summary") or "No summary returned.")

    # --- Issues + remediation ---
    st.subheader(f"Issues ({len(issues)})")
    _render_remediation_section(issues, repo_url, branch)

    # --- Scan details (collapsed by default) ---
    finding_count = len(scan.get("findings", []))
    with st.expander(f"Semgrep scan details ({finding_count} finding(s))", expanded=False):
        _render_scan(scan)


# ---------------------------------------------------------------------------
# Error message map for non-200 HTTP responses
# ---------------------------------------------------------------------------

_HTTP_MESSAGES: dict[int, str] = {
    401: "GitHub token rejected. Check GITHUB_TOKEN in the server's .env file.",
    404: "Repo not found or private. Verify the URL and that your GITHUB_TOKEN has read access.",
    422: "Invalid request (validation error).",   # detail appended below
    429: "GitHub API rate limit hit. Wait a minute and try again.",
    504: (
        "Server timed out running the review. "
        "Try reducing max_files, or set a higher AGENT_TIMEOUT_S on the server."
    ),
}


# ---------------------------------------------------------------------------
# Page layout
# ---------------------------------------------------------------------------

def _render_rpd_bar(rpd: dict) -> None:
    """Render the same 'Gemini calls today / cap' summary view_trace.py --list
    prints to the terminal, so the reliability story is visible without a
    terminal mid-demo."""
    calls = rpd.get("calls_today", 0)
    cache_hits = rpd.get("cache_hits_today", 0)
    cap = rpd.get("cap", 500) or 1  # guard div-by-zero if cap is ever 0
    pct = rpd.get("pct", 0.0)
    color = _rpd_color(pct)

    # Only fixed-shape, server-computed numeric values are interpolated here
    # (never repo/agent-generated text) — same scoping rule as the severity
    # badges above.
    st.markdown(
        f'**Gemini calls today:** {calls} / {cap} '
        f'&nbsp; <span style="color:{color}; font-weight:700;">{pct:.0f}%</span>',
        unsafe_allow_html=True,
    )
    st.progress(min(pct / 100, 1.0))
    if cache_hits:
        st.caption(
            f"{cache_hits} additional call(s) served from cache (exact-match or "
            f"semantic) today, not counted against the quota."
        )
    embed_calls = rpd.get("embed_calls_today", 0)
    if embed_calls:
        st.caption(
            f"{embed_calls} embedding call(s) today for the semantic cache — "
            f"a separate quota bucket, not counted above."
        )


def _render_history() -> None:
    """Fetch and render the run history tab from GET /traces."""
    st.subheader("Run History")
    st.caption("All pipeline runs captured in `traces/trace.jsonl` on the server.")

    try:
        resp = requests.get(f"{BASE_URL}/traces", params={"limit": 50}, timeout=10)
    except requests.ConnectionError:
        st.error(
            f"Cannot reach the review server at `{BASE_URL}`. "
            "Start it with `uvicorn server:app --reload`."
        )
        return
    except requests.Timeout:
        st.error("Timed out fetching trace history.")
        return

    if resp.status_code != 200:
        st.error(f"Server returned {resp.status_code} for /traces.")
        return

    data = resp.json()
    runs = data.get("runs", [])
    total = data.get("total", 0)
    rpd = data.get("rpd", {})
    cache_savings = data.get("cache_savings", {})

    if not runs:
        st.info("No runs recorded yet. Run a review first.")
        return

    st.caption(f"Showing {len(runs)} of {total} total run(s).")

    # --- Summary metrics ---
    col1, col2, col3, col4 = st.columns(4)
    avg_issues = sum(r.get("review_issues") or 0 for r in runs) / len(runs)
    avg_dur    = sum(r.get("duration_s") or 0 for r in runs) / len(runs)
    ok_runs    = sum(1 for r in runs if r.get("status") == "ok")
    col1.metric("Total runs shown", len(runs))
    col2.metric("Success rate", f"{ok_runs / len(runs) * 100:.0f}%")
    col3.metric("Avg issues / run", f"{avg_issues:.1f}")
    col4.metric("Avg duration", f"{avg_dur:.1f} s")

    # --- Reliability metrics (cache / fallback / quota) ---
    total_llm_calls = sum(r.get("llm_calls") or 0 for r in runs)
    total_cache_hits = sum(r.get("cache_hits") or 0 for r in runs)
    total_fallbacks = sum(r.get("fallback_used_count") or 0 for r in runs)
    cache_hit_rate = (total_cache_hits / total_llm_calls * 100) if total_llm_calls else 0.0
    fallback_rate  = (total_fallbacks / total_llm_calls * 100) if total_llm_calls else 0.0

    col5, col6, col7 = st.columns(3)
    col5.metric("LLM calls shown", total_llm_calls)
    col6.metric("Cache hit rate", f"{cache_hit_rate:.0f}%")
    col7.metric("Fallback rate", f"{fallback_rate:.0f}%")

    st.markdown("**Gemini quota**")
    _render_rpd_bar(rpd)

    st.divider()

    # --- Cache savings (project-wide, exact vs. semantic broken out) ---
    st.markdown("**Cache savings** — how much each caching layer is contributing")
    st.caption(
        "Computed project-wide across the whole trace file (not just the runs shown "
        "above), so exact-match and semantic hit rates stay comparable across "
        "however many runs are on screen."
    )
    exact_hits = cache_savings.get("exact_cache_hits", 0)
    semantic_hits = cache_savings.get("semantic_cache_hits", 0)
    hit_rate_pct = cache_savings.get("hit_rate_pct", 0.0)
    embed_calls_total = cache_savings.get("embed_calls", 0)
    net_saved = cache_savings.get("net_calls_saved", 0)
    tokens_saved = cache_savings.get("estimated_tokens_saved", 0)

    sc1, sc2, sc3, sc4 = st.columns(4)
    sc1.metric("Overall hit rate", f"{hit_rate_pct:.0f}%")
    sc2.metric("Exact-match hits", exact_hits)
    sc3.metric("Semantic hits", semantic_hits)
    sc4.metric("Est. tokens saved", f"{tokens_saved:,}")
    st.caption(
        f"Semantic layer cost {embed_calls_total} embedding call(s) to run — "
        f"**net {net_saved} call(s) saved** (hits minus embedding overhead). "
        "Tokens-saved is an estimate (average tokens per real call × hit count), "
        "since a cache hit means no generate_content call was made, so there's no "
        "usage_metadata for that specific call."
    )

    st.divider()

    # --- Charts ---
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("**Issues found per run**")
        chart_data = {
            r.get("run_id", "?")[:8]: r.get("review_issues") or 0
            for r in runs
        }
        st.bar_chart(chart_data, color="#e65100")

    with chart_col2:
        st.markdown("**Duration per run (s)**")
        dur_data = {
            r.get("run_id", "?")[:8]: round(r.get("duration_s") or 0, 1)
            for r in runs
        }
        st.bar_chart(dur_data, color="#1565c0")

    st.divider()

    # --- Run table ---
    st.markdown("**All runs**")
    for run in reversed(runs):  # most recent first
        run_id   = (run.get("run_id") or "?")[:8]
        status   = run.get("status", "?")
        repo     = run.get("repo_url") or "unknown"
        files    = run.get("files_fetched") or 0
        findings = run.get("semgrep_findings") or 0
        issues   = run.get("review_issues") or 0
        dur      = run.get("duration_s") or 0
        errors   = run.get("stage_errors") or []

        # Parse timestamp
        ts_raw = run.get("start_ts") or ""
        try:
            dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            ts = dt.strftime("%Y-%m-%d %H:%M UTC")
        except ValueError:
            ts = ts_raw[:19] if ts_raw else "?"

        icon = "✅" if status == "ok" else "❌"
        label = f"{icon} `{run_id}` &nbsp;·&nbsp; {ts} &nbsp;·&nbsp; {dur:.1f} s &nbsp;·&nbsp; {issues} issues"

        with st.expander(label, expanded=False):
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Files", files)
            c2.metric("Semgrep findings", findings)
            c3.metric("Review issues", issues)
            c4.metric("Duration", f"{dur:.1f} s")
            st.markdown(f"**Repo:** [{repo}]({repo})")

            llm_calls = run.get("llm_calls") or 0
            cache_hits = run.get("cache_hits") or 0
            exact_hits = run.get("exact_cache_hits") or 0
            semantic_hits = run.get("semantic_cache_hits") or 0
            embed_calls = run.get("embed_calls") or 0
            fallback_used = run.get("fallback_used_count") or 0
            tokens = run.get("total_tokens") or 0

            call_word     = "call" if llm_calls == 1 else "calls"
            hit_word      = "hit" if cache_hits == 1 else "hits"
            fallback_word = "fallback" if fallback_used == 1 else "fallbacks"
            reliability_line = f"{llm_calls} LLM {call_word} · {cache_hits} cache {hit_word}"
            if cache_hits:
                reliability_line += f" ({exact_hits} exact, {semantic_hits} semantic)"
            reliability_line += f" · {fallback_used} {fallback_word}"
            if embed_calls:
                reliability_line += f" · {embed_calls} embed call(s)"
            if tokens:
                reliability_line += f" · {tokens:,} tokens"
            st.caption(reliability_line)

            if errors:
                st.warning(f"Stage errors: {', '.join(errors)}")


# ---------------------------------------------------------------------------
# Page layout
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="AI Code Review Agent",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 AI Code Review Agent")
st.caption(
    f"GitHub → Semgrep → Gemini &nbsp;·&nbsp; "
    f"API: `{BASE_URL}` &nbsp;·&nbsp; "
    f"timeout: {_SERVER_TIMEOUT} s"
)

st.divider()

tab_review, tab_history = st.tabs(["▶ Review", "📊 History"])

# ---------------------------------------------------------------------------
# Tab 1 — Review
# ---------------------------------------------------------------------------

with tab_review:
    with st.form("review_form"):
        repo_url = st.text_input(
            "GitHub repository URL",
            placeholder="https://github.com/owner/repo",
            help="Must be a public (or token-accessible) github.com repository.",
        )
        col_branch, col_files = st.columns([1, 2])
        branch    = col_branch.text_input("Branch", value="main")
        max_files = col_files.slider(
            "Max files to review",
            min_value=1, max_value=500, value=100,
            help="Caps how many Python files are fetched. Lower = faster on free-tier quotas.",
        )
        submitted = st.form_submit_button("Run Review ▶", type="primary", use_container_width=True)

    if submitted:
        url = repo_url.strip()

        if not url:
            st.error("Repository URL is required.")
        elif not url.startswith("https://github.com/"):
            st.error(
                "URL must start with `https://github.com/` — "
                "for example: `https://github.com/owner/repo`"
            )
        else:
            with st.spinner("Reviewing… this typically takes 10–60 s depending on repo size."):
                try:
                    resp = requests.post(
                        f"{BASE_URL}/analyze",
                        json={
                            "repo_url":  url,
                            "branch":    branch.strip() or "main",
                            "max_files": max_files,
                        },
                        timeout=REQUEST_TIMEOUT,
                    )

                    if resp.status_code == 200:
                        # Stashed in session_state (rather than rendered
                        # immediately) so the result survives the rerun
                        # Streamlit triggers on every later widget click —
                        # e.g. ticking an issue's "include in fix" checkbox
                        # or clicking "Generate fixes" below.
                        st.session_state["last_analysis"] = {
                            "data": resp.json(),
                            "repo_url": url,
                            "branch": branch.strip() or "main",
                        }
                        # A fresh review invalidates any patches generated
                        # against a previous one.
                        st.session_state["remediation_result"] = None
                    else:
                        st.session_state["last_analysis"] = None
                        try:
                            detail = resp.json().get("detail", resp.text)
                        except Exception:
                            detail = resp.text

                        base_msg = _HTTP_MESSAGES.get(
                            resp.status_code,
                            f"Server returned {resp.status_code}",
                        )
                        if resp.status_code in (422,) or resp.status_code not in _HTTP_MESSAGES:
                            st.error(f"{base_msg}: {detail}")
                        else:
                            st.error(base_msg)

                except requests.ConnectionError:
                    st.session_state["last_analysis"] = None
                    st.error(
                        f"Cannot reach the review server at `{BASE_URL}`. "
                        f"Make sure it is running:\n\n"
                        f"```\nuvicorn server:app --reload\n```"
                    )
                except requests.Timeout:
                    st.session_state["last_analysis"] = None
                    st.error(
                        "The request timed out on the client side. "
                        "The pipeline may still be running on the server. "
                        "Try reducing **max_files** or increase `AGENT_TIMEOUT_S` on the server."
                    )

    last_analysis = st.session_state.get("last_analysis")
    if last_analysis:
        _render_results(last_analysis["data"], last_analysis["repo_url"], last_analysis["branch"])

# ---------------------------------------------------------------------------
# Tab 2 — History
# ---------------------------------------------------------------------------

with tab_history:
    _render_history()
