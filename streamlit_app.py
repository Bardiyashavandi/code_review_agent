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

def _render_issues(issues: list[dict]) -> None:
    if not issues:
        st.info("No review issues found.")
        return

    sorted_issues = sorted(issues, key=_severity_rank)

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


def _render_results(data: dict) -> None:
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

    # --- Issues ---
    st.subheader(f"Issues ({len(issues)})")
    _render_issues(issues)

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
                        _render_results(resp.json())
                    else:
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
                    st.error(
                        f"Cannot reach the review server at `{BASE_URL}`. "
                        f"Make sure it is running:\n\n"
                        f"```\nuvicorn server:app --reload\n```"
                    )
                except requests.Timeout:
                    st.error(
                        "The request timed out on the client side. "
                        "The pipeline may still be running on the server. "
                        "Try reducing **max_files** or increase `AGENT_TIMEOUT_S` on the server."
                    )

# ---------------------------------------------------------------------------
# Tab 2 — History
# ---------------------------------------------------------------------------

with tab_history:
    _render_history()
