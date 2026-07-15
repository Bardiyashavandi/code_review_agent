<div align="center">

# AI Code Review Agent

**Give it a GitHub URL. Get back a prioritized, fix-it-now code review.**

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-107%20passing-brightgreen)
![ADK](https://img.shields.io/badge/Google%20ADK-2.3-orange)
![ADK Tools](https://img.shields.io/badge/ADK%20tools-8-blueviolet)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)
![Streamlit](https://img.shields.io/badge/Streamlit-1.45-FF4B4B)
![Cost](https://img.shields.io/badge/cost-%240-success)

Kaggle 5-Day AI Agents Capstone — track: **Agents for Business**

</div>

---

## Contents

- [The idea](#the-idea)
- [Architecture](#architecture)
- [What a run actually looks like](#what-a-run-actually-looks-like)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [HTTP API](#http-api)
- [Observability](#observability)
- [Streamlit UI](#streamlit-ui)
- [Security, by design](#security-by-design)
- [Testing](#testing)
- [Real-world verification](#real-world-verification-not-just-mocks)
- [Project structure](#project-structure)
- [Known limitations](#known-limitations)
- [License](#license)

## The idea

Static analyzers find patterns but can't explain why they matter. LLMs can explain things but hallucinate when given no real grounding. This agent closes that gap: it fetches your actual repository, runs real Semgrep static analysis on it, and hands both the code and the findings to Gemini — so every issue in the final report is backed by either a deterministic rule or a model that's actually looking at your code, never a guess.

Only a fetch failure is treated as fatal — there's nothing to review without files. A Semgrep or Gemini hiccup is captured as a non-fatal `StageError` instead, so the pipeline always returns a usable result, degraded but never empty-handed. This isn't theoretical: during real testing, Gemini intermittently threw transient `503` errors under load, and the retry logic kept the run going without dropping it.

## Architecture

```
                       ┌────────────────────┐
   repo URL ──────────►│   github_fetcher   │── GitHub API
                       └──────────┬─────────┘
                                  │ Python files
                                  ▼
                       ┌────────────────────┐
                       │   semgrep_runner   │── sandboxed subprocess
                       └──────────┬─────────┘
                                  │ files + findings
                                  ▼
                       ┌────────────────────┐
                       │   gemini_reviewer  │── Gemini Flash
                       └──────────┬─────────┘
                                  │ structured issues
                                  ▼
                       ┌────────────────────┐
                       │  report_generator  │── review_report.md
                       └────────────────────┘

   agent.py orchestrates the above AND exposes it as a
   Google ADK 2.3 Agent + FunctionTool, so an LLM-driven
   agent runtime can decide on its own when to call it.

   server.py wraps the same pipeline behind a FastAPI HTTP
   endpoint, so any service can trigger a review over the
   network with a single POST request.
```

| Stage | Module | Job |
|---|---|---|
| 1. Fetch | `github_fetcher.py` | Walks the repo tree via the GitHub API, pulls every Python file, skips venvs/build noise |
| 2. Scan | `semgrep_runner.py` | Writes files into an isolated sandbox, runs Semgrep, parses JSON into typed findings |
| 3. Review | `gemini_reviewer.py` | Batches code + findings into prompts, asks Gemini for a structured, severity-ranked review |

### The agent's tool graph

`agent.py` doesn't just run that pipeline once — it exposes **eight separate tools** to the ADK agent, all as flat siblings under the agent, so the model plans its own path through them instead of always running the whole thing:

```
                              code_review_agent
                                     |
   +---------------+---------------+----------------+----------------+
   |               |               |                |                |
review_repo_   fetch_repo_     scan_code_      generate_       get_repo_
tool           files_tool      tool            review_tool     metadata_tool
(one-shot:     (fetch only)    (Semgrep        (Gemini review  (language/size/
 fetch+scan+                    only)           only)           stars, no fetch)
 review)

   |               |               |
search_code_   explain_         generate_
in_files_tool  finding_tool     report_file_tool
(grep fetched  (deep-dive on    (save review as
 files)         one issue)       a real .md file)
```

A one-line request like *"review this repo"* collapses to a single tool call. A narrower request — *"just show me the files,"* *"find every place using eval,"* *"explain that issue further,"* *"save this as a file"* — makes the model pick (and chain) the right tool(s) itself, which is the actual point of using an agent framework instead of one big function.

## What a run actually looks like

```
$ python3 main.py https://github.com/owner/repo --branch main --out review_report.md -v

Files fetched: 25  |  Semgrep findings: 2  |  Review issues: 23  |  Duration: 96.3s

### CRITICAL
Flask Debug Mode Enabled in Production (app.py:115)
  Running with debug=True in production exposes tracebacks, environment
  variables, and an interactive debugger capable of arbitrary code execution.
  Suggested fix: set debug=False and gate it behind an environment-driven config.

Hardcoded Mock API Key (agent.py:95)
  A string matching a real credential's prefix format is hardcoded. Even
  "mock" keys risk being mistaken for real ones or copied into production.
  Suggested fix: load all keys from environment variables, never literals.
```

That's a real run against a real, unmodified repository — see [Real-world verification](#real-world-verification-not-just-mocks) below.

## Quick start

```bash
git clone https://github.com/Bardiyashavandi/code_review_agent
cd code_review_agent
python3 -m pip install -r requirements.txt
pipx install semgrep   # isolated — see "Why pipx" below
```

Create a `.env` file in the project root:

```
GITHUB_TOKEN=ghp_your_token_here
GEMINI_API_KEY=your_gemini_key_here
```

**Option 1 — CLI:**

```bash
python3 main.py https://github.com/owner/repo --branch main --out review_report.md -v
```

`--max-files` (default `10`) caps how many Python files get reviewed per run — kept conservative by default since Gemini's free tier caps requests per day; raise it if you have a higher quota.

**Option 2 — HTTP API:**

```bash
uvicorn server:app --reload
```

Then POST a repo URL to get back a structured JSON review:

```bash
curl -s -X POST http://127.0.0.1:8000/analyze \
     -H "Content-Type: application/json" \
     -d '{"repo_url": "https://github.com/owner/repo", "max_files": 10}' \
     | python3 -m json.tool
```

**Option 3 — ADK playground:**

```bash
adk web
```

Opens Google's ADK Dev UI at `http://127.0.0.1:8000` — chat with the agent directly in a browser, with a visual graph of all eight tool nodes.

**Option 4 — Streamlit UI:**

Both processes must be running at the same time — the UI calls the API server:

```bash
# Terminal 1 — API server (keep this running)
uvicorn server:app --reload

# Terminal 2 — Streamlit UI
streamlit run streamlit_app.py
```

Opens at `http://localhost:8501` — paste a GitHub URL, set branch and file limit, click **Run Review**. Results show a severity-ranked issue list, Gemini summary, and Semgrep findings. Point the UI at a different server by setting `REVIEW_API_URL` in your environment.

## How it works

`agent.py` orchestrates all three stages behind a single `CodeReviewAgent.review_repo()` call, and also exposes the same pipeline as a Google ADK 2.3 `Agent` + `FunctionTool` (via a module-level `root_agent`) — so a Gemini-powered ADK agent can decide for itself, from a plain-language request, to call `review_repo_tool`.

**Use it programmatically:**

```python
import os
from agent import CodeReviewAgent

agent = CodeReviewAgent(
    github_token=os.environ["GITHUB_TOKEN"],
    gemini_api_key=os.environ["GEMINI_API_KEY"],
)
result = agent.review_repo("https://github.com/owner/repo")
for issue in result.review_report.issues:
    print(issue.severity, issue.path, issue.title)
```

**Use it as an ADK agent** — the model decides on its own which tool(s) to call:

```python
from agent import build_adk_agent

adk_agent = build_adk_agent(
    github_token=os.environ["GITHUB_TOKEN"],
    gemini_api_key=os.environ["GEMINI_API_KEY"],
)
```

Run `adk_agent` through any ADK `Runner` (e.g. `google.adk.runners.InMemoryRunner`) — or just run `python3 adk_demo.py` for a ready-made example.

| Tool | Does |
|---|---|
| `review_repo_tool` | One-shot: fetch + scan + review a repo URL in a single call |
| `fetch_repo_files_tool` | Fetch a repo's Python files only |
| `scan_code_tool` | Run Semgrep on a given set of files only |
| `generate_review_tool` | Ask Gemini to review a given set of files (+ optional findings) only |
| `get_repo_metadata_tool` | Look up a repo's language, size, stars, default branch — no file fetch |
| `search_code_in_files_tool` | Regex/keyword search across already-fetched files |
| `explain_finding_tool` | Ask Gemini for a focused, deeper explanation of one already-known issue |
| `generate_report_file_tool` | Render an already-produced review as Markdown and save it to disk |

The agent's instructions also keep it in scope: asked something unrelated to code review, it declines and redirects rather than forcing an unrelated tool call. All of this was verified live in the ADK Dev UI playground, where the tool graph shows eight distinct nodes branching from the agent.

## HTTP API

`server.py` wraps the exact same `CodeReviewAgent.review_repo()` pipeline behind a FastAPI endpoint — no changes to internal logic, just a new way to trigger it.

**Start the server:**

```bash
uvicorn server:app --reload                        # dev, auto-reloads on save
uvicorn server:app --host 0.0.0.0 --port 8080     # prod-like
```

**Interactive docs:** `http://127.0.0.1:8000/docs` (Swagger UI, auto-generated from the Pydantic models)

**`POST /analyze`**

Request:

```json
{
  "repo_url":  "https://github.com/owner/repo",
  "branch":    "main",
  "max_files": 10
}
```

Response (200):

```json
{
  "repo_url":     "https://github.com/owner/repo",
  "duration_s":   11.1,
  "files_fetched": 5,
  "truncated":    false,
  "review": {
    "summary":        "2 issues found...",
    "model":          "gemini-3.1-flash-lite",
    "files_reviewed": 5,
    "duration_s":     1.8,
    "issues": [
      {
        "path":          "auth.py",
        "line":          42,
        "severity":      "HIGH",
        "title":         "Hardcoded secret",
        "description":   "...",
        "suggested_fix": "...",
        "rule_id":       null
      }
    ]
  },
  "scan": {
    "scanned":    5,
    "skipped":    [],
    "duration_s": 4.3,
    "findings":   []
  },
  "stage_errors": []
}
```

Error responses follow standard HTTP semantics:

| Status | Cause |
|---|---|
| `400` | Bad orchestrator/config state (`AgentError`, `ValueError`) |
| `401` | GitHub token is invalid or expired |
| `404` | Repository not found (or private, without access) |
| `429` | GitHub API rate limit hit |
| `500` | Unexpected internal error (logged server-side with full traceback) |
| `502` | GitHub API error unrelated to auth/rate-limit/not-found |
| `504` | Pipeline exceeded the timeout — try a smaller `max_files` or raise `AGENT_TIMEOUT_S` |

Request validation errors (bad `repo_url`, `max_files` outside 1–500) return FastAPI's standard `422` before the pipeline ever runs. Set `AGENT_TIMEOUT_S` in your environment to override the default 180-second limit.

**`GET /health`** — liveness check, returns `{"status": "ok"}`.

Credentials stay server-side and are never passed by the caller.

## Observability

Every pipeline run writes structured JSON spans to `traces/trace.jsonl` (appended, never overwritten). Three levels are captured: a run-level span wrapping the entire `review_repo()` call, stage-level spans for fetch / scan / review, and an LLM-call span for each Gemini request — including token counts, prompt size, retry count, and latency.

After any run, inspect it with:

```bash
python3 view_trace.py              # last full run as an indented tree
python3 view_trace.py --tail 20    # last 20 spans flat, across run boundaries
python3 view_trace.py --list       # list all run_ids with timestamps
python3 view_trace.py --run a3f1   # specific run by id prefix
```

Example tree output:

```
▶ RUN  review_repo  ✓  11.47s  run_id=a3f1c2d4
  2026-07-15 10:23:01 UTC
  repo_url:  https://github.com/owner/repo
  branch=main · max_files=10
  23 files fetched · 2 semgrep findings · 5 issues

  ├─ STAGE  fetch  ✓  1.23s
  │    files_fetched=23 · truncated=False

  ├─ STAGE  scan  ✓  4.28s
  │    scanned=23 · findings=2 · skipped=0

  ├─ STAGE  review  ✓  5.87s
  │    files_reviewed=23 · issues=5 · model=gemini-3.1-flash-lite
  │    └─ LLM  gemini_call  batch=0  ✓  1.92s
  │         prompt_chars=18234 · tokens=1205→312 (1517 total) · retries=0
  │    └─ LLM  gemini_call  batch=1  ✓  1.85s
  │         prompt_chars=15612 · tokens=1156→298 (1454 total) · retries=0

  Gemini calls today: 2 / 500  [█░░░░░░░░░░░░░░░░░░░]  1%
```

`traces/` is gitignored — it's runtime data, not source.

## Streamlit UI

`streamlit_app.py` is a browser UI that calls `server.py` over HTTP — it contains no agent logic itself. Both processes must run at the same time:

```bash
# Terminal 1 — keep running
uvicorn server:app --reload

# Terminal 2
streamlit run streamlit_app.py
```

Opens at `http://localhost:8501`.

**What you get:**

- Repo URL input with client-side validation (must be `https://github.com/...`)
- Branch and max-files controls
- Color-coded severity badges (CRITICAL → HIGH → MEDIUM → LOW) on every issue
- Each issue in an expandable card showing file, line, description, and suggested fix
- Semgrep findings expandable per-finding with the actual code snippet (`st.code`)
- Metrics row: files fetched, issues found, duration, model used
- Specific readable error messages for every failure mode — connection refused, timeout, 404, 401, 429, 504 — never a raw traceback or JSON dump

Point the UI at a remote server by setting `REVIEW_API_URL` in your environment (defaults to `http://127.0.0.1:8000`).

## Security, by design

- Every subprocess call (Semgrep) uses explicit argument lists — never `shell=True`.
- File paths from a fetched repo are validated against path traversal before touching disk.
- Semgrep's `--config` argument is allow-listed by regex against argument injection.
- Gemini's system prompt instructs the model to treat all file contents and Semgrep output as **untrusted data, not instructions** — a malicious commit containing "ignore previous instructions" can't redirect the review. Tested directly with an injected payload.
- No credentials are ever hardcoded. Both API keys load from environment variables only, and `test_secrets_never_logged` asserts a key never leaks into a log line or exception message.
- Model output is never evaluated as code or interpolated unsafely into the report — tested with an injected `__import__` payload.

## Testing

```bash
pytest -v
```

107 tests across all five modules. Every external dependency — GitHub's API, the Semgrep subprocess, the Gemini SDK — is mocked, so the suite runs in about a second with no network access or credentials.

## Real-world verification, not just mocks

A real end-to-end run (not a test fixture) fetched 25 files, ran a live Semgrep scan, called Gemini, and produced a 23-issue report in 96 seconds with genuine findings — a Flask app left in debug mode, a hardcoded mock API key, an endpoint trusting a client-supplied ID. That run also surfaced three real integration bugs no mock could have caught, all now fixed and covered by regression tests:

1. **Dependency conflict** — `google-adk` and `semgrep` pin incompatible `opentelemetry` ranges. Fixed by isolating Semgrep into its own `pipx` environment.
2. **Stale shell env var** — `python-dotenv` never overrides an already-exported variable, so an old `GEMINI_API_KEY` from a previous test silently beat the correct `.env` value. Fixed by loading `.env` with `override=True`.
3. **macOS symlink bug** — macOS resolves its temp dir through a `/private/...` symlink; a path comparison that worked fine on Linux raised `ValueError` on a real Mac.

The ADK agent was verified two ways: once via the `adk_demo.py` terminal script, and again live in Google's ADK Dev UI playground (`adk web`) — both producing the same correct tool-calling behavior. The HTTP API was verified against a real repo with a live `curl` call returning a full JSON review.

### Why `pipx` for Semgrep

`google-adk` and `semgrep` pin incompatible ranges of `opentelemetry-api`/`opentelemetry-sdk` — installing both into one environment breaks one of them. `pipx` gives Semgrep its own isolated venv; `semgrep_runner.py` only ever shells out to the `semgrep` binary on `PATH`, so the isolation is invisible to the rest of the project.

## Project structure

```
code_review_agent/
├── agent.py                  # orchestrator + ADK Agent/FunctionTool (exposes root_agent)
├── github_fetcher.py         # stage 1: fetch
├── semgrep_runner.py         # stage 2: scan
├── gemini_reviewer.py        # stage 3: review
├── report_generator.py       # Markdown rendering
├── main.py                   # CLI entry point
├── server.py                 # FastAPI HTTP wrapper (POST /analyze)
├── streamlit_app.py          # Streamlit UI (calls server.py)
├── tracing.py                # structured span tracing (writes traces/trace.jsonl)
├── view_trace.py             # CLI trace viewer (tree + flat + RPD counter)
├── adk_demo.py               # standalone ADK tool-calling demo
├── *_spec.md                 # spec written before each module's code
├── tests/                    # 107 tests, one file per module
├── KAGGLE_WRITEUP.md         # full capstone writeup
└── VIDEO_SCRIPT.md           # demo video script
```

## Known limitations

`--config auto` requires reaching `semgrep.dev`'s rule registry over the network; locked-down CI runners or sandboxes with restrictive egress will need a local or registry-pinned ruleset instead. Gemini occasionally returns a transient `503` under high demand — `gemini_reviewer.py` retries automatically with exponential backoff, but a sustained outage still surfaces as a non-fatal `StageError` rather than blocking the run. Free-tier Gemini keys also cap total requests per day (not just per minute) — `--max-files` defaults to `10` and batches include a short inter-batch delay specifically to stretch a free-tier quota further.

The HTTP server (`server.py`) runs locally and is not deployed to any cloud service — real cloud deployment would typically need a billing-enabled project, which conflicts with this project's no-paid-services constraint.

## What this demonstrates

Every module started as a written spec (interface, behavior, error hierarchy, test table) before any implementation code — the `*_spec.md` files in this repo are the visible record of that. The orchestrator is a genuine Google ADK 2.3 tool, with the agent runtime itself deciding when to invoke the pipeline and which of the eight tools to chain. The same pipeline is reachable four ways: CLI (`main.py`), HTTP API (`server.py`/FastAPI), browser chat (`adk web`/ADK Dev UI), and a visual web UI (`streamlit_app.py`/Streamlit) — all calling the same underlying `CodeReviewAgent` without duplicating any logic. Every run is fully observable: `tracing.py` emits structured JSON spans (run → stage → LLM call) to `traces/trace.jsonl`, and `view_trace.py` renders them as an annotated tree with token counts and a live Gemini RPD counter. No paid services are used anywhere — Semgrep's `--config auto`, Gemini, and the GitHub API are all free-tier, by hard constraint from day one.

Full writeup: [`KAGGLE_WRITEUP.md`](./KAGGLE_WRITEUP.md). Demo video script: [`VIDEO_SCRIPT.md`](./VIDEO_SCRIPT.md).

## License

MIT — see [`LICENSE`](./LICENSE).
