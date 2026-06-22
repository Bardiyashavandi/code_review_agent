# AI Code Review Agent

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-83%20passing-brightgreen)
![ADK](https://img.shields.io/badge/Google%20ADK-2.0-orange)
![Cost](https://img.shields.io/badge/cost-%240-success)

**Give it a GitHub URL. Get back a prioritized, fix-it-now code review.**

Kaggle 5-Day AI Agents Capstone submission — track: **Agents for Business**.

Static analyzers find patterns but can't explain why they matter. LLMs can explain things but hallucinate when given no real grounding. This agent fetches your actual repo, runs real Semgrep static analysis on it, and hands both the code and the findings to Gemini 2.5 Flash — so every issue in the final report is backed by either a deterministic rule or a model that's actually looking at your code, never a guess.

```
                    ┌──────────────────┐
   repo URL ───────►│  github_fetcher  │── GitHub API
                    └────────┬─────────┘
                             │ Python files
                             ▼
                    ┌─────────────────┐
                    │  semgrep_runner  │── sandboxed subprocess
                    └────────┬─────────┘
                             │ files + findings
                             ▼
                    ┌─────────────────┐
                    │  gemini_reviewer │── Gemini 2.5 Flash
                    └────────┬─────────┘
                             │ structured issues
                             ▼
                    ┌─────────────────┐
                    │ report_generator │── review_report.md
                    └─────────────────┘

   agent.py orchestrates the above AND exposes it as a
   Google ADK 2.0 Agent + FunctionTool, so an LLM-driven
   agent runtime can decide on its own when to call it.
```

Only a fetch failure is treated as fatal — there's nothing to review without files. A Semgrep or Gemini hiccup is captured as a non-fatal `StageError` instead, so the pipeline always returns a usable result, degraded but never empty-handed. This isn't theoretical: during real testing, Gemini intermittently threw transient `503` errors under load, and the retry logic kept the run going without dropping it.

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

That's a real run against a real (unmodified) repository, not a cherry-picked fixture — see "Real-world verification" below.

## Quick start

```bash
git clone https://github.com/Bardiyashavandi/code-review-agent
cd code-review-agent
python3 -m pip install -r requirements.txt
pipx install semgrep   # isolated — see "Why pipx" below
```

Create a `.env` file in the project root:

```
GITHUB_TOKEN=ghp_your_token_here
GEMINI_API_KEY=your_gemini_key_here
```

Run it:

```bash
python3 main.py https://github.com/owner/repo --branch main --out review_report.md -v
```

`--max-files` caps how many Python files get reviewed for very large repos.

## How it works

The pipeline runs in three stages, each implemented as an independent, individually-tested module:

| Stage | Module | Job |
|---|---|---|
| 1. Fetch | `github_fetcher.py` | Walks the repo tree via the GitHub API, pulls every Python file, skips venvs/build noise |
| 2. Scan | `semgrep_runner.py` | Writes files into an isolated sandbox, runs Semgrep, parses JSON into typed findings |
| 3. Review | `gemini_reviewer.py` | Batches code + findings into prompts, asks Gemini 2.5 Flash for a structured, severity-ranked review |

`agent.py` orchestrates all three behind a single `CodeReviewAgent.review_repo()` call, and also exposes the same pipeline as a Google ADK 2.0 `Agent` + `FunctionTool` — so a Gemini-powered ADK agent can decide for itself, from a plain-language request, to call `review_repo_tool`. `report_generator.py` renders the result to Markdown, and `main.py` is the CLI entry point.

### Use it programmatically

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

### Use it as an ADK agent

```python
from agent import build_adk_agent

adk_agent = build_adk_agent(
    github_token=os.environ["GITHUB_TOKEN"],
    gemini_api_key=os.environ["GEMINI_API_KEY"],
)
```

Run `adk_agent` through any ADK `Runner` (e.g. `google.adk.runners.InMemoryRunner`). Given a prompt like *"review https://github.com/owner/repo and summarize the top issues,"* the model itself calls `review_repo_tool` — no manual function dispatch — receives the structured result, and writes a severity-prioritized summary. Verified directly against this project's own repository.

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

83 tests across all five modules. Every external dependency — GitHub's API, the Semgrep subprocess, the Gemini SDK — is mocked, so the suite runs in about a second with no network access or credentials.

### Real-world verification, not just mocks

A real end-to-end run (not a test fixture) fetched 25 files, ran a live Semgrep scan, called Gemini 2.5 Flash, and produced a 23-issue report in 96 seconds with genuine findings — a Flask app left in debug mode, a hardcoded mock API key, an endpoint trusting a client-supplied ID. That run also surfaced three real integration bugs no mock could have caught, all now fixed and covered by regression tests:

1. **Dependency conflict** — `google-adk` and `semgrep` pin incompatible `opentelemetry` ranges. Fixed by isolating Semgrep into its own `pipx` environment.
2. **Stale shell env var** — `python-dotenv` never overrides an already-exported variable, so an old `GEMINI_API_KEY` from a previous test silently beat the correct `.env` value.
3. **macOS symlink bug** — macOS resolves its temp dir through a `/private/...` symlink; a path comparison that worked fine on Linux raised `ValueError` on a real Mac.

### Why `pipx` for Semgrep

`google-adk` and `semgrep` pin incompatible ranges of `opentelemetry-api`/`opentelemetry-sdk` — installing both into one environment breaks one of them. `pipx` gives Semgrep its own isolated venv; `semgrep_runner.py` only ever shells out to the `semgrep` binary on `PATH`, so the isolation is invisible to the rest of the project.

## Project structure

```
code-review-agent/
├── agent.py                  # orchestrator + ADK Agent/FunctionTool
├── github_fetcher.py         # stage 1: fetch
├── semgrep_runner.py         # stage 2: scan
├── gemini_reviewer.py        # stage 3: review
├── report_generator.py       # Markdown rendering
├── main.py                   # CLI entry point
├── *_spec.md                 # spec written before each module's code
├── tests/                    # 83 tests, one file per module
├── KAGGLE_WRITEUP.md         # full capstone writeup
└── VIDEO_SCRIPT.md           # demo video script
```

## Known limitations

`--config auto` requires reaching `semgrep.dev`'s rule registry over the network; locked-down CI runners or sandboxes with restrictive egress will need a local or registry-pinned ruleset instead. Gemini occasionally returns a transient `503` under high demand — `gemini_reviewer.py` retries automatically with exponential backoff, but a sustained outage still surfaces as a non-fatal `StageError` rather than blocking the run.

## What this demonstrates

Every module started as a written spec (interface, behavior, error hierarchy, test table) before any implementation code — the `*_spec.md` files in this repo are the visible record of that. The orchestrator is a genuine Google ADK 2.0 tool, with the agent runtime itself deciding when to invoke the pipeline. No paid services are used anywhere — Semgrep's `--config auto`, Gemini, and the GitHub API are all free-tier, by hard constraint from day one.

Full writeup: [`KAGGLE_WRITEUP.md`](./KAGGLE_WRITEUP.md). Demo video script: [`VIDEO_SCRIPT.md`](./VIDEO_SCRIPT.md).

## License

MIT — see [`LICENSE`](./LICENSE).
