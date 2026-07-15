# AI Code Review Agent

**Track:** Agents for Business
**Project link:** https://github.com/Bardiyashavandi/code_review_agent

## The problem

Every software team has the same bottleneck: pull requests pile up faster than senior engineers can review them. Security issues — hardcoded credentials, debug flags left on in production, unsafe `eval`/`exec` calls, trusting client-supplied data — slip through not because reviewers don't know what to look for, but because manual review doesn't scale with commit volume. Static analysis tools like Semgrep catch some of this, but their output is raw, unprioritized, and rule-ID-speak that non-security engineers have to translate into "should I fix this before merging." Meanwhile, asking an LLM to "review my code" with no grounding produces plausible-sounding but unreliable feedback, because the model has no access to the actual repository or to deterministic analysis results — it's reviewing a paste, not a codebase.

This project sits in the gap between those two tools: deterministic static analysis that has no judgment, and a capable language model that has judgment but no grounding.

## The solution

The AI Code Review Agent takes a single input — a GitHub repository URL — and produces a structured, prioritized code review with concrete fix suggestions, combining static analysis with LLM judgment instead of choosing one or the other.

A root orchestrator agent (`code_review_agent`) delegates to a three-layer multi-agent pipeline:

1. **Fetch.** `scout_agent` walks the repository's file tree through the GitHub API and pulls down every Python source file, skipping virtual environments, build artifacts, and other noise that would waste review budget.
2. **Analyze.** `analysis_coordinator` routes to three Layer 2 specialist agents in parallel: `security_agent` (Semgrep + LLM security review), `quality_agent` (LLM quality review + pattern search), and `validator_agent` (cross-checks findings against source, flags false positives).
3. **Report.** `report_agent` takes the consolidated findings and renders a severity-sorted Markdown report with concrete fix suggestions. `pr_agent` handles PR diff review as a separate mode and can post findings as **inline GitHub PR comments** on the exact changed lines.
4. **Threat model.** `threat_model_agent` applies STRIDE methodology (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege) to the full codebase — identifying assets, entry points, trust boundaries, and concrete attacker scenarios with step-by-step attack paths.
5. **Dependency CVEs.** `dependency_agent` fetches `requirements.txt` and queries the free [OSV](https://osv.dev) batch API for known vulnerabilities, returning CVE IDs, severity scores, and recommended fix versions. No API key required.
6. **Cryptography audit.** `crypto_agent` inspects source files for insecure cryptographic patterns: MD5/SHA1 for passwords, Python `random` for secrets, AES-ECB mode, hardcoded IVs and keys, disabled TLS, and base64-as-encryption. Each finding includes attacker effort (seconds/minutes/hours) and a safe alternative.

The pipeline is also exposed as a FastAPI REST service (`server.py`) with a Streamlit web UI (`streamlit_app.py`) and a `/traces` endpoint for full observability of every agent run. A `review_repo_tool` wraps the pipeline so it can be invoked by an LLM-driven ADK agent runtime from a plain-language request.

Critically, the pipeline is built so a fetch failure is the only fatal failure. A Semgrep crash or a Gemini outage is captured as a non-fatal `StageError`, so the tool always returns *something* useful even in a degraded state.

## Architecture

```
LAYER 0 - Orchestrator
+-----------------------------------------------------------------------+
|  code_review_agent (root)          tool: review_repo_tool (one-shot)  |
+-----------------------------------------------------------------------+
    |          |           |           |          |           |
    v          v           v           v          v           v
LAYER 1 - Domain Specialists
+---------+ +-----------+ +----------+ +--------+ +-----------+ +----------+
|scout    | |analysis   | |report    | |pr_agent| |threat_    | |dependency|
|_agent   | |_coordinator| |_agent   | |        | |model_agent| |_agent    |
|         | |           | |          | |- PR    | |           | |          |
|-metadata| |→ Layer 2  | |- explain | |  diff  | |- STRIDE   | |- OSV CVE |
|-file    | |  security | |  findings| |- post  | |- attack   | |  query   |
|  list   | |  quality  | |- save    | |  inline| |  scenarios| |- fix     |
|-search  | |  validator| |  file    | |comments| |- entry pts| |  versions|
+---------+ +-----+-----+ +----------+ +--------+ +-----------+ +----------+
                  |
         +--------+--------+     +-----------+
         |        |        |     |crypto_    |
         v        v        v     |_agent     | ← also Layer 1
  security   quality  validator  |           |
  _agent     _agent   _agent     |-MD5/SHA1  |
                                 |-ECB mode  |
                                 |-hardcoded |
                                 |  keys     |
                                 +-----------+
```

The same pipeline is reachable four ways: as a CLI (`main.py`), as a REST API (`uvicorn server:app`), through the Streamlit web UI, and interactively through the ADK Dev UI playground. All four routes share the same agent pipeline and produce the same structured output.

## Key concepts demonstrated

**Multi-agent system (ADK).** Eleven agents across three layers, built with Google ADK 2.3. `analysis_coordinator` uses ADK's `sub_agents` mechanism to delegate to `security_agent`, `quality_agent`, and `validator_agent` — the coordinator decides which specialists to invoke and merges their findings, rather than the code dispatching directly. The root agent uses a `FunctionTool` (`review_repo_tool`) that the LLM runtime invokes based on a plain-language request, with no manual intent parsing. Three additional Layer 1 specialists handle orthogonal security concerns: `threat_model_agent` (STRIDE), `dependency_agent` (OSV CVE scan), and `crypto_agent` (cryptographic hygiene).

**Security features.** Security was treated as a first-class requirement throughout, not bolted on afterward:
- All subprocess invocations (Semgrep) use explicit argument lists — never `shell=True` — eliminating shell injection.
- Every file path from a fetched repository is validated against path traversal before being written into the Semgrep sandbox.
- Semgrep's `--config` argument is allow-listed by regex.
- The system prompt sent to Gemini explicitly instructs the model to treat all file contents as untrusted data, not instructions — prompt-injection resistance tested directly.
- No credentials are ever hardcoded. A dedicated test (`test_secrets_never_logged`) asserts authentication failures never leak the key into a log line.
- Model output is never evaluated as code or interpolated unsafely into the rendered report.

**Deployability.** Stateless pipeline, containerized-ready, exposed as both CLI and REST API. The FastAPI server can be deployed to Cloud Run or triggered by a webhook on pull-request creation without architectural changes. The `/traces` endpoint provides full observability of every agent run. CI runs on every push via GitHub Actions.

**Tracing / Observability.** Every pipeline run is recorded to `traces/trace.jsonl`. The Streamlit History tab reads this file and renders a timeline of past runs — agent name, duration, findings count — giving full visibility into what the multi-agent system did on each invocation.

## Real-world verification, not synthetic testing

A capstone project that only ever sees mocked inputs proves the code parses correctly, not that it works. So beyond the 110-test mocked suite (covering batching logic, severity sorting, error handling, and the security cases above — all running in about a second with no network access or credentials), this project was run end-to-end against a real, unmodified GitHub repository with real credentials, real network calls, and real LLM output.

A real run (visible in the demo GIF) fetched 22 Python files, ran a live Semgrep scan, sent the results through the full multi-agent pipeline, and produced a 12-issue report in 37 seconds — including genuine HIGH-severity findings like subprocess environment variable leakage and hardcoded environment dependencies. These aren't synthetic test fixtures; they're real code smells found by the actual pipeline doing its actual job.

That real run also surfaced three genuine integration bugs that the mocked test suite, by construction, could never have caught:

1. A Python dependency conflict between `google-adk` and `semgrep` over incompatible `opentelemetry` version ranges, resolved by isolating Semgrep into its own `pipx` environment.
2. A stale `GEMINI_API_KEY` exported in a shell profile silently overriding the correct key loaded from `.env` — the kind of "works on my machine" bug that synthetic tests can't surface.
3. A macOS-specific symlink-resolution bug in the Semgrep sandboxing logic: macOS resolves its temp directory through `/private/...`, and a path comparison that worked on Linux CI raised `ValueError` on a real Mac. Fixed and covered by a regression test.

All three are now fixed, documented in the README, and covered by regression tests.

## Spec-driven development

Every module started as a written specification (interface, expected behavior, error hierarchy, and a test table) before a line of implementation code was written. The specs live alongside the code in the repository (`*_spec.md` files) as a visible record of that process.

## Tech stack

Python, Google ADK 2.3 (`google-adk`), Gemini Flash Lite via `google-genai`, FastAPI + Uvicorn, Streamlit, the GitHub REST API, and Semgrep for static analysis. No paid services are used anywhere in the pipeline — all APIs are free-tier.

## Setup

```bash
git clone https://github.com/Bardiyashavandi/code_review_agent
cd code_review_agent
python3 -m pip install -r requirements.txt
pipx install semgrep   # isolated to avoid opentelemetry version conflict with google-adk
```

Create a `.env` file with `GITHUB_TOKEN` and `GOOGLE_API_KEY`, then run the CLI:

```bash
python3 main.py https://github.com/owner/repo --branch main --out review_report.md -v
```

Or start the full stack:

```bash
uvicorn server:app --reload          # API on :8000
streamlit run streamlit_app.py       # UI on :8501
```

Full setup, usage, and ADK-agent examples are in the repository's `README.md`.

## What this demonstrates

The project grew from a single-agent pipeline into an eleven-agent, three-layer system — not to check rubric boxes, but because the multi-agent design naturally maps to how a real security team would divide the work: one agent to scout the repo, specialist agents for security and quality analysis, a validator to cross-check for false positives, a threat modeler to reason about attack surfaces, a dependency scanner to check CVEs, a crypto auditor to flag insecure algorithms, and a report agent to explain findings to a human. The 110 tests, the CI pipeline, the tracing endpoint, and the three real bugs found during end-to-end testing are the evidence that this is a working system, not a demo assembled for a deadline.
