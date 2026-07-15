<div align="center">

# AI Code Review Agent

**Give it a GitHub URL. Get back a prioritized, security-first code review — powered by a multi-agent LLM pipeline.**

[![Python](https://img.shields.io/badge/python-3.11%2B-3776ab?logo=python&logoColor=white)](https://python.org)
[![Google ADK](https://img.shields.io/badge/Google%20ADK-2.3-4285F4?logo=google&logoColor=white)](https://google.github.io/adk-docs/)
[![Gemini](https://img.shields.io/badge/Gemini-Flash%20Lite-8E24AA?logo=google&logoColor=white)](https://ai.google.dev)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.45-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io)
[![Tests](https://img.shields.io/badge/tests-110%20passing-22c55e?logo=pytest&logoColor=white)](./tests)
[![CI](https://github.com/Bardiyashavandi/code_review_agent/actions/workflows/ci.yml/badge.svg)](https://github.com/Bardiyashavandi/code_review_agent/actions/workflows/ci.yml)
[![Agents](https://img.shields.io/badge/agents-29-blueviolet)](#multi-agent-architecture)
[![Layers](https://img.shields.io/badge/layers-5-orange)](#multi-agent-architecture)
[![Cost](https://img.shields.io/badge/cost-%240-success)](https://ai.google.dev/pricing)

**Kaggle 5-Day AI Agents Intensive Capstone — track: Agents for Business**

<br>

![Demo](demo.gif)

</div>

---

## Contents

- [Overview](#overview)
- [Multi-Agent Architecture](#multi-agent-architecture)
- [Pipeline Internals](#pipeline-internals)
- [What a run looks like](#what-a-run-looks-like)
- [Quick Start](#quick-start)
- [HTTP API](#http-api)
- [Observability](#observability)
- [Streamlit UI](#streamlit-ui)
- [Security, by design](#security-by-design)
- [Testing](#testing)
- [Real-world verification](#real-world-verification)
- [Project structure](#project-structure)
- [Known limitations](#known-limitations)
- [What this demonstrates](#what-this-demonstrates)

---

## Overview

Static analyzers find patterns but can't explain why they matter. LLMs can explain things but hallucinate when given no real grounding. This agent closes that gap: it fetches your actual repository, runs real Semgrep static analysis on it, and hands both the code and the findings to Gemini — so every issue in the final report is backed by a deterministic rule or a model that's actually reading your code, never a guess.

The pipeline is orchestrated by a **5-layer multi-agent system** built on Google ADK 2.3. Twenty-nine specialized agents handle routing, analysis, reporting, PR review, threat modeling, dependency CVE scanning, cryptography auditing, injection detection, auth auditing, secrets scanning, taint analysis, complexity measurement, test coverage, documentation quality, OWASP/CWE compliance mapping, risk scoring, and automated remediation — each with its own narrowly scoped tool set and instructions, rather than one monolithic agent doing everything.

> **No paid services.** Semgrep `--config auto`, Gemini Flash Lite, and the GitHub API are all free-tier. Hard constraint from day one.

---

## Multi-Agent Architecture

The system is a directed graph of **29 agents** across five layers. The root orchestrator routes every user request to the right specialist or coordinator; the planner decides which domain coordinators to invoke; coordinators manage their own specialists; and sub-specialists handle the deepest, most targeted tasks.

```mermaid
flowchart TD
    subgraph L0["LAYER 0 — Root Orchestrator"]
        Root(["⭐ code_review_agent\n―――――――――――――――――――\ntool: review_repo_tool\none-shot fast path"])
    end

    subgraph L1["LAYER 1 — Strategic Agents"]
        Planner["🧠 planner_agent\nsequences L2 coordinators"]
        Context["🔭 context_agent\nframework · entry points · attack surface"]
        Scout["🔍 scout_agent\nmetadata · file list · search"]
        PR["🔀 pr_agent\nPR diff · Semgrep · post inline comments"]
        Report["📄 report_agent\nexplain findings · save Markdown"]
        Dedup["🔁 dedup_agent\nmerge cross-agent duplicates"]
        Risk["📊 risk_scorer_agent\nCVSS-like composite scoring"]
        Remed["🔧 remediation_agent\nbefore/after code patches"]
    end

    subgraph L2["LAYER 2 — Domain Coordinators"]
        SecCoord["🎯 security_coordinator\norchestrates 6 security agents"]
        QualCoord["✨ quality_coordinator\norchestrates 4 quality agents"]
        IntelCoord["🗺️ intel_coordinator\norchestrates 3 intel agents"]
    end

    subgraph L3["LAYER 3 — Specialist Agents"]
        SAST["🔒 sast_agent\nSemgrep + LLM security review"]
        Inj["💉 injection_agent\nSQL · cmd · SSTI · XSS · SSRF · path"]
        Auth["🔑 auth_agent\nIDOR · broken auth · privilege escalation"]
        Crypto["🔐 crypto_agent\nMD5 · ECB · predictable random · hardcoded keys"]
        Sec2["🔓 secrets_agent\nAPI keys · passwords · private keys"]
        DF["🌊 data_flow_agent\ntaint analysis: source → sink"]
        Qual["📐 quality_agent\ncode quality + best practices"]
        Cx["🧮 complexity_agent\ncyclomatic · nesting · god classes"]
        Test["🧪 test_agent\ncoverage gaps · missing edge cases"]
        Doc["📝 doc_agent\ndocstrings · type hints · TODO debt"]
        Dep["📦 dependency_agent\nOSV CVE scan · fix versions"]
        TM["🗡️ threat_model_agent\nSTRIDE · attack scenarios · entry points"]
        Comp["📋 compliance_agent\nOWASP Top 10 + CWE Top 25 mapping"]
    end

    subgraph L4["LAYER 4 — Sub-Specialists"]
        Val["✅ validator_agent\nflag false positives"]
        TVal["🔬 taint_validator_agent\nconfirm path reachability"]
        OWASP["🏷️ owasp_agent\nmap findings to OWASP Top 10 2021"]
        CWE["🏷️ cwe_agent\nmap findings to CWE Top 25"]
    end

    Root --> Planner & Context & Scout & PR & Report & Dedup & Risk & Remed
    Planner --> SecCoord & QualCoord & IntelCoord
    SecCoord --> SAST & Inj & Auth & Crypto & Sec2 & DF
    QualCoord --> Qual & Cx & Test & Doc
    IntelCoord --> Dep & TM & Comp
    SAST --> Val
    DF --> TVal
    Comp --> OWASP & CWE

    classDef root  fill:#1a7340,color:#fff,stroke:#0d5c2e
    classDef l1    fill:#1d3557,color:#fff,stroke:#14253d
    classDef l2    fill:#5c2a2a,color:#fff,stroke:#3d1a1a
    classDef l3    fill:#5c4200,color:#fff,stroke:#3d2c00
    classDef l4    fill:#2a2a5c,color:#fff,stroke:#1a1a3d

    class Root root
    class Planner,Context,Scout,PR,Report,Dedup,Risk,Remed l1
    class SecCoord,QualCoord,IntelCoord l2
    class SAST,Inj,Auth,Crypto,Sec2,DF,Qual,Cx,Test,Doc,Dep,TM,Comp l3
    class Val,TVal,OWASP,CWE l4
```

```
LAYER 0 ─ Root Orchestrator
┌────────────────────────────────────────────────────────────────────┐
│  code_review_agent          tool: review_repo_tool (one-shot)      │
└────────────────────────────────────────────────────────────────────┘
  │
  ├─ planner_agent      ──── routes to L2 coordinators based on intent
  ├─ context_agent      ──── framework/stack/entry-point detection
  ├─ scout_agent        ──── metadata · file list · search (no LLM)
  ├─ pr_agent           ──── PR diff review · post inline GitHub comments
  ├─ report_agent       ──── explain findings · save Markdown report
  ├─ dedup_agent        ──── merge cross-agent duplicate findings
  ├─ risk_scorer_agent  ──── CVSS-like Impact×0.4 + Exploit×0.3 + ... scoring
  └─ remediation_agent  ──── before/after code patch generation

LAYER 2 ─ Domain Coordinators (children of planner_agent)
┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│  security_coordinator│  │  quality_coordinator  │  │  intel_coordinator   │
│  ─ 6 specialists     │  │  ─ 4 specialists      │  │  ─ 3 specialists     │
└──────────────────────┘  └──────────────────────┘  └──────────────────────┘

LAYER 3 ─ Specialists
Under security_coordinator:         Under quality_coordinator:      Under intel_coordinator:
  sast_agent      (Semgrep+LLM)       quality_agent   (best practices)  dependency_agent (OSV CVEs)
  injection_agent (SQL/XSS/SSRF)      complexity_agent (cyclomatic)     threat_model_agent (STRIDE)
  auth_agent      (IDOR/broken auth)   test_agent       (coverage gaps)  compliance_agent (OWASP/CWE)
  crypto_agent    (weak algorithms)    doc_agent        (docstrings)
  secrets_agent   (hardcoded creds)
  data_flow_agent (taint analysis)

LAYER 4 ─ Sub-Specialists (innermost)
  validator_agent       ← child of sast_agent       (false-positive filter)
  taint_validator_agent ← child of data_flow_agent  (confirms path reachability)
  owasp_agent           ← child of compliance_agent (OWASP Top 10 2021 mapping)
  cwe_agent             ← child of compliance_agent (CWE Top 25 mapping)
```

### Agent roles

**Layer 0 — Root**

| Agent | Role | Tools |
|---|---|---|
| `code_review_agent` | Root orchestrator — one-shot fast path or delegates to L1 agents | `review_repo_tool` |

**Layer 1 — Strategic**

| Agent | Role | Tools |
|---|---|---|
| `planner_agent` | Sequences domain coordinators; produces consolidated executive summary | *(sub-agents: L2 coordinators)* |
| `context_agent` | Detects framework, entry points, attack surface before deeper analysis | `get_repo_metadata_tool`, `fetch_repo_files_tool`, `context_analysis_tool` |
| `scout_agent` | Lightweight metadata, file listing, pattern search — no LLM review | `get_repo_metadata_tool`, `fetch_repo_files_tool`, `search_code_in_files_tool` |
| `pr_agent` | PR diff review — fetches only changed files, runs Semgrep + LLM, can post **inline GitHub PR comments** | `fetch_pr_files_tool`, `scan_code_tool`, `generate_review_tool`, `validate_findings_tool`, `post_pr_review_tool` |
| `report_agent` | Deep-dive explanations of individual findings + saves Markdown reports | `explain_finding_tool`, `generate_report_file_tool` |
| `dedup_agent` | Merges duplicate/overlapping findings from multiple agents | `dedup_tool` |
| `risk_scorer_agent` | Assigns CVSS-like composite risk scores; ranks findings by priority | `risk_score_tool` |
| `remediation_agent` | Generates copy-pasteable before/after code patches for findings | `fetch_repo_files_tool`, `remediation_tool` |

**Layer 2 — Domain Coordinators**

| Agent | Role |
|---|---|
| `security_coordinator` | Orchestrates 6 security specialists; aggregates by severity |
| `quality_coordinator` | Orchestrates 4 quality specialists |
| `intel_coordinator` | Orchestrates 3 intel specialists (CVE, threat model, compliance) |

**Layer 3 — Specialists**

| Agent | Domain | Role | Tools |
|---|---|---|---|
| `sast_agent` | Security | Semgrep static analysis + LLM security review; delegates to `validator_agent` | `fetch_repo_files_tool`, `scan_code_tool`, `generate_review_tool`, `explain_finding_tool` |
| `injection_agent` | Security | SQL, command, SSTI, XSS, SSRF, path traversal, LDAP, XXE detection | `fetch_repo_files_tool`, `injection_audit_tool` |
| `auth_agent` | Security | Broken auth, IDOR, privilege escalation, JWT, OAuth flaws | `fetch_repo_files_tool`, `auth_audit_tool` |
| `crypto_agent` | Security | Weak hashing, ECB mode, predictable randomness, hardcoded keys, disabled TLS | `fetch_repo_files_tool`, `crypto_audit_tool` |
| `secrets_agent` | Security | Hardcoded API keys, passwords, private keys, JWT signing secrets | `fetch_repo_files_tool`, `secrets_audit_tool`, `search_code_in_files_tool` |
| `data_flow_agent` | Security | Taint analysis — traces input sources to dangerous sinks | `fetch_repo_files_tool`, `data_flow_tool` |
| `quality_agent` | Quality | Code quality, readability, Python best practices | `fetch_repo_files_tool`, `generate_review_tool`, `search_code_in_files_tool` |
| `complexity_agent` | Quality | Cyclomatic complexity, nesting depth, god classes, magic numbers | `fetch_repo_files_tool`, `complexity_tool` |
| `test_agent` | Quality | Test coverage gaps, missing edge cases, untested security-critical paths | `fetch_repo_files_tool`, `test_coverage_tool` |
| `doc_agent` | Quality | Missing docstrings, type hints, stale comments, TODO debt | `fetch_repo_files_tool`, `doc_quality_tool` |
| `dependency_agent` | Intel | OSV CVE scan on `requirements.txt` — CVE IDs, severity, fix versions | `fetch_requirements_tool`, `dependency_scan_tool` |
| `threat_model_agent` | Intel | STRIDE threat model — assets, entry points, attack scenarios | `fetch_repo_files_tool`, `threat_model_tool` |
| `compliance_agent` | Intel | Maps findings to OWASP Top 10 + CWE Top 25 via sub-agents | `owasp_mapping_tool`, `cwe_mapping_tool` |

**Layer 4 — Sub-Specialists**

| Agent | Parent | Role | Tools |
|---|---|---|---|
| `validator_agent` | `sast_agent` | Cross-checks findings against source code to flag false positives | `validate_findings_tool` |
| `taint_validator_agent` | `data_flow_agent` | Confirms taint paths are actually reachable and exploitable | `fetch_repo_files_tool`, `search_code_in_files_tool` |
| `owasp_agent` | `compliance_agent` | Maps findings to OWASP Top 10 2021 (A01–A10) | `owasp_mapping_tool` |
| `cwe_agent` | `compliance_agent` | Maps findings to CWE Top 25 Most Dangerous Weaknesses | `cwe_mapping_tool` |

### How routing works

The root agent reads the user's intent and picks a path:

```
"quick review <url>"                        →  review_repo_tool (one call, done)
"what is this repo?"                        →  scout_agent
"what framework does this use?"             →  context_agent
"security review <url>"                     →  planner_agent → security_coordinator
                                                   → sast_agent + injection_agent + auth_agent
"full deep review <url>"                    →  planner_agent → security_coordinator
                                                              → quality_coordinator
                                                              → intel_coordinator
"injection vulnerabilities"                 →  planner_agent → security_coordinator → injection_agent
"check for hardcoded credentials"           →  planner_agent → security_coordinator → secrets_agent
"data flow analysis"                        →  planner_agent → security_coordinator → data_flow_agent
                                                                → taint_validator_agent
"quality review <url>"                      →  planner_agent → quality_coordinator
"how complex is this codebase?"             →  planner_agent → quality_coordinator → complexity_agent
"test coverage gaps"                        →  planner_agent → quality_coordinator → test_agent
"OWASP compliance" / "CWE mapping"         →  planner_agent → intel_coordinator
                                                   → compliance_agent → owasp_agent + cwe_agent
"threat model this repo"                    →  planner_agent → intel_coordinator → threat_model_agent
"scan dependencies for CVEs"               →  planner_agent → intel_coordinator → dependency_agent
"review this PR: github.com/.../pull/42"   →  pr_agent
"review PR #42 and post to GitHub"         →  pr_agent → post_pr_review_tool
"deduplicate findings"                      →  dedup_agent
"risk score" / "prioritize findings"        →  risk_scorer_agent
"fix this" / "generate patches"             →  remediation_agent
"explain issue #3"                          →  report_agent
"save the report"                           →  report_agent
```

All `transfer_to_agent` calls are visible in the ADK Dev UI Traces panel in real time. A full deep review flows through up to 5 levels: root → planner → coordinator → specialist → sub-specialist.

---

## Pipeline Internals

Under every agent's tool calls, the same three-stage pipeline runs:

```
  repo URL
     │
     ▼
┌──────────────────┐      GitHub REST API
│  github_fetcher  │ ──── (tree + blob endpoints)
│                  │
│  · walks the     │
│    repo tree     │
│  · pulls Python  │
│    files only    │
│  · skips venvs,  │
│    build dirs    │
└────────┬─────────┘
         │  List[FileResult]
         ▼
┌──────────────────┐      sandboxed subprocess
│  semgrep_runner  │ ──── (pipx-isolated binary)
│                  │
│  · writes files  │
│    to a temp dir │
│  · runs semgrep  │
│    --config auto │
│  · parses JSON   │
│    findings      │
└────────┬─────────┘
         │  files + findings
         ▼
┌──────────────────┐      Gemini Flash Lite
│ gemini_reviewer  │ ──── (google-genai SDK)
│                  │
│  · batches code  │
│    + findings    │
│  · structured    │
│    JSON response │
│  · retry on 429  │
│    / 503         │
└────────┬─────────┘
         │  ReviewReport
         ▼
┌──────────────────┐
│ report_generator │ ──── review_report.md
└──────────────────┘
```

| Stage | Module | What it does |
|---|---|---|
| **Fetch** | `github_fetcher.py` | Walks the repo tree via the GitHub REST API, pulls every `.py` file, strips venv/build noise |
| **Scan** | `semgrep_runner.py` | Writes files into an isolated sandbox, runs Semgrep, parses findings into typed `Finding` objects |
| **Review** | `gemini_reviewer.py` | Batches code + findings into prompts, calls Gemini for a structured, severity-ranked `ReviewReport` |

Only a fetch failure is fatal — there's nothing to review without files. Semgrep or Gemini failures are captured as non-fatal `StageError` entries so the pipeline always returns a usable, possibly degraded, result.

---

## What a run looks like

```
$ python3 main.py https://github.com/owner/repo --branch main --out review_report.md -v

Files fetched: 25  |  Semgrep findings: 2  |  Review issues: 23  |  Duration: 96.3s

── CRITICAL ──────────────────────────────────────────────────────────
Flask Debug Mode Enabled in Production                      app.py:115
  Running with debug=True in production exposes tracebacks, environment
  variables, and an interactive debugger capable of arbitrary code execution.
  Fix: set debug=False and gate it behind an environment-driven config.

Hardcoded Mock API Key                                      agent.py:95
  A string matching a real credential's prefix format is hardcoded. Even
  "mock" keys risk being mistaken for real ones or copied into production.
  Fix: load all keys from environment variables, never literals.

── HIGH ──────────────────────────────────────────────────────────────
...
```

That's a real run against a real, unmodified repository — not a mock.

---

## Quick Start

### Prerequisites

```bash
git clone https://github.com/Bardiyashavandi/code_review_agent
cd code_review_agent
python3 -m pip install -r requirements.txt
pipx install semgrep        # isolated — avoids opentelemetry conflicts
```

> **Why `pipx`?** `google-adk` and `semgrep` pin incompatible `opentelemetry` version ranges. `pipx` gives Semgrep its own isolated venv; `semgrep_runner.py` only ever shells out to the binary on `PATH`, so the isolation is invisible to the rest of the project.

### Environment

Create a `.env` in the project root:

```env
GITHUB_TOKEN=ghp_your_token_here
GEMINI_API_KEY=your_gemini_key_here
```

Both are free. Get them at [github.com/settings/tokens](https://github.com/settings/tokens) and [aistudio.google.com](https://aistudio.google.com).

---

### Option 1 — CLI

```bash
python3 main.py https://github.com/owner/repo --branch main --out review_report.md -v
```

`--max-files` (default `10`) caps how many Python files are reviewed — kept conservative for Gemini's free-tier daily limit. Raise it if you have quota.

---

### Option 2 — ADK Playground

```bash
adk web
```

Opens Google's ADK Dev UI at `http://127.0.0.1:8000`. Chat with the 5-layer agent system directly in a browser. The graph panel shows all 29 agents and their tool connections; the Traces panel shows every agent transfer and tool call in real time.

**Example prompts to try:**

```
scout https://github.com/Bardiyashavandi/code_review_agent
security review https://github.com/Bardiyashavandi/code_review_agent
quality review https://github.com/Bardiyashavandi/code_review_agent
full deep review https://github.com/Bardiyashavandi/code_review_agent
quick review https://github.com/Bardiyashavandi/code_review_agent
review this PR: https://github.com/owner/repo/pull/42
```

---

### Option 3 — HTTP API

```bash
uvicorn server:app --reload
```

```bash
curl -s -X POST http://127.0.0.1:8000/analyze \
     -H "Content-Type: application/json" \
     -d '{"repo_url": "https://github.com/owner/repo", "max_files": 10}' \
     | python3 -m json.tool
```

---

### Option 4 — Streamlit UI

Both processes must run simultaneously — the UI calls the API server:

```bash
# Terminal 1
uvicorn server:app --reload

# Terminal 2
streamlit run streamlit_app.py
```

Opens at `http://localhost:8501`.

---

## HTTP API

`server.py` wraps `CodeReviewAgent.review_repo()` behind a FastAPI endpoint — same internal logic, different entrypoint.

**Interactive docs:** `http://127.0.0.1:8000/docs` (Swagger UI, auto-generated from Pydantic models)

### `POST /analyze`

**Request:**

```json
{
  "repo_url":  "https://github.com/owner/repo",
  "branch":    "main",
  "max_files": 10
}
```

**Response `200`:**

```json
{
  "repo_url":      "https://github.com/owner/repo",
  "duration_s":    11.1,
  "files_fetched": 5,
  "truncated":     false,
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

**Error codes:**

| Status | Cause |
|---|---|
| `400` | Bad config state (`AgentError`, `ValueError`) |
| `401` | GitHub token invalid or expired |
| `404` | Repository not found or private |
| `422` | Invalid request body (bad URL, `max_files` out of 1–500 range) |
| `429` | GitHub API rate limit hit |
| `500` | Unexpected internal error (logged server-side) |
| `502` | GitHub API error unrelated to auth/rate-limit/not-found |
| `504` | Pipeline exceeded timeout — try smaller `max_files` or raise `AGENT_TIMEOUT_S` |

### `GET /health`

```json
{ "status": "ok" }
```

Credentials stay server-side and are never passed by the caller.

---

## Observability

Every pipeline run emits structured JSON spans to `traces/trace.jsonl` (appended, never overwritten). Three levels are captured:

```
run span          ← wraps the entire review_repo() call
  └─ stage span   ← fetch / scan / review
       └─ llm_call span  ← each Gemini generate_content() call
```

Each LLM span records token counts, prompt size, retry count, and latency. The run span records files fetched, findings, issues, and total duration.

**View traces:**

```bash
python3 view_trace.py              # last full run as an indented tree
python3 view_trace.py --tail 20    # last 20 spans, flat, across runs
python3 view_trace.py --list       # all runs with timestamps and status
python3 view_trace.py --run a3f1   # specific run by id prefix
```

**Example tree:**

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

`traces/` is gitignored — runtime data, not source.

---

## Streamlit UI

`streamlit_app.py` is a browser UI that calls `server.py` over HTTP. It contains no agent logic itself.

**What you get:**

Two tabs:

**▶ Review tab**
- Repo URL input with client-side validation
- Branch and max-files controls
- Color-coded severity badges: `CRITICAL` `HIGH` `MEDIUM` `LOW`
- Expandable issue cards: file, line, description, suggested fix
- Semgrep findings with actual code snippets (`st.code`)
- Metrics row: files fetched, issues found, duration, model used
- Specific readable error messages for every failure mode — never a raw traceback

**📊 History tab**
- Summary metrics: total runs, success rate, average issues, average duration
- Bar charts: issues-per-run and duration-per-run (reads from `/traces` on the server)
- Expandable run cards with per-run metrics and stage-error warnings

Point at a remote server: `REVIEW_API_URL=https://your-server.example.com streamlit run streamlit_app.py`

---

## Security, by design

Every layer of the stack has explicit security decisions:

| Layer | Decision |
|---|---|
| **Subprocess** | All `semgrep` calls use explicit argument lists — never `shell=True` |
| **File paths** | Repo paths are validated against path traversal before touching disk |
| **Semgrep config** | `--config` argument is allow-listed by regex against argument injection |
| **Prompt injection** | Gemini's system prompt instructs the model to treat all file contents and Semgrep output as **untrusted data, not instructions** — tested with a live injected payload |
| **Credentials** | API keys load from environment variables only; `test_secrets_never_logged` asserts no key ever appears in a log line or exception message |
| **Output rendering** | Model output is never evaluated as code or interpolated unsafely into the Streamlit UI — tested with an injected `__import__` payload |

---

## Testing

```bash
pytest -v
```

107 tests across all five modules. Every external dependency — GitHub API, Semgrep subprocess, Gemini SDK — is mocked, so the full suite runs in under a second with no network access or credentials required.

---

## Real-world verification

A real end-to-end run — not a test fixture — fetched 25 files, ran a live Semgrep scan, called Gemini, and produced a 23-issue report in 96 seconds. Genuine findings: a Flask app in debug mode, a hardcoded mock API key, an endpoint trusting a client-supplied ID.

That run also surfaced three integration bugs no mock could have caught:

| Bug | Root cause | Fix |
|---|---|---|
| Dependency conflict | `google-adk` and `semgrep` pin incompatible `opentelemetry` ranges | Isolated Semgrep into `pipx` |
| Stale env var | `python-dotenv` won't override an already-exported variable | Load `.env` with `override=True` |
| macOS symlink bug | macOS resolves its temp dir through `/private/...`; path comparison that works on Linux raised `ValueError` on a real Mac | Normalize paths before comparison |

The multi-agent system was verified live in Google's ADK Dev UI playground — agent transfers visible in the Traces panel, the 5-layer graph rendered correctly with all 29 agents.

---

## Project structure

```
code_review_agent/
│
├── Core pipeline
│   ├── github_fetcher.py         # Stage 1: fetch Python files via GitHub API
│   ├── semgrep_runner.py         # Stage 2: run Semgrep, parse findings
│   ├── gemini_reviewer.py        # Stage 3: LLM review via Gemini Flash Lite
│   └── report_generator.py       # Render PipelineResult → Markdown
│
├── Orchestration
│   └── agent.py                  # CodeReviewAgent + 5-layer 29-agent ADK graph
│                                 #   (build_multi_agent_system → root_agent)
│                                 #   L0: code_review_agent
│                                 #   L1: planner · context · scout · pr · report
│                                 #       dedup · risk_scorer · remediation
│                                 #   L2: security_coordinator · quality_coordinator
│                                 #       intel_coordinator
│                                 #   L3: sast · injection · auth · crypto · secrets
│                                 #       data_flow · quality · complexity · test
│                                 #       doc · dependency · threat_model · compliance
│                                 #   L4: validator · taint_validator · owasp · cwe
│
├── Entry points
│   ├── main.py                   # CLI: python3 main.py <url>
│   ├── server.py                 # HTTP API: FastAPI, POST /analyze
│   ├── streamlit_app.py          # Browser UI: calls server.py over HTTP
│   └── adk_demo.py               # Standalone ADK tool-calling demo
│
├── Observability
│   ├── tracing.py                # Span context manager → traces/trace.jsonl
│   └── view_trace.py             # CLI viewer: tree / flat / list / RPD counter
│
├── Specs (written before code)
│   └── *_spec.md                 # Interface, behavior, error hierarchy, test table
│
└── Tests
    └── tests/                    # 110 tests, one file per module, all mocked
```

---

## Known limitations

- `--config auto` requires reaching `semgrep.dev`'s rule registry over the network; air-gapped or egress-restricted environments need a local ruleset.
- Gemini occasionally returns transient `503` errors under high demand — `gemini_reviewer.py` retries with exponential backoff, but a sustained outage surfaces as a non-fatal `StageError`.
- Free-tier Gemini keys cap total requests per day. `--max-files` defaults to `10` and batches include a short inter-batch delay specifically to stretch that quota.
- `server.py` runs locally only — cloud deployment would require a billing-enabled project, which conflicts with this project's no-paid-services constraint.

---

## What this demonstrates

**Spec-driven development.** Every module started as a written spec (interface, behavior, error hierarchy, test table) before any implementation code. The `*_spec.md` files are the visible record of that.

**Genuine multi-agent architecture.** Twenty-nine agents across five layers — root orchestrator, eight strategic agents (planner, context analyzer, scout, PR reviewer, reporter, deduplicator, risk scorer, remediation), three domain coordinators (security, quality, intel), thirteen specialists (SAST, injection, auth, crypto, secrets, data flow, quality, complexity, test coverage, documentation, dependency CVE, threat model, compliance), and four sub-specialists (findings validator, taint validator, OWASP mapper, CWE mapper). Each has a narrow role, focused instructions, and only the tools it actually needs. Agent-to-agent transfers are explicit and visible in the ADK playground. A dedicated `pr_agent` reviews only the changed files in a Pull Request and can post its findings as **inline comments directly on the GitHub PR**. The `dependency_agent` queries the free [OSV](https://osv.dev) database for known CVEs in pinned dependencies. The `data_flow_agent` traces untrusted input from entry points through to dangerous sinks, with the `taint_validator_agent` confirming path reachability. The `compliance_agent` delegates to `owasp_agent` and `cwe_agent` to map every finding to OWASP Top 10 2021 and CWE Top 25. The `risk_scorer_agent` quantifies findings with a CVSS-like composite score; the `remediation_agent` produces copy-pasteable before/after code patches.

**Four access surfaces, one pipeline.** The same `CodeReviewAgent` is reachable via CLI (`main.py`), HTTP API (`server.py`/FastAPI), browser chat (`adk web`/ADK Dev UI), and a visual web UI (`streamlit_app.py`/Streamlit) — without duplicating any logic.

**Full observability.** `tracing.py` emits structured JSON spans (run → stage → LLM call) to `traces/trace.jsonl`. `view_trace.py` renders them as an annotated tree with token counts, retries, and a live Gemini RPD counter.

**Security first, zero cost.** Semgrep `--config auto`, Gemini Flash Lite, and the GitHub API are all free-tier. No paid services, by hard constraint from day one.

Full writeup: [`KAGGLE_WRITEUP.md`](./KAGGLE_WRITEUP.md)

---

<div align="center">

MIT License — see [`LICENSE`](./LICENSE)

</div>
