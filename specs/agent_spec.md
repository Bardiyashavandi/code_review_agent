# Spec: `agent` Module (Orchestrator)

**Project:** AI Code Review Agent
**Module:** `agent.py`
**Version:** 1.0
**Status:** Draft

---

## 1. Purpose

Wire `github_fetcher`, `semgrep_runner`, and `gemini_reviewer` together as a single Google ADK 2.0 agent that takes a GitHub repo URL and produces a complete `PipelineResult`. This is the module the Kaggle capstone actually demos — everything else is a library the agent calls.

---

## 2. Public Interface

```python
from agent import CodeReviewAgent

agent = CodeReviewAgent(
    github_token=os.environ["GITHUB_TOKEN"],
    gemini_api_key=os.environ["GEMINI_API_KEY"],
)
result = agent.review_repo("https://github.com/owner/repo", branch="main")
# Returns: PipelineResult
```

### `PipelineResult` (dataclass)

| Field          | Type                  | Description                                      |
|----------------|-----------------------|----------------------------------------------------|
| `repo_url`     | `str`                 | The URL that was reviewed                          |
| `fetch_result` | `FetchResult`         | Output of `github_fetcher`                         |
| `scan_report`  | `ScanReport`          | Output of `semgrep_runner`                         |
| `review_report`| `ReviewReport`        | Output of `gemini_reviewer`                         |
| `stage_errors` | `list[StageError]`    | Non-fatal errors from any stage (see 3.3)          |
| `duration_s`   | `float`               | Total wall-clock time for the full pipeline         |

### `StageError` (dataclass)

| Field   | Type  | Description                              |
|---------|-------|--------------------------------------------|
| `stage` | `str` | `"fetch"`, `"scan"`, or `"review"`          |
| `message` | `str` | Human-readable error description          |

### `CodeReviewAgent`

| Method | Signature | Returns | Description |
|--------|-----------|---------|--------------|
| `__init__` | `(github_token: str, gemini_api_key: str, semgrep_config: str = "auto")` | — | Constructs the three underlying clients; validates both tokens non-empty |
| `review_repo` | `(url: str, branch: str = "main", max_files: int = 100) → PipelineResult` | `PipelineResult` | Runs fetch → scan → review in sequence, handling partial failures per §3.3 |

### ADK Integration

The agent is also exposed as a Google ADK `Agent` (or `LlmAgent`/`FunctionTool`, per ADK 2.0 conventions) via a single tool function:

```python
def review_repo_tool(repo_url: str, branch: str = "main") -> dict:
    """ADK-callable tool wrapping CodeReviewAgent.review_repo, returning a JSON-serializable dict."""
```

This is the function registered with the ADK agent definition so the capstone demo can be driven by natural-language requests ("review https://github.com/x/y") as well as direct calls.

---

## 3. Behavior

### 3.1 Pipeline Sequence
1. `GitHubFetcher.fetch_python_files(url, branch, max_files)` → `FetchResult`.
2. `SemgrepRunner.scan(fetch_result.files)` → `ScanReport`.
3. `GeminiReviewer.review(fetch_result.files, scan_report)` → `ReviewReport`.
4. Assemble `PipelineResult`.

### 3.2 Input Validation
- `github_token` and `gemini_api_key` must be non-empty; raise `ValueError` immediately (delegates to the underlying modules' own validation, but checked here too for a fast, clear failure before any network/process work starts).
- `url` is not pre-validated here — `GitHubFetcher.parse_repo_url` is the single source of truth for URL validation; its `ValueError` propagates unchanged.

### 3.3 Partial Failure Handling
This is the key orchestration decision: a failure in `scan` or `review` should not discard the work already done in earlier stages.

- **Fetch stage fails** (e.g. `RepoNotFoundError`, `AuthenticationError`): fatal. Re-raise immediately — there is nothing to review without files.
- **Scan stage fails** (e.g. `SemgrepNotInstalledError`, `SemgrepExecutionError`): non-fatal. Record a `StageError(stage="scan", message=...)`, continue to the review stage with an empty `ScanReport(findings=[], scanned=0, skipped=[f.path for f in files])` so Gemini still reviews the code without Semgrep context.
- **Review stage fails** (e.g. `GeminiAuthenticationError`, `GeminiRateLimitError`): non-fatal from the pipeline's perspective. Record a `StageError(stage="review", message=...)`, return a `PipelineResult` with `review_report=ReviewReport(issues=[], summary="Review unavailable: <reason>", model=<model>, files_reviewed=0)`.
- This means `review_repo` only ever raises for fetch-stage failures; everything downstream degrades gracefully and is visible via `stage_errors`.

### 3.4 Logging & Observability
- Each stage logs start/end with file counts and duration at INFO.
- No secrets (`github_token`, `gemini_api_key`) are ever logged — this module passes them straight through to the underlying clients and does not touch them otherwise.
- `PipelineResult.duration_s` covers the whole pipeline; each underlying report already carries its own stage-level `duration_s` for breakdown.

### 3.5 Security
- This module performs no I/O itself beyond delegating to the three already-hardened modules — no new attack surface should be introduced here.
- The ADK tool function (`review_repo_tool`) validates that `repo_url` is a string and delegates all real validation to `GitHubFetcher.parse_repo_url`; it does not attempt its own regex/parsing duplicate logic (single source of truth).
- The ADK tool function's return dict is built from dataclasses via explicit field mapping — never `vars()`/`__dict__` dumped wholesale — so any future field added to an internal dataclass doesn't leak into the tool's output by accident.

---

## 4. Error Hierarchy

```
AgentError (base)
└── (fetch-stage errors propagate unchanged from github_fetcher;
     scan/review-stage errors are captured as StageError, not raised)
```

`AgentError` is reserved for orchestrator-level problems only (e.g. bad constructor args), not for re-wrapping the underlying modules' own exceptions.

---

## 5. Configuration

| Parameter         | Default   | Description                                    |
|--------------------|-----------|--------------------------------------------------|
| `github_token`     | required  | Passed to `GitHubFetcher`                         |
| `gemini_api_key`   | required  | Passed to `GeminiReviewer`                         |
| `semgrep_config`   | `"auto"`  | Passed to `SemgrepRunner`                           |
| `branch`           | `"main"`  | Passed through to `fetch_python_files`              |
| `max_files`        | `100`     | Passed through to `fetch_python_files`              |

---

## 6. Tests (`tests/test_agent.py`)

`GitHubFetcher`, `SemgrepRunner`, and `GeminiReviewer` are all mocked at the `agent` module level — this module's tests verify orchestration logic only, not the underlying modules (already covered by their own suites).

| Test ID | Scenario | Expected |
|---------|----------|----------|
| `test_empty_github_token_raises` | `CodeReviewAgent(github_token="", ...)` | `ValueError` |
| `test_empty_gemini_key_raises` | `CodeReviewAgent(gemini_api_key="", ...)` | `ValueError` |
| `test_happy_path_runs_all_three_stages` | All stages succeed | `PipelineResult` has all three reports populated, `stage_errors == []` |
| `test_fetch_failure_is_fatal` | `fetch_python_files` raises `RepoNotFoundError` | Propagates unchanged out of `review_repo` |
| `test_scan_failure_is_non_fatal` | `scan` raises `SemgrepExecutionError` | `PipelineResult` returned; `stage_errors` has one `stage="scan"` entry; `review` was still called |
| `test_scan_failure_falls_back_empty_report` | `scan` raises | `review` called with a `ScanReport` whose `findings == []` |
| `test_review_failure_is_non_fatal` | `review` raises `GeminiRateLimitError` | `PipelineResult` returned; `stage_errors` has one `stage="review"` entry; `review_report.issues == []` |
| `test_both_scan_and_review_fail` | Both raise | Both stage errors recorded; pipeline still returns (doesn't raise) |
| `test_pipeline_result_has_duration` | Happy path | `duration_s > 0` (or `>= 0` with mocked instant calls) |
| `test_review_repo_tool_returns_json_serializable_dict` | ADK tool function called | `json.dumps(result)` does not raise |
| `test_review_repo_tool_does_not_leak_internal_fields` | Inspect tool output keys | Only documented keys present, no stray internal attributes |
| `test_secrets_never_logged` | Run full pipeline with `caplog` | Neither token nor API key substring appears in any log record |

---

## 7. File Layout

```
code-review-agent/
├── github_fetcher.py
├── semgrep_runner.py
├── gemini_reviewer.py
├── agent.py                  ← this module
├── tests/
│   ├── test_github_fetcher.py
│   ├── test_semgrep_runner.py
│   ├── test_gemini_reviewer.py
│   └── test_agent.py
└── ...
```

---

## 8. Dependencies

```
google-adk>=2.0          # Agent framework / tool registration
```

No other new dependencies — `agent.py` only imports the three existing project modules plus ADK.

---

## 9. Out of Scope

- Multi-repo / batch review in a single call (one `review_repo` call = one repo)
- Persisting `PipelineResult` to disk (that's the report generator's job, next module)
- Async/concurrent stage execution (stages are sequential since each depends on the previous one's output)
- ADK session/memory management beyond the single tool function — conversational state is ADK's concern, not this module's

---

## 10. Acceptance Criteria

- [ ] All tests in `tests/test_agent.py` pass with `pytest -v`
- [ ] A scan or review failure never prevents `review_repo` from returning a result
- [ ] Only a fetch failure propagates as an exception
- [ ] Neither `github_token` nor `gemini_api_key` ever appears in logs
- [ ] `review_repo_tool`'s output is valid JSON via `json.dumps`
- [ ] End-to-end manual run against `https://github.com/Bardiyashavandi/Internship` completes and returns a populated `PipelineResult`

---

## 11. `security_full_scan` — deterministic parallel full-security-review path

### 11.1 Purpose

Every agent in the ADK graph, including all three domain coordinators, was originally a plain `Agent` relying on the LLM to call `transfer_to_agent` for delegation — there was no use of ADK's deterministic workflow-agent primitives (`ParallelAgent`, `SequentialAgent`, `LoopAgent`) anywhere in `agent.py`. `security_coordinator`'s six security specialists (`sast_agent`, `injection_agent`, `auth_agent`, `crypto_agent`, `secrets_agent`, `data_flow_agent`) are fully independent — each reads repo files and audits on its own, with no dependency on another specialist's output — which is exactly the case `ParallelAgent` exists for. Previously, a "full/comprehensive security review" request was just a prompt hoping the LLM remembered to call all six specialists itself, sequentially, with no guarantee none got silently skipped.

### 11.2 Interface

```
security_full_scan = SequentialAgent(
    name="security_full_scan",
    sub_agents=[
        ParallelAgent(name="security_parallel_scan", sub_agents=[
            sast_agent_scan, injection_agent_scan, auth_agent_scan,
            crypto_agent_scan, secrets_agent_scan, data_flow_agent_scan,
        ]),
        security_aggregator_agent,
    ],
)
```

- The six `*_scan` agents are `.clone()`s of the L3 specialists (`sast_agent`, etc.), not the same instances — ADK enforces a single-parent agent tree (`BaseAgent` raises if a sub_agent already has a `parent_agent`), and the originals already belong to `security_coordinator.sub_agents` for existing single-specialist routing. Clones drop the optional `validator_agent`/`taint_validator_agent` delegation sub-agents (not needed for a deterministic full-scan pass) but keep identical tools, instructions, and `output_key`.
- Each of the six specialists (originals and clones) has `output_key` set (`sast_result`, `injection_result`, `auth_result`, `crypto_result`, `secrets_result`, `data_flow_result`), storing its final response in session state.
- `security_aggregator_agent` is a plain `Agent` with no tools; its instruction reads all six `{..._result}` state placeholders and consolidates findings by severity, stating which agents ran and how many findings each produced — deterministic aggregation over actually-collected results, not a re-analysis.
- `security_coordinator` keeps ALL existing `sub_agents` and single-specialist LLM-routing paths (`injection_agent` for "check for SQL injection", etc.) untouched; only the "full/comprehensive security review" case now routes to `security_full_scan` instead of the old six-sequential-calls prompt.

### 11.3 Tests (`tests/test_agent.py::TestSecurityFullScan`)

| Test ID | Scenario | Expected |
|---------|----------|----------|
| `test_security_coordinator_keeps_existing_specialists_and_gains_full_scan` | Build the graph | `security_coordinator.sub_agents` still includes all 6 originals plus `security_full_scan` |
| `test_security_full_scan_is_sequential_parallel_then_aggregator` | Inspect `security_full_scan` | `SequentialAgent` of `[ParallelAgent(6 clones), security_aggregator_agent]` |
| `test_parallel_scan_specialists_are_distinct_instances_from_coordinator_specialists` | Compare instances | Clones are not the same object as the originals (proves the single-parent constraint is respected) |
| `test_output_keys_set_for_state_passing_to_aggregator` | Inspect each specialist + clone | `output_key` matches the documented state key |

---

## 12. `remediation_agent` — verify-and-refine loop (LoopAgent)

### 12.1 Purpose

The original `remediation_agent` generated before/after patches in a single shot via `remediation_tool` with no check that a generated patch actually resolves the finding it targets. A loop is the right shape here — unlike, say, `sast_agent → validator_agent` (a single-pass judgment call with no new information to loop on), each patch-generation attempt CAN get new information each iteration: whether the patched code still trips the same Semgrep rule/finding. Verify-and-refine, not re-asking the same question twice.

### 12.2 Interface

```
remediation_loop = LoopAgent(
    name="remediation_agent",   # outward-facing name preserved
    sub_agents=[patch_generator_agent, patch_verifier_step],
    max_iterations=3,
    before_agent_callback=_seed_remediation_state,
)
```

- `patch_generator_agent` — does what the old `remediation_agent` did (fetch files, call `remediation_tool`, produce a patch), but its instruction also reads `{verifier_feedback}` from state so a retry addresses WHY the previous attempt failed rather than generating blind.
- `patch_verifier_step` — calls `patch_verifier_tool` (wrapping `CodeReviewAgent.verify_patch`) for each patch `patch_generator_agent` just produced. If every patch verifies resolved, it calls `exit_loop` (`tool_context.actions.escalate = True`), which the docs confirm as the current API for a `LoopAgent` sub-agent to signal early termination. If any patch is still unresolved, it writes a feedback summary to `output_key="verifier_feedback"` for the next iteration.
- `_seed_remediation_state` (`before_agent_callback`) seeds `state["verifier_feedback"] = "No prior attempts."` before iteration 1, so `patch_generator_agent`'s `{verifier_feedback}` placeholder always resolves.
- `CodeReviewAgent.verify_patch(finding, patch)`: if the finding has a Semgrep `rule_id`, re-runs `SemgrepRunner.scan()` (the same sandboxing pattern used everywhere else — isolated temp dir, explicit subprocess args, no new subprocess pattern) against just the patched code and checks whether that `rule_id` still fires. If the finding has no `rule_id` (an LLM-only finding), falls back to `GeminiReviewer.verify_patch_resolves_finding`, which reuses the existing `_call_model` path (caching, retry, tracing span) rather than a new Gemini-calling mechanism.
- Capped at `max_iterations=3`; each verifier call is its own `tracing.span("stage", "patch_verifier_iteration", ...)` so the loop's behavior is visible in `traces/trace.jsonl` / `view_trace.py`, not a black box.
- The outward-facing name `remediation_agent` is preserved (the `LoopAgent`'s own `.name` is `"remediation_agent"`) so root's `sub_agents` list and `transfer_to_agent` routing are unchanged.

### 12.3 Extending verify-and-refine beyond the ADK graph

`POST /remediate` (`server.py`) and the Streamlit fix-generation button call `CodeReviewAgent.generate_remediation_patches()` as a **direct Python method call** — this bypasses the ADK agent graph entirely, so `remediation_loop`'s `LoopAgent` behavior does not reach those two surfaces on its own. `CodeReviewAgent.generate_remediation_patches_with_verification(findings, files, max_iterations=3)` mirrors the same verify-and-refine shape for these non-ADK callers: generate once, verify every patch, regenerate only the unresolved ones (folding in why they failed via `generate_remediation_patches`' `retry_context` param), repeat up to `max_iterations`, and report `iterations_run` / `fully_resolved` / `unresolved_finding_indices` honestly if a patch never verifies clean within the cap. `server.py`'s `/remediate` route and `PatchOut`/`RemediateResponse` were updated to call this method and surface the new fields.

### 12.4 Tests

`tests/test_agent.py::TestRemediationLoop` (ADK graph shape), `::TestGenerateRemediationPatchesWithVerification` (non-ADK iterate/exit-early/give-up-honestly behavior), `::TestVerifyPatch` and `::TestPatchVerifierTool` (the shared verify step), plus `tests/test_gemini_reviewer.py::TestRemediationRetryContext` and `::TestVerifyPatchResolvesFinding`.

| Test ID | Scenario | Expected |
|---------|----------|----------|
| `test_remediation_agent_is_a_loop_of_generator_then_verifier` | Build the graph | `remediation_agent` is a `LoopAgent`, `max_iterations == 3`, sub_agents `[patch_generator_agent, patch_verifier_step]` |
| `test_root_still_transfers_to_remediation_agent_by_name` | Build the graph | `root.sub_agents` still contains an agent named `"remediation_agent"` |
| `test_clean_on_first_try_exits_after_one_iteration_not_three` | Mocked patch verifies resolved immediately | `iterations_run == 1`, `fully_resolved is True`, only 1 generation call |
| `test_still_fails_after_retries_runs_all_three_and_reports_honestly` | Mocked patch never verifies | `iterations_run == 3`, `fully_resolved is False`, `unresolved_finding_indices == [0]` |
| `test_rule_id_backed_finding_uses_semgrep_rescan_not_llm` | Finding has `rule_id` | `SemgrepRunner.scan` called, LLM fallback not called |
| `test_no_rule_id_falls_back_to_llm_judged_check` | Finding has no `rule_id` | `GeminiReviewer.verify_patch_resolves_finding` called, Semgrep not called |

### 12.5 Acceptance Criteria

- [ ] All tests in `tests/test_agent.py` (including the new classes above) and `tests/test_gemini_reviewer.py` pass with `pytest -v`
- [ ] A patch that verifies clean on the first attempt does not run all 3 iterations
- [ ] A patch that never verifies clean is reported as such (`fully_resolved: false`), never silently presented as fixed
- [ ] `/remediate` and the Streamlit fix-generation button both benefit from verify-and-refine, not just the ADK Dev UI chat path
- [ ] No new subprocess pattern introduced for patch verification (reuses `SemgrepRunner.scan`)
- [ ] No new Gemini-calling mechanism introduced for the LLM-judged fallback (reuses `GeminiReviewer._call_model`)

## 13. Trajectory verification of §11/§12 (`evals/trajectory_cases.py`)

§11.3 and §12.4 above verify `security_full_scan` and `remediation_agent` are
**constructed** correctly — right agent types, right `sub_agents`, right
clones, right `output_key`s — by inspecting `build_multi_agent_system()`'s
returned tree without running it. Neither proves the graph actually
**behaves** that way when it runs: that all 6 parallel specialists really
fire, or that `remediation_agent`'s loop really exits early / really reports
honestly on exhaustion. `evals/trajectory_cases.py` closes that gap with 3
cases that build the real ADK graph and run it via `google.adk.runners.
InMemoryRunner`, inspecting the actual event trace.

**Why this lives in `evals/`, not `tests/`:** these cases make real Gemini
(and, for one case, real GitHub) calls in `--mode live`, same as the rest of
`evals/`'s LLM-backed cases — that's an eval property (real judgment), not a
unit-test property (fully offline, always deterministic). `--mode mock`
exists purely as a harness self-test, same convention as every other
category.

**Why hand-rolled `InMemoryRunner` trace inspection instead of ADK's own
`AgentEvaluator` / `*.evalset.json` / `adk eval`:** that framework expects a
fixed on-disk module exposing `root_agent` and scores tool-call trajectory
against a hand-authored expected sequence. This repo's agent is a factory
(`build_multi_agent_system(github_token, gemini_api_key)`) needing runtime
secrets, and these 3 cases specifically need to invoke a **sub-tree**
(`security_full_scan` / `remediation_agent`) directly — bypassing root's own
LLM-driven routing decision, which is a separate, already-covered concern —
rather than the whole graph from a user-facing prompt. `InMemoryRunner` plus
direct event-trace inspection fits that need without forcing it through
evalset JSON this repo doesn't otherwise use. Full rationale, the exact 3
cases, and the two-layer mocking design (`agent.GeminiReviewer` for pipeline
judgment vs. `google.adk.models.google_llm.Gemini.generate_content_async`
for the ADK graph's own model calls) are documented in
`evals/trajectory_cases.py`'s module docstring and `evals/README.md`'s
"Trajectory cases" section — not duplicated here to avoid the two
descriptions drifting apart.

Tests for the pure-Python trace-parsing/scoring logic backing these cases:
`tests/test_trajectory_scorers.py`.

## 14. Grounded-fetch hardening for security specialist audit tools

### 14.1 Incident

A live `adk web` run against a real external repo (`review <repo_url>`,
routed through `security_full_scan`) produced a CRITICAL/HIGH-severity
report — RCE via `os.system(cmd)`, path traversal, SQL injection via
f-strings, a hardcoded `SECRET_KEY`, an unprotected `/admin` route,
reflected XSS — that was then used to open a real GitHub issue on that
repo (`create_issue_tool`, approved via the write-action gate). None of it
was real. The target repo has no `app.py` or `main.py` at all; every
finding referenced files and code that don't exist anywhere in the
repository, the local codebase, or any test fixture (confirmed by
fetching the actual repo tree and grepping this codebase for the
fabricated snippets — zero matches either way). The issue was later
deleted.

Root cause, confirmed via the session's `.adk/session.db` event log: on a
retry immediately following a cancelled first attempt and repeated Gemini
429s, 4 of the 6 parallel security specialists (`injection_agent_scan`,
`auth_agent_scan`, `secrets_agent_scan`, `data_flow_agent_scan`) skipped
their `fetch_repo_files_tool` call entirely and called their audit tool
directly with a fabricated Flask app in the `files` argument. Only
`sast_agent_scan` fetched real files that run. Nothing prevented this:
`injection_audit_tool` / `auth_audit_tool` / `secrets_audit_tool` /
`data_flow_tool` / `crypto_audit_tool` (§11.2's `*_scan` clones and their
L3 originals) all took `files: list[dict]` as a plain LLM-supplied
argument — the only link to a real fetch was a docstring sentence ("from
fetch_repo_files_tool"), not an enforced one. `security_aggregator_agent`
and `report_agent` downstream had no way to distinguish grounded output
from fabricated output; both just formatted whatever they were given.

This is a different failure mode from Wednesday/Thursday's hardening
(§§ untrusted-input-from-other-agents, blind-trust-between-handoffs): this
was the model fabricating its OWN tool-call input from training-data
patterns, not a downstream agent trusting a poisoned upstream value.
Delimiter-wrapping (this week's other fix) does nothing here — there was
no real specialist output to wrap in the first place.

### 14.2 Fix

`injection_audit_tool`, `auth_audit_tool`, `secrets_audit_tool`,
`data_flow_tool`, and `crypto_audit_tool` no longer accept `files`. Each
now takes `repo_url: str, branch: str = DEFAULT_BRANCH` and fetches the
repository itself (`agent.fetch_files(repo_url, branch=branch)`) before
calling the same underlying `agent.generate_*_audit(...)` method as
before. This makes fabricating findings structurally impossible rather
than instruction-discouraged — there is no parameter left for a model to
put invented file content into. `injection_agent`, `auth_agent`,
`crypto_agent`, and `data_flow_agent`'s instructions and `tools` lists
were updated to match (their standalone `fetch_repo_files_tool` call is
gone — the audit tool now does it in one step). `secrets_agent` keeps
`fetch_repo_files_tool` in its tool list because `search_code_in_files_tool`
(its supplementary grep pass) still needs an already-fetched `files` list;
`secrets_audit_tool` itself is grounded the same way as the other four.

As a side effect, this also reduces token usage per specialist: file
content used to flow through the model twice — once in
`fetch_repo_files_tool`'s response, once retyped into the audit tool's
`files` argument — and now flows through Python only, which helps (but
does not eliminate) the free-tier rate-limit pressure that this incident
happened under.

**Deliberately out of scope:** `scan_code_tool` and `generate_review_tool`
(used by `sast_agent` and other, more broadly-shared call sites) accept
the same style of `files: list[dict]` argument and carry the same class of
risk in principle. They were not changed here — `sast_agent` fetched
correctly in the incident, they're shared across more agents than the
five above, and Semgrep's `scan_code_tool` path is deterministic
rule-matching rather than LLM synthesis (lower-severity risk if fed bad
input). This is a real residual gap, not a claim that the whole tool
surface is now hardened — noted here rather than silently left
undocumented.

### 14.3 Tests (`tests/test_agent.py::TestGroundedFetchAuditTools`)

| Test ID | Scenario | Expected |
|---------|----------|----------|
| `test_tool_fetches_real_files_and_forwards_them_to_the_audit_call` (parametrized over all 5 tools) | Call tool with only `repo_url` | `GitHubFetcher.fetch_python_files` is actually called; the exact files it returned are what's passed to `generate_*_audit` |
| `test_tool_rejects_empty_repo_url` (parametrized) | Call with `""` | `ValueError` mentioning `repo_url` |
| `test_tool_signature_no_longer_accepts_a_files_argument` (parametrized) | Inspect signature; call with `files=...` | `files` not in the tool's parameters, `repo_url` is; calling with `files=` raises `TypeError` — the actual incident vector is gone, not just discouraged |

### 14.4 Acceptance Criteria

- [x] `injection_audit_tool`, `auth_audit_tool`, `secrets_audit_tool`, `data_flow_tool`, `crypto_audit_tool` take `repo_url`, not `files`
- [x] Each fetches its own files via `agent.fetch_files` rather than trusting a model-supplied argument
- [x] `tests/test_agent.py::TestGroundedFetchAuditTools` proves both the new behavior and that the old `files=` vector raises `TypeError`
- [x] Full `pytest` suite passes (409 passed, up from 393)
- [x] `scan_code_tool` / `generate_review_tool`'s same-class residual risk is documented, not silently left unmentioned

## 15. 429 retry-with-backoff for the ADK agent graph

### 15.1 Problem

The quota pressure behind §14's incident kept recurring after the fix
above: `security_full_scan`'s 6-way parallel fan-out (plus L4
sub-delegates like `validator_agent`/`taint_validator_agent`) can burst
past the free tier's per-minute caps within a single scan — observed
directly against `gemini-3.1-flash-lite`: 15 requests/minute
(`GenerateRequestsPerMinutePerProjectPerModel-FreeTier`) and 250,000 input
tokens/minute (`GenerateContentInputTokensPerModelPerMinute-FreeTier`),
both distinct from the daily RPD cap `main.py`'s CLI path already paces
around. A 429 hitting any one of the parallel specialists propagated
straight up through `ParallelAgent`'s `asyncio.TaskGroup` as an unhandled
`ExceptionGroup`, killing the entire scan — the user had to notice, wait,
and manually resend.

**Why `gemini_reviewer.py`'s existing retry/backoff (`_call_model()`,
`MAX_RETRIES=3`) doesn't cover this:** that mechanism is only reachable via
`CodeReviewAgent`'s own methods, called from the CLI/`server.py`/Streamlit
path. Every `Agent(model=...)` in this file previously took a bare model
name string, which ADK resolves to its own internal `google.adk.models.
Gemini` model wrapper — a Gemini call made from inside the ADK agent
graph (i.e. every `adk web` chat call) never goes through
`gemini_reviewer.py` at all. This is the same gap the "Not yet handled"
bullet in README's Known limitations already named for fallback/caching/
routing; retry-with-backoff was the same class of gap.

### 15.2 Fix

ADK's `Gemini` model class has a documented, first-class field for
exactly this: `retry_options: Optional[types.HttpRetryOptions]`, which
retries at the HTTP layer inside `google-genai`'s own client — before an
exception ever reaches ADK or this project's code. `_gemini_model()` (a
small factory near `DEFAULT_MODEL`) returns a fresh `Gemini(model=
DEFAULT_MODEL, retry_options=HttpRetryOptions(attempts=6, initial_delay=
2.0, max_delay=30.0, exp_base=2.0))` instance; every `Agent(model=...)`
call in `build_multi_agent_system()`/`build_adk_agent()` now passes
`model=_gemini_model()` instead of the bare `DEFAULT_MODEL` string. A
fresh instance per agent, not one shared object, matching ADK's own
documented `Agent(model=Gemini(...))` pattern and avoiding any shared-
mutable-state question across `ParallelAgent`'s concurrently-running
specialists.

The backoff schedule (`initial_delay=2.0`, `max_delay=30.0`, `exp_base=
2.0`, `attempts=6`) is tuned toward the per-minute reset window actually
observed in the incident's 429 responses (`retryDelay` values of roughly
16-30s) rather than the SDK's own defaults (`attempts=5`, `initial_delay=
1.0`, `max_delay=60.0`), which front-load retries too fast for a cap that
resets on a roughly 60-second cadence rather than immediately.

**Deliberately out of scope:** this does not add any caching, model
fallback, or RPD pacing to the ADK graph — only retry-with-backoff on
429/5xx, matching what was actually asked for and actually broke. The
broader "ADK graph has none of gemini_reviewer.py's resilience" gap
remains in README's Known limitations, now narrowed by one item rather
than closed entirely.

### 15.3 Tests (`tests/test_agent.py::TestGeminiRetryOptions`)

| Test ID | Scenario | Expected |
|---------|----------|----------|
| `test_gemini_model_factory_configures_retry_on_the_right_model_name` | Call `_gemini_model()` directly | Returns a `Gemini` instance with `model == DEFAULT_MODEL` and `retry_options.attempts > 1` |
| `test_gemini_model_factory_returns_a_fresh_instance_every_call` | Call `_gemini_model()` twice | Two distinct objects, not one shared instance |
| `test_agents_across_the_graph_use_the_retry_configured_model` (parametrized over root, L1, L2, L3, an aggregator, and `remediation_agent`) | Build the real graph, inspect each named agent's `.model` | Every layer's agent uses a `Gemini` instance with the same `DEFAULT_MODEL` and retry configured — not just the first agent touched |

### 15.4 Acceptance Criteria

- [x] Every `Agent(model=...)` in the graph uses `Gemini(retry_options=...)`, not a bare model string
- [x] Retry happens at the HTTP layer (ADK's own documented mechanism), not a hand-rolled wrapper duplicating `gemini_reviewer.py`'s existing logic
- [x] Each agent gets its own `Gemini` instance (verified, not just assumed)
- [x] Full `pytest` suite passes (418 passed, up from 409)
