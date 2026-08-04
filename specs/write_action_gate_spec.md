# Spec: Write-Action Security Hardening

**Project:** AI Code Review Agent
**Modules:** `report_generator.py` (path confinement), `agent.py` (confirmation gate, tool wiring)
**Version:** 1.0
**Status:** Draft

---

## 1. Purpose

An earlier investigation (write-action inventory) established that exactly three tools in the ADK chat graph have side effects outside the review pipeline itself: `post_pr_review_tool` (posts GitHub PR review comments), `create_issue_tool` (opens a GitHub issue), and `generate_report_file_tool` (writes a Markdown file to disk at a model-supplied path). All three were previously reachable from a normal chat turn with only a natural-language instruction ("opt-in only, call when the user explicitly asks") standing between a request and the write — advisory text the model could misread or a crafted prompt could talk it past. This spec covers two independent hardening changes:

- **Change 1** (`report_generator.py`): `generate_report_file_tool`'s `output_path` is confined inside a fixed output directory before it ever reaches the filesystem, rejecting absolute paths and `../` traversal rather than redirecting them.
- **Change 2** (`agent.py`): all three write tools are (a) off by default — not attached to the ADK graph at all unless explicitly enabled — and (b) when enabled, individually hard-gated by ADK 2.3's native tool-confirmation primitive, so the underlying write function cannot execute without an explicit, separately-confirmed follow-up call.

Both changes are defense-in-depth on top of, not a replacement for, the existing opt-in instruction wording and the `guardrail.py` content check that already runs on all three write paths.

---

## 2. Investigation findings that shaped this design

**2.1 — `main.py` never reaches any of the three write tools.** The CLI entry point calls `agent.review_repo()` and `report_generator.write_report()` directly; it never builds the ADK graph or calls any `make_*_tool` factory. The only place the ADK graph is constructed is `agent.py`'s own module-level `root_agent = build_multi_agent_system(...)`, which `adk web` loads. A CLI flag on `main.py` would gate a code path that doesn't exist — the off-by-default control instead lives as a `CODE_REVIEW_AGENT_ALLOW_WRITE` env var read at `root_agent` construction time, and as an `allow_write` parameter threaded through `build_multi_agent_system()`/`build_adk_agent()`.

**2.2 — ADK 2.3.0 has a native, non-advisory confirmation primitive.** `google.adk.tools.function_tool.FunctionTool.__init__` accepts `require_confirmation: bool | Callable`. Verified by reading ADK's own source and by direct empirical test against a fake `ToolContext`: a call with no `tool_context.tool_confirmation` set never invokes the wrapped function — ADK's own `FunctionTool.run_async` returns `{"error": "This tool call requires confirmation, please approve or reject."}` and records a pending confirmation via `tool_context.request_confirmation()` before `self.func` is ever reached. A follow-up call with `tool_confirmation.confirmed=False` still never invokes the function (`{"error": "This tool call is rejected."}`); only `confirmed=True` reaches it. This is enforced inside ADK itself, not by anything this project writes, and the `TOOL_CONFIRMATION` feature is `default_on=True` in the installed `google-adk==2.3.0`, so no extra feature flag is needed to activate it.

**2.3 — `post_pr_review_tool`'s own docstring contradicted its opt-in intent.** It read *"Always call this as the last step of a PR review workflow"* — the literal opposite of opt-in-only, and inconsistent with `create_issue_tool`'s already-correct wording. Fixed as part of Change 2/3 to mirror `create_issue_tool`'s pattern exactly.

**2.4 — `build_adk_agent` is a second, still-live entry point.** A simpler, single-agent (8-tool) alternative to `build_multi_agent_system`, used by `scripts/adk_demo.py` and `deploy/app/adk_demo.py`. It exposes `generate_report_file_tool` (but not the two GitHub write tools). Given the same file-write risk applies, it gets the same `allow_write` gate and `require_confirmation=True` treatment. (`deploy/app/agent.py` is a separate, independently-duplicated copy of this file for Cloud Run packaging and was out of scope for this pass — flagged, not fixed.)

---

## 3. Change 1 — Path confinement (`report_generator.py`)

### 3.1 Public interface

```python
DEFAULT_OUTPUT_DIR = "reports"

class ReportPathError(ValueError): ...

def confine_report_path(output_path: str, base_dir: str = DEFAULT_OUTPUT_DIR) -> str: ...
```

### 3.2 Behavior

- Resolves `base_dir` to an absolute, canonical path.
- Resolves `output_path`: if absolute, resolved as-is; if relative, resolved **relative to `base_dir`**, not the process's current working directory.
- Checks containment via `Path.relative_to()`; any path that would land outside `base_dir` — an absolute path pointing elsewhere, or a `../` traversal that walks back out — raises `ReportPathError` (a `ValueError` subclass) naming the rejected path and the confinement directory. The path is **rejected, not redirected**.
- Returns the resolved absolute path (guaranteed inside `base_dir`) on success.

### 3.3 Scope — deliberately not universal

`write_report()` and `main.py`'s `--out` flag are **not** touched by this function and remain able to write anywhere the local filesystem permissions allow. Both are trusted, human-operated call sites (a person running the CLI on their own machine, pointing it at their own output path) — confining them would regress a documented, intentional feature for no security benefit. `confine_report_path()` is called from exactly one place: `agent.py`'s `generate_report_file_tool`, the one call site where `output_path` is model-controlled.

---

## 4. Change 2 — Confirmation gate (`agent.py`)

### 4.1 Two independent layers

1. **Attachment gate (`allow_write`, off by default).** `build_multi_agent_system(..., allow_write: bool = False)` and `build_adk_agent(..., allow_write: bool = False)`. When `False`, the three write tools are omitted from their agents' `tools=[...]` lists entirely — the model cannot see or call a tool that was never attached. `root_agent`'s construction reads `CODE_REVIEW_AGENT_ALLOW_WRITE` (env var, unset/false by default) and passes it through. Each affected agent's instruction text is conditional on the same flag, so it doesn't reference a tool that isn't there.
2. **Per-call confirmation (`require_confirmation=True`, unconditional whenever a write tool is attached).** The `_ft()` helper used throughout `build_multi_agent_system()` takes an optional `require_confirmation: bool = False`, passed straight to `FunctionTool(...)`. Set `True` at the three write call sites (`_ft(make_post_pr_review_tool, require_confirmation=True)`, `_ft(make_create_issue_tool, require_confirmation=True)`, `_ft(make_generate_report_file_tool, require_confirmation=True)`) and on `build_adk_agent`'s flat `FunctionTool(generate_report_file_tool, require_confirmation=True)`. All other tools leave this at its default `False`.

Layer 1 answers "is write capability available in this deployment at all." Layer 2 answers "does *this specific call* actually execute" — and layer 2 holds even if a future change accidentally sets `allow_write=True` somewhere it shouldn't: an attached write tool still can't fire without a separate confirmed follow-up.

### 4.2 Why this satisfies "not prompt-only"

The gate is enforced inside ADK's own `FunctionTool.run_async`, before the wrapped function (`post_pr_review_tool`, `create_issue_tool`, or `generate_report_file_tool`'s closures, which call `agent._fetcher.post_pr_review()`, `agent._fetcher.create_review_issue()`, or `agent.save_report()` respectively) is ever invoked. A model that ignores or is talked past its own instructions still cannot make the write happen in a single turn — see `tests/test_agent.py::TestConfirmationHardBlock` for an empirical proof using a fake `ToolContext` and `assert_not_called()` on the underlying GitHub/filesystem calls.

---

## 5. Configuration

| Setting | Default | Effect |
|---|---|---|
| `CODE_REVIEW_AGENT_ALLOW_WRITE` (env var) | unset (falsy) | When truthy (`1`/`true`/`yes`/`on`, case-insensitive), `root_agent` is built with `allow_write=True` — write tools are attached to `pr_agent`/`report_agent`, still individually confirmation-gated |
| `build_multi_agent_system(allow_write=...)` / `build_adk_agent(allow_write=...)` | `False` | Programmatic equivalent, for callers that construct the graph directly (e.g. `scripts/adk_demo.py`) rather than through `root_agent` |

---

## 6. Tests

- `tests/test_agent.py::TestSaveReport` — `confine_report_path()` behavior via `generate_report_file_tool`: relative path resolves inside `reports/`, absolute path outside is rejected, `../` traversal is rejected, rejection happens before any file is written.
- `tests/test_agent.py::TestWriteActionGateWiring` — write tools absent from the built graph by default; present and `_require_confirmation is True` when `allow_write=True`; read-only tools on the same agents stay ungated either way; `build_adk_agent` gated the same way.
- `tests/test_agent.py::TestConfirmationHardBlock` — direct `FunctionTool.run_async()` calls against a fake `ToolContext`: unconfirmed and explicitly-rejected calls never reach `agent._fetcher.create_review_issue()` (`assert_not_called()`); a confirmed call does; an unconfirmed `generate_report_file_tool` call never creates the `reports/` directory.

---

## 7. Out of Scope

- `deploy/app/agent.py` / `deploy/app/adk_demo.py` — an independently-duplicated deployment copy of `build_adk_agent`, not updated in this pass.
- Rotating or auto-scoping `GITHUB_TOKEN` itself — the token's actual GitHub-side permissions are the user's responsibility to set correctly (see README's minimum-scope table); this project doesn't and can't enforce token scope at the API-call level, only avoid calling more than it needs to.
- A UI/CLI flow for actually *supplying* the confirmation (e.g. a Streamlit "Approve" button, or a second `adk web` chat turn) — this spec covers the gate mechanism only; how a given client surfaces and answers ADK's `requested_tool_confirmations` is a client-side concern outside this codebase's control (the ADK Dev UI used by `adk web` handles it natively).

---

## 8. Acceptance Criteria

- [x] `confine_report_path()` resolves relative paths inside `reports/`, rejects absolute paths and traversal, raises before any write.
- [x] `generate_report_file_tool` calls `confine_report_path()` before `agent.save_report()`.
- [x] All three write tools are absent from the ADK graph unless `allow_write=True`.
- [x] All three write tools, when attached, are wrapped with `require_confirmation=True`.
- [x] `post_pr_review_tool`'s docstring and `pr_agent`'s instruction match `create_issue_tool`'s opt-in-only wording pattern.
- [x] README's Security-by-design table reflects the actual (corrected) behavior, documents the confirmation gate, and documents minimum `GITHUB_TOKEN` scope.
- [x] Tests cover fail-closed behavior (`assert_not_called()` on the underlying write) for unconfirmed and rejected calls, and success for confirmed calls.
