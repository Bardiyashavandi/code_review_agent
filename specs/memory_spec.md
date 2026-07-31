# Spec: `review_memory` Module (Persistent Findings Memory)

**Project:** AI Code Review Agent
**Module:** `review_memory.py`
**Version:** 1.0
**Status:** Draft

---

## 1. Purpose

Give the agent a memory of its own past reviews. Today, `CodeReviewAgent.review_repo()` starts from zero on every call — the only existing state (the exact-match/semantic response caches in `gemini_reviewer.py`, and the `ProjectContext` cache in `agent.py`) is process-lifetime only and gone on restart, and none of it is *about* findings: caching skips re-doing identical work, RAG pulls in a repo's own conventions/past PR comments. Reviewing the same repo twice, even in two separate processes a week apart, currently looks identical both times.

`review_memory.py` adds a small, dependency-free, disk-persistent store of the *findings themselves*, keyed by `(repo_url, branch)`, so a review can answer: what's new since last time, what's still open, and what got fixed.

---

## 2. Why not ADK's own `SessionService`/`MemoryService`

Investigated per this feature's own instructions (`https://google.github.io/adk-docs/sessions/memory/`) before writing this spec. ADK ships three `MemoryService` implementations:

| Service | Persistence | Cost |
|---|---|---|
| `InMemoryMemoryService` | **None — lost on restart** | free |
| `VertexAiMemoryBankService` | Yes | requires a Google Cloud Agent Platform (Agent Engine) instance |
| `VertexAiRagMemoryService` | Yes | requires Google Cloud Knowledge Engine (RAG corpus) |

The only free option is explicitly non-persistent — it exists for prototyping, not for surviving a process restart, which is the entire point of this feature. Both persistent options are managed Google Cloud services with billing attached, which conflicts outright with this project's standing "no paid services, ever" constraint. `DatabaseSessionService` (the source of the pre-existing, currently-unwired `.adk/session.db` files from `adk web` playground runs) is a different concept again — it persists **conversation session state** (events, turn history) keyed by `(app_name, user_id, session_id)`, not structured findings keyed by `(repo_url, branch)`; bending it to this purpose would mean inventing a session-id-to-repo-branch mapping and reconstructing findings out of serialized conversation events, for no benefit over just storing the findings directly.

**Decision:** hand-roll a minimal, independent persistent store (plain JSON file, stdlib only). No new dependency, no Google Cloud requirement, and the data shape (a list of findings per `(repo_url, branch)`) matches exactly what needs to be stored — nothing generic to bend to fit.

---

## 3. Public Interface

```python
from review_memory import ReviewMemoryStore, MemoryDiff, MemorySummary

store = ReviewMemoryStore()                       # defaults to .review_memory/findings.json
store = ReviewMemoryStore(path="/custom/path.json") # tests use a tmp_path

# Look up prior findings for a (repo, branch). None if never reviewed before,
# or if the file is missing/corrupted (best-effort, never raises).
prior = store.load_snapshot(repo_url, branch)       # list[dict] | None

# Compare new findings against a prior snapshot (or None for "first review").
diff = store.diff(new_findings, prior)              # MemoryDiff

# Persist new_findings (plus the diff's counts, for recall_previous_findings_tool)
# as this (repo, branch)'s latest snapshot. Best-effort, never raises.
store.save_snapshot(repo_url, branch, new_findings, diff)
```

`new_findings` / the stored snapshot are plain dicts with the same shape as `ReviewIssue` (`path`, `line`, `severity`, `title`, `description`, `suggested_fix`, `rule_id`).

### `MemoryDiff`

```python
@dataclass
class MemoryDiff:
    new_count: int
    still_open_count: int
    resolved_count: int
    resolved: list[dict]          # findings present last time, absent now
    has_prior_history: bool       # False on a repo/branch's first-ever review
    # statuses[i] corresponds 1:1 to new_findings[i] passed into diff():
    # "new" or "still_open".
    statuses: list[str]
```

### `MemorySummary` (attached to `PipelineResult.memory`)

```python
@dataclass
class MemorySummary:
    has_prior_history: bool
    new_count: int
    still_open_count: int
    resolved_count: int
    resolved: list[dict]   # up to a handful of {path, line, title} for display
```

---

## 4. Behavior

### 4.1 Identity matching

Two findings are "the same finding" across reviews if `(path, line, identity)` match, where `identity` is:

- `rule_id` if the finding has a non-empty one (Semgrep-sourced findings and any Gemini finding that carries a stable rule id), else
- the first 16 hex chars of `sha256(title)` (LLM-only findings routinely have no `rule_id` — matching on a hash of `title` is more stable than matching on the full free-text `description`, which can reword itself slightly between calls even for the "same" finding).

This mirrors the existing `_rag_fingerprint()` pattern in `gemini_reviewer.py` (stable hash of a small tuple, truncated hex digest) rather than inventing a new hashing convention.

### 4.2 Classification

Given `new_findings` (this review's `ReviewIssue`s, as dicts) and `prior` (the last stored snapshot, or `None`):

- `prior is None` → every new finding is `"new"`, `resolved_count = 0`, `has_prior_history = False`. Identical output to a repo's first-ever review — this is the required degrade path, not a special case.
- Otherwise, for each finding in `new_findings`: `"still_open"` if its identity matches a finding in `prior`, else `"new"`.
- Any finding present in `prior` whose identity does **not** appear in `new_findings` is `resolved` — it was flagged last time and Gemini/Semgrep no longer surface it. Reported as a positive signal (count + a short list), never as an error.

### 4.3 Storage

- Format: one JSON file, default path `.review_memory/findings.json` (relative to CWD, mirroring `traces/trace.jsonl`'s convention of a plain relative data directory). Top-level shape: `{"<repo_url>::<branch>": {"reviewed_at": "<ISO8601>", "findings": [...], "last_diff": {...}}}`.
- Writes are atomic: serialize to a `.tmp` file in the same directory, then `os.replace()` over the real path — a crash mid-write can never leave a half-written, corrupt file in place of a good one.
- Reads are best-effort: a missing file, a directory that doesn't exist yet, invalid JSON, or an unexpected shape all degrade to "no prior history" (`load_snapshot` returns `None`) — logged as a warning, never raised. A memory failure must never fail or block a review.
- Writes are also best-effort in the same sense: if `save_snapshot` can't write (permissions, disk full, etc.), it logs a warning and returns — the review itself already completed and must still return its result.

### 4.4 Integration with `review_repo()`

In `agent.py`, `CodeReviewAgent.review_repo()`:

1. Before the review stage: `prior = self._memory.load_snapshot(url, branch)`.
2. After the review stage: `diff = self._memory.diff(issue_dicts, prior)`; each `ReviewIssue` in `review_report.issues` gets its `memory_status` field set from `diff.statuses` (new optional field on `ReviewIssue`, default `None`, so every existing call site/test that builds a `ReviewIssue` without it is unaffected).
3. `self._memory.save_snapshot(url, branch, issue_dicts, diff)`.
4. `PipelineResult.memory = MemorySummary(...)` built from `diff`.
5. All of the above wrapped in one `try/except Exception` — a memory-layer failure logs a warning and leaves `PipelineResult.memory = None` (and every `ReviewIssue.memory_status = None`), it never turns a successful review into a failed one.

**Scope note:** "make [the prior result] available to the review" is implemented as making it available to this post-review diff/classification step, not as additional grounding fed into the Gemini prompt itself. Feeding prior findings into the review prompt would change `review()`'s core judgment behavior and cost extra tokens for a benefit (fewer plainly-restated findings) that isn't what was asked for — the concrete ask is the new/still_open/resolved classification, which only needs the prior snapshot after the new findings exist.

### 4.5 `recall_previous_findings_tool`

New ADK `FunctionTool`, following the existing `make_*_tool(agent)` factory convention in `agent.py`:

```python
def recall_previous_findings_tool(repo_url: str, branch: str = "main") -> dict:
    """Look up the last stored review of this repo/branch without running a
    new review. Returns {"has_history": False} if none exists."""
```

Reads the stored snapshot's `last_diff` (already computed and persisted by the last `review_repo()` run for that `(repo_url, branch)` — nothing is recomputed) and returns it directly: `{"has_history", "reviewed_at", "total_findings", "new_since_previous", "still_open", "resolved_since_previous", "resolved_examples"}`. Wired onto `report_agent` (the agent already responsible for summarizing/presenting review output to the user in chat mode — see `agent_spec.md` §2/§7) alongside its existing tools, so a user can ask "what changed since the last review of this repo" in the ADK playground without triggering a full re-review.

---

## 5. Error Hierarchy

No new exception types. `ReviewMemoryStore` never raises out of `load_snapshot`/`save_snapshot`/`diff` — every failure mode (missing file, corrupt JSON, unwritable directory, unexpected shape) is caught internally and logged, matching this repo's existing "best-effort, log and continue" convention used by `CodeReviewAgent.build_project_context()` and `_embed()`.

---

## 6. Configuration

- `ReviewMemoryStore(path: str | os.PathLike = DEFAULT_MEMORY_PATH)` — `DEFAULT_MEMORY_PATH = ".review_memory/findings.json"`. `CodeReviewAgent.__init__` accepts an optional `memory_path` passthrough (defaults to `DEFAULT_MEMORY_PATH`) so tests and deployments can redirect it without an environment variable.
- No new environment variables, no new third-party dependency (`json`, `hashlib`, `os`, `pathlib`, `dataclasses` — all stdlib).

---

## 7. Tests (`tests/test_review_memory.py`)

- Round trip: `save_snapshot` then `load_snapshot` returns the same findings back.
- First-ever review: `diff(findings, None)` → all `"new"`, `resolved_count == 0`, `has_prior_history is False`.
- Still-open: a finding with the same `(path, line, rule_id)` in both snapshots → `"still_open"`.
- New: a finding absent from the prior snapshot → `"new"`.
- Resolved: a finding present in the prior snapshot but absent from the new one → counted in `resolved`, not present in `statuses` (statuses is 1:1 with `new_findings`).
- Identity fallback: two findings with no `rule_id` but the same `title` at the same `path`/`line` are matched via the title-hash fallback.
- Corrupted file (invalid JSON on disk) → `load_snapshot` returns `None`, does not raise.
- Missing directory → `save_snapshot` creates it; a second `save_snapshot` overwrites cleanly (atomic replace, no leftover `.tmp`).
- `recall_previous_findings_tool`: no history → `{"has_history": False, ...}`; with history → fields populated from the last stored `last_diff` verbatim, no re-review triggered (mocked `CodeReviewAgent`, tool never calls `review_repo`).

Plus `agent.py` integration tests in `tests/test_agent.py`: `review_repo()` sets `memory_status` on issues and populates `PipelineResult.memory` on a second call to the same `(repo, branch)`; a memory-layer exception (patched to raise) is swallowed and still returns a normal `PipelineResult` with `memory is None`.

---

## 8. File Layout

- `review_memory.py` — `ReviewMemoryStore`, `MemoryDiff`, `MemorySummary`, `DEFAULT_MEMORY_PATH`.
- `agent.py` — `ReviewIssue.memory_status` field, `PipelineResult.memory` field, `review_repo()` wiring, `make_recall_previous_findings_tool()`, wired onto `report_agent`.
- `server.py` — `/analyze` response gains a `memory` object.
- `streamlit_app.py` — results view surfaces the new/still_open/resolved counts.
- `tests/test_review_memory.py` — new.
- `tests/test_agent.py` — extended.

---

## 9. Out of Scope

- No UI/tool to browse full history across more than the single latest snapshot per `(repo, branch)` — only the most recent snapshot is retained (overwritten each run), matching "keep storage simple" and the described new/still_open/resolved scope. A full audit trail of every past review is a natural follow-up, not built here.
- No change to `review()`'s prompt/grounding — see the scope note in §4.4.
- No cross-repo or cross-branch aggregation (e.g. "show me everything resolved this month across all repos").

---

## 10. Acceptance Criteria

- [ ] Reviewing the same `(repo_url, branch)` twice in two separate processes correctly reports the second run's new/still_open/resolved counts.
- [ ] A missing or corrupted memory file degrades silently to "first-ever review" behavior — never an exception, never a failed pipeline.
- [ ] `PipelineResult.memory`, `/analyze`'s response, and the Streamlit UI all surface the same three counts.
- [ ] `recall_previous_findings_tool` answers "what changed since the last review" from the stored snapshot alone, with no new Gemini/GitHub calls.
- [ ] Full existing test suite (275) plus new tests pass.
