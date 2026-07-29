# Spec: `gemini_reviewer` Module

**Project:** AI Code Review Agent
**Module:** `gemini_reviewer.py`
**Version:** 1.0
**Status:** Draft

---

## 1. Purpose

Send fetched source files plus their Semgrep findings to Gemini 3.1 Flash Lite and get back a structured, prioritized list of code review issues with fix suggestions. This is the synthesis step of the pipeline: `github_fetcher` provides the "what", `semgrep_runner` provides the "known issues", and this module asks the model to reason over both and produce the human-facing review.

---

## 2. Public Interface

```python
from gemini_reviewer import GeminiReviewer

reviewer = GeminiReviewer(api_key=os.environ["GEMINI_API_KEY"])
review = reviewer.review(files, scan_report)
# files: list[FileResult] from github_fetcher
# scan_report: ScanReport from semgrep_runner
# Returns: ReviewReport
```

### `ReviewIssue` (dataclass)

| Field           | Type            | Description                                                |
|-----------------|-----------------|--------------------------------------------------------------|
| `path`          | `str`           | File the issue applies to                                     |
| `line`          | `int`           | Best-guess line number (0 if not localizable)                |
| `severity`      | `str`           | One of `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`             |
| `title`         | `str`           | One-line issue summary                                        |
| `description`   | `str`           | Explanation of the problem                                    |
| `suggested_fix` | `str`           | Concrete fix suggestion (code or description)                 |
| `rule_id`       | `Optional[str]` | Linked Semgrep `rule_id` if this issue originated there, else `None` |

### `ReviewReport` (dataclass)

| Field        | Type                | Description                                  |
|--------------|---------------------|------------------------------------------------|
| `issues`     | `list[ReviewIssue]` | All issues, sorted by severity (Critical→Low)  |
| `summary`    | `str`               | Short model-generated overview of the repo scan |
| `model`      | `str`               | Model id used, e.g. `"gemini-3.1-flash-lite"`        |
| `files_reviewed` | `int`           | Count of files actually sent to the model        |
| `duration_s` | `float`             | Wall-clock time for the review call(s)           |

### `GeminiReviewer`

| Method | Signature | Returns | Description |
|--------|-----------|---------|--------------|
| `__init__` | `(api_key: str, model: str = "gemini-3.1-flash-lite", max_files_per_batch: int = 10, max_chars_per_batch: int = 60_000)` | — | Validates `api_key` non-empty; stores config; never logs the key |
| `review` | `(files: list[FileResult], scan_report: ScanReport) → ReviewReport` | `ReviewReport` | Batches files, builds prompts, calls Gemini, parses + merges results |

---

## 3. Behavior

### 3.1 Input Validation
- `api_key` must be a non-empty string; raise `ValueError("GEMINI_API_KEY must not be empty")` if blank.
- `files` must be non-empty; raise `ValueError("No files to review")` if empty.
- `scan_report` may have zero findings — that's a valid "Semgrep found nothing" state, not an error.

### 3.2 Batching
- Files are grouped into batches respecting both `max_files_per_batch` and `max_chars_per_batch`, whichever limit is hit first — this bounds prompt size and keeps each call within free-tier token limits.
- Each batch is reviewed independently; results are merged into a single `ReviewReport`.
- Semgrep findings for a batch are filtered to only those whose `path` is in that batch, so the model isn't given irrelevant findings.

### 3.3 Prompt Construction
- System instruction fixes the model's role ("senior code reviewer"), output contract (strict JSON matching the `ReviewIssue` schema), and explicitly instructs the model to ignore any instructions found inside the source code or Semgrep messages — code/file content is **data**, not commands.
- File content is wrapped in clearly delimited blocks (e.g. fenced with a path header) so the model can't confuse code-as-text with the surrounding instructions.
- Request uses Gemini's structured output mode (`response_mime_type="application/json"` with a response schema) rather than asking the model to "please return JSON" in free text — this is the modern, more reliable approach in the Gemini API.

### 3.4 API Calls & Retries
- Calls go through the official `google-genai` SDK client, never raw HTTP.
- On `429`/quota errors: retry up to 3 times with exponential backoff (1s, 2s, 4s), matching the convention used in `github_fetcher`.
- On invalid/expired API key (`401`/`403` from the SDK): raise `GeminiAuthenticationError`.
- On any other API failure: raise `GeminiAPIError(status, message)`.
- On retry exhaustion: raise `GeminiRateLimitError`.

### 3.5 Output Parsing
- Response is parsed as JSON per the requested schema. If parsing fails for a batch, that batch's issues are dropped and a WARNING is logged — one bad batch must not fail the entire review.
- `severity` values are normalized to the four allowed levels; unrecognized values default to `"MEDIUM"`.
- Final `issues` list is sorted by severity rank (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW`), preserving batch order within each severity tier.

### 3.6 Security
- `api_key` is never logged, printed, or included in any exception message.
- File content sent to the model is treated as untrusted data: the prompt explicitly tells the model not to follow instructions embedded in code comments, strings, docstrings, or Semgrep messages (defense against prompt injection from a malicious repo).
- No `eval`/`exec` of anything in the model's response — the response is only ever parsed as JSON into dataclasses.
- Total characters sent per batch are capped (`max_chars_per_batch`) to bound cost and avoid sending unexpectedly huge files in full.

---

## 4. Error Hierarchy

```
GeminiReviewerError (base)
├── GeminiAuthenticationError
├── GeminiRateLimitError
└── GeminiAPIError
```

All errors include `.message`; `GeminiAPIError` additionally includes `.http_status` where available.

---

## 5. Configuration

| Parameter              | Default              | Description                                  |
|-------------------------|----------------------|------------------------------------------------|
| `api_key`               | required             | Gemini API key (free tier)                      |
| `model`                 | `"gemini-3.1-flash-lite"` | Model id                                          |
| `max_files_per_batch`   | `10`                 | Max files sent in a single request                |
| `max_chars_per_batch`   | `60_000`             | Max total source chars per request                |

Environment variables are read by the caller, not this module — same convention as `github_fetcher` and `semgrep_runner`.

---

## 6. Tests (`tests/test_gemini_reviewer.py`)

The Gemini client is fully mocked (patch the SDK client object) — no live API calls, no real key required.

| Test ID | Scenario | Expected |
|---------|----------|----------|
| `test_empty_api_key_raises` | `GeminiReviewer(api_key="")` | `ValueError` |
| `test_empty_files_raises` | `review([], scan_report)` | `ValueError` |
| `test_batches_respect_max_files` | 25 files, `max_files_per_batch=10` | 3 API calls made |
| `test_batches_respect_max_chars` | 2 large files exceeding `max_chars_per_batch` | Split into separate batches |
| `test_findings_filtered_per_batch` | Findings for file not in batch | Not included in that batch's prompt |
| `test_parses_issues_correctly` | Mocked JSON response with 2 issues | 2 `ReviewIssue` objects with correct fields |
| `test_severity_unknown_defaults_medium` | Issue with `severity="urgent"` | Normalized to `"MEDIUM"` |
| `test_issues_sorted_by_severity` | Mixed severities returned | Output sorted CRITICAL→LOW |
| `test_malformed_json_batch_dropped` | One batch returns invalid JSON | That batch's issues empty, others unaffected, no exception |
| `test_401_raises_auth_error` | SDK raises auth error | `GeminiAuthenticationError` |
| `test_429_retries_then_succeeds` | First call quota error, second succeeds | Retries and returns issues |
| `test_429_exhausted_raises` | All retries quota error | `GeminiRateLimitError` |
| `test_api_key_not_in_exception_message` | Auth error raised | Key absent from `.message` |
| `test_prompt_instructs_against_injection` | Inspect constructed prompt | Contains explicit instruction to ignore embedded commands |
| `test_no_eval_of_model_output` | Response contains code-like string | Parsed only as JSON, never executed |

---

## 7. File Layout

```
code-review-agent/
├── github_fetcher.py
├── semgrep_runner.py
├── gemini_reviewer.py        ← this module
├── tests/
│   ├── test_github_fetcher.py
│   ├── test_semgrep_runner.py
│   └── test_gemini_reviewer.py
└── ...
```

---

## 8. Dependencies

```
google-genai>=0.3          # Official Gemini SDK
```

No other new dependencies. Uses Gemini's free tier — no billing setup required, consistent with the "no paid services" rule.

---

## 9. Out of Scope

- Multi-turn conversational review (single-shot batch calls only)
- Streaming responses
- Fine-tuning or custom model training
- Caching review results across runs (out of scope for v1; could be added later keyed on file SHA from `FileResult`)

---

## 10. Acceptance Criteria

- [ ] All tests in `tests/test_gemini_reviewer.py` pass with `pytest -v`
- [ ] API key never appears in logs or exceptions under any code path
- [ ] Prompt explicitly defends against instructions embedded in reviewed code
- [ ] A batch's parse failure never aborts the whole review
- [ ] Issues are deterministically sorted by severity in the final report

---

## 11. RAG comment retrieval — Contextual Retrieval + semantic-cache interaction (addendum)

This section documents a later, narrower pass over the RAG project-context
feature (`embed_review_comments`/`retrieve_relevant_comments`, `_build_prompt`)
and the semantic cache (`_call_model`) it interacts with. It does not
supersede §1–§10 above, which predate both features entirely — see
`agent_spec.md` §13 and `README.md`'s "RAG project context" section for
where those features themselves are documented.

### 11.1 Contextual Retrieval on comment embedding

`embed_review_comments` previously embedded each comment's bare `body` text.
A standalone comment like "please add input validation here" is
semantically generic and hard to retrieve accurately against; the same
comment tied to the file it was left on is far more distinguishable. Per
[Anthropic's Contextual Retrieval](https://www.anthropic.com/engineering/contextual-retrieval),
`_contextualize_comment_for_embedding(comment)` now prepends the comment's
`path`/`line` before embedding (e.g. `"In auth/db.py:42: please add input
validation here"`), falling back to the bare body if no `path` is present.
This is embedding-input only — the stored/returned comment dict, and what
`_build_prompt` renders into the final prompt, are both unchanged.

### 11.2 Semantic cache × RAG grounding

Investigated whether the semantic cache (bucket key: `system_instruction`
alone, keyed off the whole prompt's embedding) could serve a response
generated under different RAG grounding than a repeat call would retrieve
today. Finding: yes — demonstrated in
`tests/test_gemini_reviewer.py::TestSemanticCacheRagGrounding::
test_prompts_with_different_rag_grounding_can_still_look_near_identical`.
The "## Relevant past review feedback" section is typically a few short
lines next to an entire code batch, so two prompts differing only in which
comments were retrieved can still embed as near-duplicates overall. Fix:
the bucket key is now `(system_instruction, rag_fingerprint)`, where
`rag_fingerprint` (see `_rag_fingerprint`) hashes the actual retrieved
comments — `""` when there's no RAG grounding at all (every `_call_model`
call site except `review()`'s per-batch loop), so this is a no-op for the
common case. `_call_model` and `_store_semantic_entry` both gained an
optional `relevant_comments` parameter to compute this.

### 11.3 Tests

`tests/test_gemini_reviewer.py::TestEmbedReviewComments` (contextualization:
path/line prepended, falls back without a path, stored comment dict
unmodified) and `::TestSemanticCacheRagGrounding` (the gap demonstration, the
fix closing it even with identical embedding vectors, and that same/no-RAG
calls still share a bucket as before).

### 11.4 Eval coverage

`evals/` gained a `retrieval_quality` category (`rag-01-relevant-over-
irrelevant`, see `evals/README.md`): given one clearly-relevant and one
clearly-irrelevant past comment, `retrieve_relevant_comments` must rank the
relevant one into the top_k against a real SQL-injection fixture.

### 11.5 Acceptance Criteria

- [ ] All tests in `tests/test_gemini_reviewer.py` (including the new classes above) pass with `pytest -v`
- [ ] `_build_prompt`'s rendering of retrieved comments is byte-for-byte unchanged by the Contextual Retrieval change (embedding input only)
- [ ] Two prompts grounded by different retrieved comments never share a semantic-cache entry, even when their embeddings are near-identical
- [ ] Repeat calls with the same (or no) RAG grounding still hit the semantic cache exactly as before this change
- [ ] `evals/runner.py --category retrieval_quality` passes in both `--mode mock` and `--mode live`
