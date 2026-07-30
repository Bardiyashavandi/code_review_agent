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

---

## 12. Native `response_schema` (structured output) — addendum

Day-4 addition: `_call_model` gained an optional `response_schema` parameter,
passed straight into `GenerateContentConfig` alongside `response_mime_type`
so Gemini's Python SDK (`google-genai`) constrains **generation itself** —
structurally malformed JSON becomes impossible for the calls that use it,
rather than only being caught after the fact. This is additive defense in
depth: every existing post-hoc Pydantic validation (`_parse_response`'s use
of `_ReviewResponseSchema`) is unchanged and still runs, since a schema can
constrain *shape* but not *content* — a hallucinated field value that
happens to be the right type (e.g. a fabricated `path` string) passes a
schema fine but is exactly what post-hoc validation exists to think harder
about downstream.

Confirmed locally before wiring anything in: `google-genai==2.9.0`'s schema
transformer (`google.genai._transformers.t_schema`) correctly resolves
Pydantic's `$defs`/`$ref` output for a nested `list[BaseModel]` field (an
older, now-fixed SDK limitation — see [python-genai#60](https://github.com/googleapis/python-genai/issues/60)),
so `_ReviewResponseSchema`'s existing `issues: list[_IssueSchema]` shape,
`Literal` enum field, and `Optional[str]` field all transform without error.

### 12.1 `_call_model` signature change

`response_schema: type[BaseModel] | None = None` (default `None` — every
existing call site that doesn't pass one behaves exactly as before this
parameter existed). Only takes effect when `json_mode=True`; a caller
passing both `response_schema` and `json_mode=False` gets neither
`response_mime_type` nor `response_schema` set on the config (defensive;
no current caller does this).

### 12.2 Call sites audited, and what got a schema

Every `_call_model` call site in this file was reviewed. Exactly 4 got
`response_schema` (1 pre-existing schema wired in, 3 new ones added):

| Call site | Schema | Why |
|---|---|---|
| `review()`'s per-batch loop | `_ReviewResponseSchema` (pre-existing) | Already the target of `_parse_response`'s post-hoc validation — this is the schema the task explicitly asked to wire in first. |
| `verify_patch_resolves_finding` | `_PatchVerificationSchema` (new: `resolved: bool`, `reason: str`) | Trivially simple, fully self-contained 2-field shape spelled out verbatim in `PATCH_VERIFY_SYSTEM_INSTRUCTION`. Lowest-risk addition in the file. |
| `generate_remediation_patches` | `_RemediationResponseSchema` (new, wraps `_PatchSchema`) | Produces a NEW object from scratch — patches reference input findings only by `finding_index`, never copy arbitrary upstream fields — fully specified in `REMEDIATION_SYSTEM_INSTRUCTION`, and already relied upon downstream with exactly this shape (`agent.py`'s `make_remediation_tool` docstring, `evals/cases.py`'s `rem-01` scripted patch dict). Formalizes an existing implicit contract rather than inventing a new one. |
| `generate_risk_scores` | `_RiskScoreResponseSchema` (new, wraps `_ScoredFindingSchema`) | Same reasoning as remediation patches — `scored_findings` items are newly-computed scores referencing findings by `finding_index`/`title`/`path`, not a passthrough of arbitrary upstream fields, fully specified in `RISK_SCORE_SYSTEM_INSTRUCTION`, and already relied upon by `evals/scorers.py::score_risk_ordering` with exactly this shape. |

### 12.3 Call sites deliberately left alone, and why

Every other `_call_model` call site was left unchanged:

- **The 9 specialist audit methods** (`generate_injection_audit`,
  `generate_auth_audit`, `generate_secrets_audit`, `generate_data_flow_
  analysis`, `generate_crypto_audit`, `generate_threat_model`,
  `generate_complexity_report`, `generate_test_coverage_report`,
  `generate_doc_quality_report`) **and `analyze_context`** — no existing
  Pydantic schema, and each specialist's own "finding" shape is
  heterogeneous BY DESIGN (injection findings carry `injection_type`/
  `vulnerable_code`/`attack_vector`; crypto findings carry `pattern`/
  `current_code`/`why_dangerous`; `evals/scorers.py`'s `_finding_text`
  helper exists specifically because there's no canonical finding schema
  across specialists). Their docstrings only loosely describe top-level
  keys, never full per-field types. Inventing 9+ new schemas from scratch
  for output that's genuinely loosely-structured is exactly what this task
  was scoped to avoid.
- **`map_to_owasp`, `map_to_cwe`, `deduplicate_findings`** — each has a
  fully worked-out example JSON shape in its own system instruction, but
  the finding-level items they operate on are a MERGE/mapping of
  heterogeneous upstream findings (`deduplicated_findings` explicitly needs
  to preserve `source_agents`/arbitrary original fields; `mappings` entries
  reference findings by title, not by a fixed schema). A strict schema here
  risks silently truncating specialist-specific fields at GENERATION time —
  a real behavior change, not a safety net — so these were left alone
  rather than risk that regression for a task scoped to be additive.

### 12.4 Tests

`tests/test_gemini_reviewer.py::TestResponseSchema` — `response_schema`
passthrough when given, omission when not given, no-op when
`json_mode=False`, and end-to-end wiring checks that each of the 4 call
sites above actually passes its schema into `GenerateContentConfig` (plus
one check that specialist-audit/dedup/owasp-mapping calls do NOT gain a
`response_schema`).

### 12.5 Why no live before/after eval case

A genuine before/after comparison of malformed-JSON incidence needs live,
repeated adversarial calls to be meaningful — this is inherently
probabilistic (a single run proves little either way) and would double the
API cost of any live eval run (once with the schema, once without, to have
something to compare). Per this task's own explicit fallback, unit tests
covering the passthrough/omission plumbing (12.4 above) were judged the
more reliable, honest signal to automate here, rather than a flaky/
expensive "looks better on this one run" eval case.

### 12.6 Acceptance Criteria

- [ ] All tests in `tests/test_gemini_reviewer.py` (including `TestResponseSchema`) pass with `pytest -v`
- [ ] Every `_call_model` call site NOT listed in §12.2 passes no `response_schema` and behaves identically to before this change
- [ ] `_parse_response`'s post-hoc Pydantic validation of `_ReviewResponseSchema` is unchanged and still runs on every batch
- [ ] `evals/runner.py --mode live` (if `GEMINI_API_KEY` is available) shows no regression in `schema_errors`/`GeminiResponseValidationError` incidence across the detection/false_positive/dedup/risk_scoring/prompt_injection categories
