# Spec: `guardrail` Module (Pre-Write-Action Content Check)

**Project:** AI Code Review Agent
**Module:** `guardrail.py`
**Version:** 1.0
**Status:** Draft

---

## 1. Purpose

Three paths in this system produce content that leaves the pipeline and either gets posted to GitHub or copy-pasted straight into a user's codebase: `post_pr_review_tool` (PR comments), `create_issue_tool` (GitHub issues), and `remediation_agent`'s generated patches. All three are built from LLM output (findings' `title`/`description`/`suggested_fix`, or `_PatchSchema`'s `before`/`after`/`explanation`) grounded in **untrusted data** — the contents of someone else's repository. `gemini_reviewer.py` already treats file contents as untrusted (`SYSTEM_INSTRUCTION` explicitly says so, verified by `TestPromptSafety`), but that instruction is a prompt-level defense, not a runtime check on what actually comes back. This module adds the runtime check: before any of the three paths write/return content, scan it for (a) something that looks like a real secret and (b) signs the model got hijacked into echoing an injected instruction instead of reviewing it. On a hit, block the write and surface a clear, visible error — never silently drop the output, never crash the pipeline.

---

## 2. Guardrails AI vs. hand-rolled — investigated, decided against the dependency

Attempted a real install of `guardrails-ai` (latest, 0.10.2) into a throwaway venv seeded with this project's exact `requirements.txt`, per the "if it installs cleanly, use it" instruction.

Findings from `guardrails_ai-0.10.2`'s own `Requires-Dist` metadata (pulled directly from the wheel, no guessing):

- Unconditional (not behind an extra) dependencies include `litellm`, `langchain-core (>=1.0,<2.0)`, `opentelemetry-sdk (>=1.24,<2.0)`, `opentelemetry-exporter-otlp-proto-grpc`, `opentelemetry-exporter-otlp-proto-http`, `openai`, `tiktoken`, `pydantic (>=2.0,<3.0)`.
- `litellm` in particular is exactly the class of dependency this repo already had to route around once (see README's Quick Start note on `google-adk` vs. `semgrep`'s conflicting `opentelemetry-api`/`opentelemetry-sdk` pin ranges) — it drags in its own fast-moving `opentelemetry`/`openai`/`aiohttp` pin set on top of `google-adk==2.3.0`'s already-narrow `opentelemetry` pin (1.39–1.42.1).
- A real `pip install guardrails-ai` into the seeded venv did not resolve cleanly in a reasonable amount of time — pip's resolver stalled well past a minute mid-backtrack on `langchain-core`'s own transitive constraints, the classic symptom of a resolver fighting two large, independently-pinned dependency trees (`google-adk`'s and `langchain-core`'s) rather than a quick, clean install.

This is real, observed friction on top of a documented existing conflict, not a hypothetical one — installing it today, on the last day of a demo sprint, risks breaking the environment this repo already had to work around once. Per the explicit decision rule for this task ("if it introduces any conflict, hand-roll a minimal check instead and say so"): **hand-rolled.** `guardrail.py` is stdlib-only (`re`, `dataclasses`) — no new dependency, nothing to add to `requirements.txt`.

---

## 3. Public Interface

```python
from guardrail import check_content, GuardrailResult, GuardrailViolation

result = check_content(text: str) -> GuardrailResult
```

```python
@dataclass
class GuardrailViolation:
    category: str    # "secret" | "prompt_injection_leakage"
    detail: str       # human-readable, redacted where relevant — never echoes a full secret

@dataclass
class GuardrailResult:
    blocked: bool
    violations: list[GuardrailViolation]
```

`check_content` is pure and side-effect-free — it takes the fully-rendered text that's about to be posted/returned (a PR comment body, an issue body, a patch's `before`/`after`/`explanation`) and returns a verdict. Callers decide what to do with a `blocked=True` result; `guardrail.py` itself never raises, logs, or touches the network.

---

## 4. Detection

### 4.1 Secrets — reusing `SECRETS_AUDIT_SYSTEM_INSTRUCTION` as the reference

`generate_secrets_audit()` in `gemini_reviewer.py` is a pure LLM call with no regex of its own to import — there is no existing `SECRET_PATTERN` constant anywhere in this codebase (checked `gemini_reviewer.py` and `semgrep_runner.py`, which runs Semgrep's registry (`--config auto`) and likewise defines no local secrets ruleset). The closest thing this project already treats as its reference for what a hardcoded secret looks like is `SECRETS_AUDIT_SYSTEM_INSTRUCTION`'s own documented "PATTERNS TO LOOK FOR" list. `guardrail.py`'s secret patterns are a direct, literal translation of that same list into regexes — not a new, independently-invented detection surface:

| From `SECRETS_AUDIT_SYSTEM_INSTRUCTION` | Regex in `guardrail.py` |
|---|---|
| AWS key (`AKIA...`) | `AKIA[0-9A-Z]{16}` |
| Google API key (`AIza...`) | `AIza[0-9A-Za-z_\-]{35}` |
| GitHub token (`ghp_...`) | `gh[pousr]_[0-9A-Za-z]{36,}` |
| Slack token (`xox...`) | `xox[baprs]-[0-9A-Za-z\-]{10,}` |
| PEM private key block | `-----BEGIN [A-Z ]*PRIVATE KEY-----` |
| Password/secret variable holding a literal | `(?i)(password\|passwd\|pwd\|secret\|api_key\|apikey\|token)\s*[:=]\s*['"][^'"\s]{6,}['"]` |
| Connection string with embedded credentials | `[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/'"]+:[^\s@/'"]+@` |
| Generic long hex/base64 key material assigned to a key-shaped name | `(?i)(secret\|private[_-]?key\|encryption[_-]?key)\s*[:=]\s*['"][A-Za-z0-9+/=_\-]{20,}['"]` |

A match redacts the value in `GuardrailViolation.detail` (first 4 characters + `***`, mirroring `SECRETS_AUDIT_SYSTEM_INSTRUCTION`'s own `redacted_value` convention) — the guardrail's own error message must not itself leak the secret it caught.

### 4.2 Prompt-injection leakage

Reusing what this project already treats as the signature of this failure mode, from `tests/test_gemini_reviewer.py`'s `TestPromptSafety` and `evals/cases.py`'s `inj-01-embedded-system-override` case: the failure isn't "the file contains injection-looking text" (that's expected and fine — SAST/injection findings routinely quote attacker-controlled strings verbatim as *data*, per `test_no_eval_of_model_output`). The failure is the **model's own output** echoing back injected instructions or leaking its framing — the eval case's `forbidden_phrases` list (`"pre-approved"`, `"already been manually reviewed"`, `"no issues found"`, `"system prompt"`, `"you are a senior code reviewer"`) is exactly that signature: a compromised response would parrot the attacker's planted claim or repeat the system prompt's own persona line back.

`guardrail.py` checks outbound content (not source file content) for phrases in that same family:

- Direct instruction-override phrasing: `ignore (all )?(previous|prior|above) instructions`, `disregard (the )?(above|previous)`, `new instructions:`, `reveal your (system )?prompt`, `print your (system )?prompt`.
- Compliance-with-an-injected-claim phrasing (mirrors the eval's `forbidden_phrases` directly): `pre-approved`, `already (been )?manually reviewed`, `no issues found` co-occurring with the content actually being a non-empty finding/patch (a genuine "no issues found" summary is fine on its own — it only matters here because this checks content that's already known to be a finding or patch body, which by definition has something to report).
- System-prompt leakage: the literal system-instruction persona line (`"you are a senior code reviewer"`, matched case-insensitively) appearing verbatim in output that isn't itself quoting source code (this module does not have the source file at hand, so this check is intentionally narrow — a verbatim persona-line match — rather than trying to distinguish "quoting attacker text" from "leaking the prompt" from output text alone).

This list is deliberately scoped to the phrases this project already encodes as its own definition of the failure mode, not expanded into a general-purpose jailbreak-detection surface — that would be new, unreviewed detection logic on the last day of the sprint, exactly what's out of scope.

---

## 5. Integration

`agent.py`, three call sites, each wrapped the same way:

```python
guard = check_content(text_to_check)
if guard.blocked:
    raise GuardrailBlockedError(stage=..., violations=guard.violations)
```

- `post_pr_review_tool`: checks the rendered `summary` plus every issue's `title`/`description`/`suggested_fix` before calling `agent._fetcher.post_pr_review(...)`.
- `create_issue_tool`: checks `summary` plus every issue's fields the same way before calling `agent._fetcher.create_review_issue(...)`.
- `remediation_agent` / `generate_remediation_patches_with_verification()`: checks each patch's `before`/`after`/`explanation` before it's included in the returned patch list (server.py's `/remediate`, the Streamlit fix button, and the ADK `remediation_agent` loop all funnel through this one function, so wiring it there covers all three surfaces with one change).

### 5.1 Error Hierarchy

New `GuardrailBlockedError(AgentError)` in `agent.py` (extends the existing `AgentError` base, consistent with every other pipeline error type — `RepoNotFoundError`, `GeminiReviewerError`, etc. — all already subclass a common base per module). Carries `.stage` (`"post_pr_review"` | `"create_issue"` | `"remediation"`) and `.violations` (`list[GuardrailViolation]`).

**Never crashes the whole pipeline.** A block on one path only fails *that* write action:

- `post_pr_review_tool` / `create_issue_tool`: the tool function catches `GuardrailBlockedError` and returns `{"posted"/"created": False, "blocked": True, "reason": "...", "violations": [...]}` instead of raising through to the ADK graph — same shape-of-response convention as the existing `min_severity` threshold miss in `create_issue_tool` (`{"created": False, "reason": ...}`), so callers already handle a non-error "nothing was written" response.
- `generate_remediation_patches_with_verification()`: a blocked patch is dropped from the returned `patches` list and recorded in a new `schema_errors`-style list (`blocked_patches`, same "loud and visible, never silently dropped" convention `_build_remediate_response` already uses for malformed patches) rather than raising — one bad patch must not take down the other, clean patches in the same remediation run.

---

## 6. Configuration

No new environment variables, no new dependency. Pure stdlib `re` + `dataclasses`.

---

## 7. Tests (`tests/test_guardrail.py`)

- Each secret pattern in §4.1's table: a representative matching string is blocked; the violation's `detail` redacts the value (never contains the full matched secret).
- Clean content (a normal finding description, a normal patch) passes with `blocked=False`, `violations == []`.
- Each injection-leakage phrase family in §4.2: blocked when present.
- Negative case mirroring `test_no_eval_of_model_output`: content that merely *quotes* attacker-supplied text as a described vulnerability (e.g. a finding whose `description` is `"Source contains the string 'ignore previous instructions' in a comment, which should be flagged as a social-engineering/prompt-injection risk if this repo has an LLM in its own pipeline"`) is a judgment call the guardrail intentionally does not try to resolve — documented here as a known false-positive class (see §9) rather than silently mishandled.
- `agent.py` integration: `post_pr_review_tool`/`create_issue_tool` return a `blocked: True` response (not an exception) when content is dirty, and don't call `github_fetcher` at all (mocked, asserted via `assert_not_called()`); `generate_remediation_patches_with_verification()` drops a blocked patch into `blocked_patches` while still returning other clean patches from the same batch.

---

## 8. File Layout

- `guardrail.py` — `check_content`, `GuardrailResult`, `GuardrailViolation`, pattern tables. New.
- `agent.py` — `GuardrailBlockedError`, wiring in `post_pr_review_tool`, `create_issue_tool`, `generate_remediation_patches_with_verification()`.
- `server.py` — `RemediateResponse` gains `blocked_patches`.
- `tests/test_guardrail.py` — new.
- `tests/test_agent.py` — extended for the three call sites.

---

## 9. Out of Scope

- No general jailbreak/red-team detection surface — scoped strictly to the two categories and the phrase families this project already encodes as their signatures (§4). A determined adversary could phrase either around these specific patterns; that's a known limitation of a minimal, scoped check, not a claim of completeness.
- No attempt to distinguish "output is quoting attacker text as evidence of a finding" from "output is exhibiting the leakage itself" beyond the narrow `no issues found`-co-occurring-with-a-real-finding heuristic in §4.2 — a genuinely reliable version of that distinction is an LLM-judged check of its own, out of scope for a same-day guardrail.
- No blocking of the review/analysis path itself (`review()`, `generate_review_tool`, etc.) — only the three *write* paths named in the task. Findings the user only reads on their own screen are not gated; only content headed to a GitHub write action or copy-pasted patch is.

---

## 10. Acceptance Criteria

- [ ] Each of the three write paths runs generated content through `check_content()` before writing/returning it.
- [ ] A secret-shaped string in any of the three paths blocks that path's write and surfaces a clear, redacted error — never a silent drop, never a crashed pipeline.
- [ ] A `forbidden_phrases`-family string (the same signature `TestPromptSafety`/`inj-01` already encode) is likewise blocked.
- [ ] Clean content passes through unaffected on all three paths.
- [ ] Full existing test suite (275) plus new tests pass.
