# Eval suite

Scenario-based, end-to-end evaluation of the code-review pipeline — not
unit tests. The existing `tests/` suite (124 tests) mocks every Gemini
call and checks plumbing: batching, JSON parsing, retries, caching. It
never checks whether the pipeline actually catches a real vulnerability,
correctly clears a false positive, merges real duplicates, or ranks risk
sensibly. This directory does.

## Why this needs a real API key

`deduplicate_findings`, `generate_risk_scores`, `generate_remediation_patches`,
`validate_review_findings`, and every specialist audit (`generate_injection_audit`,
`generate_auth_audit`, etc.) are thin proxies straight to a Gemini call —
there is no deterministic/rule-based logic backing any of them. Scoring
"does it catch SQL injection" or "does it correctly reject a fabricated
finding" against a **mocked** response would just re-test JSON parsing
(already covered by `tests/`), not the actual judgment being evaluated.

So: **20 cases total.** 18 of them (`detection`, `false_positive`, `dedup`,
`risk_scoring`) call real `CodeReviewAgent` methods and need a real
`GEMINI_API_KEY` to mean anything. 2 of them (`cost_estimate`) touch no LLM
at all — pure Python logic checking `server.py`'s token/RPD math against
`view_trace.py`'s — and are genuinely meaningful in any environment.

## Running it

```bash
cd evals

# Mock mode (default) — harness self-test only. Proves the runner,
# scorers, and result table work; every LLM-backed case returns a
# pre-scripted "ideal" response, so passing here does NOT mean the real
# pipeline catches anything. Useful for CI / regression-testing the
# harness itself, and for a quick sanity check with no API key.
python3 runner.py

# Real eval — needs GEMINI_API_KEY (GITHUB_TOKEN can stay a placeholder;
# no GitHub network calls happen) and a working `semgrep` on PATH
# (CodeReviewAgent's constructor builds a SemgrepRunner even though these
# cases never call scan()).
export GEMINI_API_KEY=your_key_here
python3 runner.py --mode live

# Narrow the run:
python3 runner.py --mode live --category detection
python3 runner.py --mode live --only det-01-sqli,fp-02-enum-table-name

# Save full results as JSON for a before/after diff:
python3 runner.py --mode live --json-out results/run_$(date +%Y%m%d_%H%M%S).json
```

Live mode makes ~18 real Gemini calls per full run (small snippets, no
batching across files) — cheap against the free tier, but not free. `results/`
is where JSON snapshots go for before/after comparisons; it's gitignored.

## Categories

| Category | Cases | What it checks |
|---|---|---|
| `detection` | 9 | Does the right specialist catch the right known-bad pattern (SQLi, command injection, hardcoded secrets, weak crypto, IDOR, SSRF, path traversal, multi-hop taint flow, XXE) in a realistic file? |
| `false_positive` | 4 | Given a *fabricated* finding against actually-safe code (parameterized query, enum-only f-string, stale scary comment, correct `secrets` usage), does `validate_review_findings` correctly flag it `false_positive=True` or downgrade confidence to `LOW`? |
| `dedup` | 3 | When the same vulnerability is reported twice under different `source_agent` tags (exact same line, and near-duplicate adjacent lines), does `deduplicate_findings` actually merge them — and does it leave 3 genuinely distinct findings alone rather than over-merging? |
| `risk_scoring` | 2 | Does `generate_risk_scores` rank an obvious CRITICAL (hardcoded prod DB password / unauthenticated RCE) above an obvious LOW (a DEBUG log line / a missing docstring) in both `composite_score` and `priority_rank`? |
| `cost_estimate` | 2 | Does `server.py`'s RPD/token aggregation match `view_trace.py`'s on an identical synthetic trace file, including edge cases (a call with no `usage_metadata`, a cache hit, a call from a different UTC day, and a span with a stale `total_tokens` value on `tokens_available=False` that must not leak into the sum)? |

## Fixtures

`fixtures/vulnerable/*.py` — 9 synthetic files, each containing one
unambiguous, realistic instance of a specific vulnerability class. Not
adversarial or obfuscated; the point is "does the pipeline catch the
obvious case," not "can it beat CTF-grade evasion."

`fixtures/clean/*.py` — 4 synthetic files that are actually safe but
superficially resemble something vulnerable (a parameterized query next
to an f-string that only touches a fixed enum, a bcrypt hash sitting under
a stale "TODO: fix security hole" comment). These back the
`false_positive` cases: a fabricated finding is deliberately fed in
against these files, and the eval checks whether the validator catches
that the premise is wrong.

None of these come from a real past PR in this repo — this repo's own
history doesn't contain real vulnerable code to mine (it's a security
tool, not a vulnerable app), so all 13 fixtures are synthetic but modeled
on real-world patterns. `fixtures/vulnerable/weak_crypto.py` is adapted
from the sample already used in `demo_security_agents.py` for continuity
with that existing manual-verification script.

## Scoring philosophy

Scoring is intentionally loose on exact wording (LLM phrasing varies run
to run) and strict on the structural thing being measured: did a finding
land on the right file, with at least one matching keyword from the right
category (`detection`); did the validator's `false_positive`/`confidence`
field actually flip (`false_positive`); did the count of distinct findings
actually go down, or actually *not* go down when it shouldn't
(`dedup`); did the composite score and priority rank both order correctly
(`risk_scoring`). See `scorers.py` for the exact logic — it's short and
meant to be read, not a black box.

## Files

- `cases.py` — the 18 LLM-backed case definitions (detection, false_positive, dedup, risk_scoring)
- `cost_estimate_cases.py` — the 2 no-LLM cases
- `trace_fixtures.py` — synthetic `trace.jsonl` span builders for the cost_estimate cases
- `scorers.py` — shared scoring logic, one function per category
- `runner.py` — CLI: runs cases, prints the pass/fail table
- `fixtures/` — the 13 synthetic source files described above
- `results/` — JSON snapshots from `--json-out` runs (gitignored)
