"""
guardrail.py — pre-write-action content check for the three paths that send
generated content outside the pipeline: post_pr_review_tool, create_issue_tool,
and remediation_agent's patches. See specs/guardrail_spec.md for the full
design, why Guardrails AI was evaluated and not used, and why these specific
patterns/phrases were chosen (both are a direct reuse of signatures this
project already documents elsewhere — SECRETS_AUDIT_SYSTEM_INSTRUCTION's
"PATTERNS TO LOOK FOR" list in gemini_reviewer.py, and
tests/test_gemini_reviewer.py's TestPromptSafety / evals/cases.py's
inj-01-embedded-system-override forbidden_phrases — not new, independently
invented detection surfaces).

Pure and side-effect-free: check_content() never raises, logs, or touches
the network. Callers decide what a `blocked=True` result means for them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Secret patterns — a literal translation of gemini_reviewer.py's
# SECRETS_AUDIT_SYSTEM_INSTRUCTION "PATTERNS TO LOOK FOR" list into regexes.
# See specs/guardrail_spec.md §4.1 for the source-to-regex mapping table.
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("github_token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "password_or_token_literal",
        re.compile(
            r"(?i)(password|passwd|pwd|secret|api_key|apikey|token)\s*[:=]\s*"
            r"['\"][^'\"\s]{6,}['\"]"
        ),
    ),
    (
        "credential_connection_string",
        re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/'\"]+:[^\s@/'\"]+@"),
    ),
    (
        "key_material_literal",
        re.compile(
            r"(?i)(secret|private[_-]?key|encryption[_-]?key)\s*[:=]\s*"
            r"['\"][A-Za-z0-9+/=_\-]{20,}['\"]"
        ),
    ),
]

# ---------------------------------------------------------------------------
# Prompt-injection-leakage phrases — the same signature this project already
# treats as this failure mode's fingerprint (TestPromptSafety, inj-01's
# forbidden_phrases). Deliberately scoped to these families only — see
# specs/guardrail_spec.md §4.2 / §9.
# ---------------------------------------------------------------------------

_INJECTION_PHRASE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("instruction_override", re.compile(r"(?i)ignore (all )?(previous|prior|above) instructions")),
    ("instruction_override", re.compile(r"(?i)disregard (the )?(above|previous)")),
    ("instruction_override", re.compile(r"(?i)new instructions\s*:")),
    ("prompt_leakage_request", re.compile(r"(?i)(reveal|print|show) your (system )?prompt")),
    ("injected_claim_compliance", re.compile(r"(?i)pre-approved")),
    ("injected_claim_compliance", re.compile(r"(?i)already (been )?manually reviewed")),
    ("injected_claim_compliance", re.compile(r"(?i)no issues found")),
    ("system_prompt_leak", re.compile(r"(?i)system prompt")),
    ("system_prompt_leak", re.compile(r"(?i)you are a senior code reviewer")),
]


@dataclass
class GuardrailViolation:
    category: str
    detail: str


@dataclass
class GuardrailResult:
    blocked: bool
    violations: list[GuardrailViolation] = field(default_factory=list)


def _redact(matched: str) -> str:
    if len(matched) <= 4:
        return "***"
    return f"{matched[:4]}***"


def check_content(text: str) -> GuardrailResult:
    """Scan `text` (a rendered PR comment, issue body, or patch before/after/
    explanation) for a real-looking secret or a prompt-injection-leakage
    signature. Returns a GuardrailResult; never raises."""
    violations: list[GuardrailViolation] = []

    if not text:
        return GuardrailResult(blocked=False, violations=[])

    for name, pattern in _SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            violations.append(
                GuardrailViolation(
                    category="secret",
                    detail=f"looks like a {name.replace('_', ' ')}: {_redact(match.group(0))}",
                )
            )

    for name, pattern in _INJECTION_PHRASE_PATTERNS:
        match = pattern.search(text)
        if match:
            violations.append(
                GuardrailViolation(
                    category="prompt_injection_leakage",
                    detail=f"{name.replace('_', ' ')}: matched \"{match.group(0)}\"",
                )
            )

    return GuardrailResult(blocked=bool(violations), violations=violations)
