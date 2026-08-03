"""
injection_scanner.py — Layer B of this project's prompt-injection defense:
a lightweight heuristic pre-scan of INBOUND repo content, run BEFORE fetched
files reach GeminiReviewer.

This is a visibility backstop, not the primary defense. Layer A (the
untrusted-data framing + explicit "flag it, don't comply" instruction in
every gemini_reviewer.py system instruction, plus the <file_content>
delimiter wrapping in every prompt-construction site) is what actually
prevents the model from complying with an embedded instruction. This module
exists so a suspected attempt is visible to a human reviewer even in cases
where the LLM-level defense is the thing actually doing the stopping — it
never strips, blocks, or otherwise modifies the content it scans.

Shares its core phrase patterns with guardrail.py's INJECTION_PHRASE_PATTERNS
(the mirror-image concern: guardrail.py checks OUTBOUND model output for
leakage, this module checks INBOUND repo content for the attempt itself) and
adds a small number of inbound-only patterns — role markers and direct
address to an AI reviewer — that make sense on the input side but not when
scanning a model's own output. See specs/injection_defense_spec.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from guardrail import INJECTION_PHRASE_PATTERNS

# ---------------------------------------------------------------------------
# Inbound-only patterns — things a malicious/compromised file might contain
# to try to address an AI reviewer directly, that wouldn't make sense to
# check for in the model's own OUTBOUND output (guardrail.py's concern).
# ---------------------------------------------------------------------------

_INBOUND_ONLY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("role_marker", re.compile(r"(?i)\bsystem\s*:")),
    ("role_marker", re.compile(r"(?i)system override\b")),
    ("role_reassignment", re.compile(r"(?i)\byou are now\b")),
    ("direct_address_to_reviewer", re.compile(r"(?i)note to (the )?(ai\b|llm\b|reviewer\b)")),
    ("direct_address_to_reviewer", re.compile(r"(?i)dear (ai|reviewer|llm)\b")),
    ("direct_address_to_reviewer", re.compile(r"(?i)attention:?\s*ai\b")),
]

# Combined pattern set this scanner checks every line against. Order doesn't
# matter for correctness (only the first match per line is kept — see
# scan_text_for_injection), but shared patterns are listed first so a phrase
# that's meaningful in both directions gets attributed to the shared
# category rather than an inbound-only one.
_ALL_PATTERNS: list[tuple[str, re.Pattern]] = list(INJECTION_PHRASE_PATTERNS) + _INBOUND_ONLY_PATTERNS

# How much of a matching line to keep as the reported snippet. This is
# INBOUND content being surfaced to a human reviewer in a report they
# control -- unlike guardrail.py's redaction (which protects against a
# model's OUTBOUND text leaking a real secret), there's nothing here that
# needs hiding: showing the suspicious source text verbatim is the entire
# point of a visibility backstop. Still capped, so one absurdly long line
# doesn't blow up the report.
_MAX_SNIPPET_CHARS = 200


@dataclass
class InjectionMatch:
    path: str
    line: int
    category: str
    snippet: str


def scan_text_for_injection(path: str, content: str) -> list[InjectionMatch]:
    """Scan one file/content blob's text, line by line, for suspected
    prompt-injection attempts. Flags only — never modifies content. At most
    one match per line (the first pattern that hits), so one heavily
    "suspicious-sounding" line doesn't produce a flood of near-duplicate
    entries in the report."""
    matches: list[InjectionMatch] = []
    if not content:
        return matches

    for line_no, line in enumerate(content.splitlines(), start=1):
        for category, pattern in _ALL_PATTERNS:
            if pattern.search(line):
                matches.append(
                    InjectionMatch(
                        path=path,
                        line=line_no,
                        category=category,
                        snippet=line.strip()[:_MAX_SNIPPET_CHARS],
                    )
                )
                break  # one match per line -- see docstring

    return matches


def scan_files_for_injection(files) -> list[InjectionMatch]:
    """Scan a list of FileResult-like objects (anything with .path/.content
    attributes) for suspected prompt-injection attempts."""
    matches: list[InjectionMatch] = []
    for f in files:
        matches.extend(scan_text_for_injection(f.path, f.content))
    return matches
