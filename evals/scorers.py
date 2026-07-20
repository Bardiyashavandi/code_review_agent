"""
evals/scorers.py
------------------
Shared scoring helpers for eval cases. Kept separate from cases.py so the
scoring logic (what counts as a pass) is easy to audit independently of
the 20 individual case definitions that use it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ScoreResult:
    passed: bool
    detail: str


def _finding_text(finding: dict) -> str:
    """Concatenate every string-ish field on a finding dict into one
    lowercased blob, so keyword matching doesn't need to know which
    specific field (pattern/injection_type/description/vulnerable_code/
    current_code/...) a given audit schema uses."""
    parts = []
    for v in finding.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (list, dict)):
            parts.append(str(v))
    return " ".join(parts).lower()


def score_detection(
    result: dict,
    expected_path_substring: str,
    expected_keywords: list[str],
    min_matching_keywords: int = 1,
    result_key: str = "findings",
) -> ScoreResult:
    """
    PASS if `result[result_key]` contains at least one finding whose path
    matches `expected_path_substring` AND whose combined text contains at
    least `min_matching_keywords` of `expected_keywords` (case-insensitive).

    `result_key` defaults to "findings" (used by generate_injection_audit,
    generate_auth_audit, generate_secrets_audit, generate_crypto_audit).
    generate_data_flow_analysis is the one specialist method that doesn't
    share this schema -- it returns its list under "tainted_paths" instead
    -- so callers scoring that method must pass result_key="tainted_paths"
    explicitly. (This inconsistency across specialist schemas is itself
    worth normalizing at the product level someday; not done here.)

    This is deliberately loose on exact wording (LLM phrasing varies run to
    run) but strict on "did it flag the right file for something in the
    right category" rather than just "did it produce any output at all".
    """
    if result.get("parse_error"):
        return ScoreResult(False, f"Response failed to parse as JSON: {result.get('raw', '')[:200]}")

    findings = result.get(result_key, [])
    if not findings:
        return ScoreResult(False, f"No entries returned under '{result_key}' at all.")

    for f in findings:
        path = str(f.get("path", "")).lower()
        if expected_path_substring.lower() not in path:
            continue
        text = _finding_text(f)
        matched = [kw for kw in expected_keywords if kw.lower() in text]
        if len(matched) >= min_matching_keywords:
            return ScoreResult(
                True,
                f"Matched finding on '{f.get('path')}' via keywords {matched} "
                f"(severity={f.get('severity', '?')}).",
            )

    return ScoreResult(
        False,
        f"{len(findings)} finding(s) returned, but none matched path "
        f"'{expected_path_substring}' with >= {min_matching_keywords} of "
        f"{expected_keywords}. Paths seen: {[f.get('path') for f in findings]}",
    )


def score_false_positive(validations: list[dict], target_index: int = 0) -> ScoreResult:
    """
    PASS if the validator marked the fabricated finding at `target_index`
    as a likely false positive: either false_positive=True, or confidence
    downgraded to LOW. (A MEDIUM/HIGH "confirmed" verdict on a finding that
    describes a vulnerability which isn't actually present is a real FP-rate
    failure -- the validator agreeing with a wrong premise.)
    """
    if not validations:
        return ScoreResult(False, "validate_findings returned no validations at all.")

    match = next((v for v in validations if v.get("index") == target_index), None)
    if match is None:
        match = validations[0]

    if match.get("false_positive") is True:
        return ScoreResult(True, f"Correctly flagged as false positive: {match.get('note', '')}")
    if str(match.get("confidence", "")).upper() == "LOW":
        return ScoreResult(True, f"Correctly downgraded to LOW confidence: {match.get('note', '')}")

    return ScoreResult(
        False,
        f"Validator did NOT flag the fabricated finding: "
        f"confidence={match.get('confidence')}, false_positive={match.get('false_positive')}, "
        f"note={match.get('note', '')!r}",
    )


def score_dedup_merges(result: dict, original_count: int, expect_merge: bool) -> ScoreResult:
    """
    PASS if deduplicated_count < original_count when expect_merge=True
    (duplicates should collapse), or deduplicated_count == original_count
    when expect_merge=False (genuinely distinct findings must NOT be
    over-merged into one).
    """
    if result.get("parse_error"):
        return ScoreResult(False, f"Response failed to parse: {result.get('raw', '')[:200]}")

    dedup_count = result.get("deduplicated_count")
    findings = result.get("deduplicated_findings", [])
    if dedup_count is None:
        dedup_count = len(findings)

    if expect_merge:
        if dedup_count < original_count:
            return ScoreResult(
                True, f"Merged {original_count} -> {dedup_count} findings as expected."
            )
        return ScoreResult(
            False,
            f"Expected a merge ({original_count} -> fewer) but got "
            f"deduplicated_count={dedup_count} (no reduction).",
        )
    else:
        if dedup_count == original_count:
            return ScoreResult(True, f"Correctly kept all {original_count} distinct findings separate.")
        return ScoreResult(
            False,
            f"Expected {original_count} findings to stay distinct, but got "
            f"deduplicated_count={dedup_count} (over-merged).",
        )


def score_risk_ordering(
    result: dict,
    high_finding_title: str,
    low_finding_title: str,
) -> ScoreResult:
    """
    PASS if the finding expected to be the obvious high-severity one scores
    a higher composite_score AND a numerically lower (= more urgent)
    priority_rank than the finding expected to be low-severity.
    """
    if result.get("parse_error"):
        return ScoreResult(False, f"Response failed to parse: {result.get('raw', '')[:200]}")

    scored = result.get("scored_findings", [])
    if len(scored) < 2:
        return ScoreResult(False, f"Expected >= 2 scored findings, got {len(scored)}.")

    def _find(title_substr: str) -> dict | None:
        for s in scored:
            if title_substr.lower() in str(s.get("title", "")).lower():
                return s
        return None

    high = _find(high_finding_title)
    low = _find(low_finding_title)
    if high is None or low is None:
        return ScoreResult(
            False,
            f"Could not match both findings by title substring. "
            f"Titles seen: {[s.get('title') for s in scored]}",
        )

    high_score = high.get("composite_score")
    low_score = low.get("composite_score")
    if high_score is None or low_score is None:
        return ScoreResult(False, "composite_score missing on one or both findings.")

    if high_score <= low_score:
        return ScoreResult(
            False,
            f"Expected high-severity composite_score > low-severity, got "
            f"{high_score} <= {low_score}.",
        )

    high_rank = high.get("priority_rank")
    low_rank = low.get("priority_rank")
    if high_rank is not None and low_rank is not None and high_rank >= low_rank:
        return ScoreResult(
            False,
            f"composite_score ordering correct ({high_score} > {low_score}) but "
            f"priority_rank did not follow: high={high_rank}, low={low_rank} "
            f"(lower rank number should mean higher priority).",
        )

    return ScoreResult(
        True,
        f"High-severity scored {high_score} (rank {high_rank}) > "
        f"low-severity {low_score} (rank {low_rank}), as expected.",
    )


def score_exact(actual: Any, expected: Any, label: str) -> ScoreResult:
    if actual == expected:
        return ScoreResult(True, f"{label}: {actual} (matches expected)")
    return ScoreResult(False, f"{label}: got {actual!r}, expected {expected!r}")
