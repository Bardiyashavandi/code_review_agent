"""
review_memory.py — persistent per-(repo_url, branch) memory of past review
findings. See specs/memory_spec.md for the full design and rationale.

This is deliberately independent of ADK's own SessionService/MemoryService:
the only free MemoryService (InMemoryMemoryService) is explicitly
non-persistent, and both persistent options (VertexAiMemoryBankService,
VertexAiRagMemoryService) require a billing-enabled Google Cloud project —
see specs/memory_spec.md §2 for the full comparison. This module is plain
stdlib (json/hashlib/os/pathlib/dataclasses) — no new dependency.

Everything here is best-effort by design: a missing or corrupted memory
file must degrade to "no prior history" (identical to a repo's first-ever
review), never raise, never block a review. Storage failures are logged
and swallowed the same way.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_MEMORY_PATH = ".review_memory/findings.json"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class MemoryDiff:
    new_count: int
    still_open_count: int
    resolved_count: int
    resolved: list[dict] = field(default_factory=list)
    has_prior_history: bool = False
    # 1:1 with the `new_findings` list passed into diff(): "new" | "still_open"
    statuses: list[str] = field(default_factory=list)


@dataclass
class MemorySummary:
    has_prior_history: bool
    new_count: int
    still_open_count: int
    resolved_count: int
    resolved: list[dict] = field(default_factory=list)

    @classmethod
    def from_diff(cls, diff: MemoryDiff, max_resolved_examples: int = 10) -> "MemorySummary":
        return cls(
            has_prior_history=diff.has_prior_history,
            new_count=diff.new_count,
            still_open_count=diff.still_open_count,
            resolved_count=diff.resolved_count,
            resolved=diff.resolved[:max_resolved_examples],
        )


# ---------------------------------------------------------------------------
# Identity matching
# ---------------------------------------------------------------------------

def _finding_identity(finding: dict) -> str:
    """A stable identifier for a finding, independent of (path, line) —
    combined with (path, line) by the caller for the full match key.

    rule_id when the finding has a non-empty one (Semgrep findings, and any
    Gemini finding that carries one); otherwise a short hash of `title`,
    since LLM-only findings routinely have no rule_id and free-text
    `description` can reword itself slightly between calls even for "the
    same" finding — title is the more stable field to key off of. Mirrors
    the existing _rag_fingerprint() pattern in gemini_reviewer.py (a short
    hex digest of a small tuple) rather than inventing a new convention.
    """
    rule_id = finding.get("rule_id")
    if rule_id:
        return str(rule_id)
    title = finding.get("title", "")
    return hashlib.sha256(title.encode("utf-8")).hexdigest()[:16]


def _match_key(finding: dict) -> tuple:
    return (finding.get("path", ""), finding.get("line", 0), _finding_identity(finding))


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class ReviewMemoryStore:
    """Persistent store of the latest review-findings snapshot per
    (repo_url, branch), backed by a single JSON file."""

    def __init__(self, path: str | os.PathLike = DEFAULT_MEMORY_PATH) -> None:
        self._path = Path(path)

    # -- reading -------------------------------------------------------

    def load_snapshot(self, repo_url: str, branch: str) -> list[dict] | None:
        """Return the last-stored findings list for (repo_url, branch), or
        None if there is no prior history, the file is missing, or it's
        corrupted in any way. Never raises."""
        record = self._load_record(repo_url, branch)
        if record is None:
            return None
        findings = record.get("findings")
        if not isinstance(findings, list):
            return None
        return findings

    def load_last_diff(self, repo_url: str, branch: str) -> dict | None:
        """Return the last-persisted diff summary dict for (repo_url,
        branch) (as saved by save_snapshot), or None if there's no history
        or the file is unreadable. Used by recall_previous_findings_tool so
        it never needs to recompute anything."""
        record = self._load_record(repo_url, branch)
        if record is None:
            return None
        return {
            "reviewed_at": record.get("reviewed_at"),
            "total_findings": len(record.get("findings") or []),
            **(record.get("last_diff") or {}),
        }

    def _load_record(self, repo_url: str, branch: str) -> dict | None:
        try:
            if not self._path.exists():
                return None
            raw = self._path.read_text(encoding="utf-8")
            if not raw.strip():
                return None
            data = json.loads(raw)
            if not isinstance(data, dict):
                return None
            record = data.get(self._key(repo_url, branch))
            if not isinstance(record, dict):
                return None
            return record
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.warning(
                "review_memory: could not read %s for %s@%s (%s); "
                "degrading to no prior history.", self._path, repo_url, branch, exc,
            )
            return None

    # -- writing ---------------------------------------------------------

    def save_snapshot(
        self, repo_url: str, branch: str, findings: list[dict], diff: MemoryDiff,
    ) -> None:
        """Persist `findings` as the latest snapshot for (repo_url, branch),
        alongside a summary of `diff` (so recall_previous_findings_tool can
        answer from storage alone, no recomputation). Best-effort: logs and
        returns on any failure, never raises.

        `findings` dicts are stored exactly as given -- this module stays
        deliberately unaware of any domain types (FetchResult, etc.) or of
        what plausibility/provenance checks a caller may have already run.
        agent.py's review_repo() (see specs/write_action_gate_spec.md's
        memory-recall hardening addendum) drops findings whose path wasn't
        part of the run's fetched files *before* calling this, and attaches
        two provenance keys to each finding it does pass in: source_run_id
        (a synthetic per-review_repo()-call identifier -- not a git commit
        sha, since none is fetched anywhere in this codebase today) and
        persisted_at (this write's timestamp). Neither key is required or
        interpreted here, or by diff()/_finding_identity()/_match_key()
        below, which only ever read path/line/rule_id/title -- they exist so
        a future staleness check (e.g. "drop anything not reconfirmed in N
        runs") has something to key off without another migration."""
        try:
            data: dict = {}
            if self._path.exists():
                try:
                    raw = self._path.read_text(encoding="utf-8")
                    if raw.strip():
                        loaded = json.loads(raw)
                        if isinstance(loaded, dict):
                            data = loaded
                except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                    # Existing file is unreadable — overwrite it rather than
                    # blocking a write on a file we can't trust anyway.
                    data = {}

            data[self._key(repo_url, branch)] = {
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                "findings": findings,
                "last_diff": {
                    "new_since_previous": diff.new_count,
                    "still_open": diff.still_open_count,
                    "resolved_since_previous": diff.resolved_count,
                    "resolved_examples": diff.resolved[:10],
                    "has_history": diff.has_prior_history,
                },
            }

            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            os.replace(tmp_path, self._path)
        except OSError as exc:
            logger.warning(
                "review_memory: could not persist snapshot to %s for %s@%s (%s); "
                "this review's results are unaffected, only memory for next "
                "time is missing.", self._path, repo_url, branch, exc,
            )

    @staticmethod
    def _key(repo_url: str, branch: str) -> str:
        return f"{repo_url}::{branch}"

    # -- diffing -----------------------------------------------------------

    def diff(self, new_findings: list[dict], prior: list[dict] | None) -> MemoryDiff:
        """Classify new_findings against a prior snapshot (or None for a
        repo/branch's first-ever review)."""
        if prior is None:
            return MemoryDiff(
                new_count=len(new_findings),
                still_open_count=0,
                resolved_count=0,
                resolved=[],
                has_prior_history=False,
                statuses=["new"] * len(new_findings),
            )

        prior_keys = {_match_key(f): f for f in prior}
        new_keys = {_match_key(f) for f in new_findings}

        statuses: list[str] = []
        new_count = 0
        still_open_count = 0
        for finding in new_findings:
            key = _match_key(finding)
            if key in prior_keys:
                statuses.append("still_open")
                still_open_count += 1
            else:
                statuses.append("new")
                new_count += 1

        resolved = [
            {"path": f.get("path", ""), "line": f.get("line", 0), "title": f.get("title", "")}
            for key, f in prior_keys.items()
            if key not in new_keys
        ]

        return MemoryDiff(
            new_count=new_count,
            still_open_count=still_open_count,
            resolved_count=len(resolved),
            resolved=resolved,
            has_prior_history=True,
            statuses=statuses,
        )
