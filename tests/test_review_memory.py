"""
tests/test_review_memory.py
----------------------------
Tests for review_memory.py's ReviewMemoryStore -- storage round-tripping,
best-effort degradation on a missing/corrupted file, and the new/still_open/
resolved diff classification. See specs/memory_spec.md.

Run with:
    pytest tests/test_review_memory.py -v
"""

from __future__ import annotations

import json
import os

import pytest

from review_memory import MemoryDiff, MemorySummary, ReviewMemoryStore, _finding_identity, _match_key


def make_finding(path="a.py", line=1, title="Finding", rule_id=None, **kw) -> dict:
    return {
        "path": path, "line": line, "severity": kw.get("severity", "HIGH"),
        "title": title, "description": kw.get("description", "d"),
        "suggested_fix": kw.get("suggested_fix", "f"), "rule_id": rule_id,
    }


# ---------------------------------------------------------------------------
# 1. Identity matching
# ---------------------------------------------------------------------------

class TestFindingIdentity:

    def test_uses_rule_id_when_present(self):
        f = make_finding(rule_id="py.sql-injection")
        assert _finding_identity(f) == "py.sql-injection"

    def test_falls_back_to_title_hash_without_rule_id(self):
        f = make_finding(title="Hardcoded secret", rule_id=None)
        identity = _finding_identity(f)
        assert identity != ""
        # Same title -> same hash, independent of description wording.
        f2 = make_finding(title="Hardcoded secret", rule_id=None, description="different wording")
        assert _finding_identity(f2) == identity

    def test_different_titles_hash_differently(self):
        f1 = make_finding(title="Hardcoded secret", rule_id=None)
        f2 = make_finding(title="SQL injection", rule_id=None)
        assert _finding_identity(f1) != _finding_identity(f2)

    def test_match_key_combines_path_line_and_identity(self):
        f = make_finding(path="a.py", line=10, rule_id="rule.1")
        assert _match_key(f) == ("a.py", 10, "rule.1")


# ---------------------------------------------------------------------------
# 2. diff() classification
# ---------------------------------------------------------------------------

class TestDiff:

    def test_first_ever_review_marks_everything_new(self):
        store = ReviewMemoryStore(path="/unused")
        findings = [make_finding(title="A"), make_finding(title="B", line=2)]

        diff = store.diff(findings, None)

        assert diff.has_prior_history is False
        assert diff.new_count == 2
        assert diff.still_open_count == 0
        assert diff.resolved_count == 0
        assert diff.resolved == []
        assert diff.statuses == ["new", "new"]

    def test_still_open_when_present_in_both(self):
        store = ReviewMemoryStore(path="/unused")
        prior = [make_finding(path="a.py", line=1, rule_id="rule.1")]
        new = [make_finding(path="a.py", line=1, rule_id="rule.1")]

        diff = store.diff(new, prior)

        assert diff.has_prior_history is True
        assert diff.statuses == ["still_open"]
        assert diff.still_open_count == 1
        assert diff.new_count == 0
        assert diff.resolved_count == 0

    def test_new_when_absent_from_prior(self):
        store = ReviewMemoryStore(path="/unused")
        prior = [make_finding(path="a.py", line=1, rule_id="rule.1")]
        new = [make_finding(path="b.py", line=5, rule_id="rule.2")]

        diff = store.diff(new, prior)

        assert diff.statuses == ["new"]
        assert diff.new_count == 1
        # The prior finding no longer appears -> resolved.
        assert diff.resolved_count == 1
        assert diff.resolved[0]["path"] == "a.py"

    def test_resolved_finding_not_in_statuses(self):
        """statuses is 1:1 with the new_findings list passed in -- a
        resolved finding (absent from new_findings) must not appear there,
        only in `resolved`."""
        store = ReviewMemoryStore(path="/unused")
        prior = [make_finding(path="a.py", line=1, rule_id="rule.1", title="Old")]
        new: list[dict] = []

        diff = store.diff(new, prior)

        assert diff.statuses == []
        assert diff.new_count == 0
        assert diff.still_open_count == 0
        assert diff.resolved_count == 1
        assert diff.resolved[0]["title"] == "Old"

    def test_identity_fallback_matches_same_title_no_rule_id(self):
        store = ReviewMemoryStore(path="/unused")
        prior = [make_finding(path="a.py", line=1, title="Hardcoded secret", rule_id=None)]
        new = [make_finding(path="a.py", line=1, title="Hardcoded secret", rule_id=None)]

        diff = store.diff(new, prior)

        assert diff.statuses == ["still_open"]


# ---------------------------------------------------------------------------
# 3. Storage round-trip + best-effort degradation
# ---------------------------------------------------------------------------

class TestStorage:

    def test_round_trip_save_then_load(self, tmp_path):
        store = ReviewMemoryStore(path=str(tmp_path / "findings.json"))
        findings = [make_finding(title="A"), make_finding(title="B", line=2)]
        diff = store.diff(findings, None)

        store.save_snapshot("https://github.com/o/r", "main", findings, diff)
        loaded = store.load_snapshot("https://github.com/o/r", "main")

        assert loaded == findings

    def test_different_branch_is_a_separate_key(self, tmp_path):
        store = ReviewMemoryStore(path=str(tmp_path / "findings.json"))
        main_findings = [make_finding(title="main-only")]
        diff = store.diff(main_findings, None)
        store.save_snapshot("https://github.com/o/r", "main", main_findings, diff)

        assert store.load_snapshot("https://github.com/o/r", "dev") is None

    def test_missing_file_degrades_to_none(self, tmp_path):
        store = ReviewMemoryStore(path=str(tmp_path / "does_not_exist.json"))
        assert store.load_snapshot("https://github.com/o/r", "main") is None

    def test_corrupted_file_degrades_to_none(self, tmp_path):
        path = tmp_path / "findings.json"
        path.write_text("{not valid json", encoding="utf-8")
        store = ReviewMemoryStore(path=str(path))

        assert store.load_snapshot("https://github.com/o/r", "main") is None

    def test_unexpected_shape_degrades_to_none(self, tmp_path):
        path = tmp_path / "findings.json"
        path.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
        store = ReviewMemoryStore(path=str(path))

        assert store.load_snapshot("https://github.com/o/r", "main") is None

    def test_save_creates_missing_parent_directory(self, tmp_path):
        nested_path = tmp_path / "nested" / "dir" / "findings.json"
        store = ReviewMemoryStore(path=str(nested_path))
        findings = [make_finding()]
        diff = store.diff(findings, None)

        store.save_snapshot("https://github.com/o/r", "main", findings, diff)

        assert nested_path.exists()
        assert store.load_snapshot("https://github.com/o/r", "main") == findings

    def test_save_is_atomic_no_leftover_tmp_file(self, tmp_path):
        path = tmp_path / "findings.json"
        store = ReviewMemoryStore(path=str(path))
        findings = [make_finding()]
        diff = store.diff(findings, None)

        store.save_snapshot("https://github.com/o/r", "main", findings, diff)
        store.save_snapshot("https://github.com/o/r", "main", findings, diff)  # overwrite

        assert not (tmp_path / "findings.json.tmp").exists()
        assert path.exists()

    def test_save_failure_does_not_raise(self, tmp_path, monkeypatch):
        """A directory that can't be created (e.g. permissions) must not
        raise out of save_snapshot -- this review's own result must still
        be returned, only memory for next time is missing."""
        # Point at a path whose parent is actually a file, not a directory --
        # mkdir(parents=True) will fail with a real OSError/NotADirectoryError.
        blocking_file = tmp_path / "not_a_dir"
        blocking_file.write_text("x", encoding="utf-8")
        store = ReviewMemoryStore(path=str(blocking_file / "findings.json"))

        findings = [make_finding()]
        diff = store.diff(findings, None)
        store.save_snapshot("https://github.com/o/r", "main", findings, diff)  # must not raise

    def test_load_last_diff_reflects_saved_diff_summary(self, tmp_path):
        store = ReviewMemoryStore(path=str(tmp_path / "findings.json"))
        prior = [make_finding(path="a.py", line=1, rule_id="r1", title="Old")]
        store.save_snapshot("https://github.com/o/r", "main", prior, store.diff(prior, None))

        new = [make_finding(path="b.py", line=2, rule_id="r2", title="New one")]
        diff = store.diff(new, prior)
        store.save_snapshot("https://github.com/o/r", "main", new, diff)

        last_diff = store.load_last_diff("https://github.com/o/r", "main")

        assert last_diff["new_since_previous"] == 1
        assert last_diff["still_open"] == 0
        assert last_diff["resolved_since_previous"] == 1
        assert last_diff["total_findings"] == 1
        assert last_diff["has_history"] is True

    def test_load_last_diff_none_when_no_history(self, tmp_path):
        store = ReviewMemoryStore(path=str(tmp_path / "findings.json"))
        assert store.load_last_diff("https://github.com/o/r", "main") is None


# ---------------------------------------------------------------------------
# 4. MemorySummary.from_diff
# ---------------------------------------------------------------------------

class TestMemorySummary:

    def test_from_diff_caps_resolved_examples(self):
        diff = MemoryDiff(
            new_count=0, still_open_count=0, resolved_count=12,
            resolved=[{"path": f"f{i}.py", "line": i, "title": f"t{i}"} for i in range(12)],
            has_prior_history=True, statuses=[],
        )

        summary = MemorySummary.from_diff(diff, max_resolved_examples=5)

        assert summary.resolved_count == 12
        assert len(summary.resolved) == 5
