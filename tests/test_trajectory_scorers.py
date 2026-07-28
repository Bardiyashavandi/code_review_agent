"""
tests/test_trajectory_scorers.py
-----------------------------------
Unit tests for evals/trajectory_scorers.py -- the pure-Python trace-parsing
and assertion helpers backing the trajectory eval category (evals/
trajectory_cases.py). These operate on a plain list of event dicts
({"author", "function_calls", "text"}), so they're testable here without
needing a real (or even mocked) ADK graph, InMemoryRunner, or Gemini call
at all -- exactly the kind of logic this repo's convention says needs its
own pytest coverage, separate from the eval harness itself.

Run with:
    pytest tests/test_trajectory_scorers.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_EVALS_DIR = _REPO_ROOT / "evals"
for _p in (_REPO_ROOT, _EVALS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from trajectory_scorers import (  # noqa: E402
    score_all_authors_present,
    score_remediation_converges_early,
    score_remediation_exhausts_honestly,
)


def _event(author: str, function_calls: list[str] | None = None, text: str | None = None) -> dict:
    return {"author": author, "function_calls": function_calls or [], "text": text}


# ---------------------------------------------------------------------------
# score_all_authors_present (traj-01)
# ---------------------------------------------------------------------------

class TestScoreAllAuthorsPresent:

    def test_passes_when_every_expected_author_appears(self):
        events = [_event("sast_agent_scan"), _event("injection_agent_scan"),
                  _event("security_aggregator_agent")]
        result = score_all_authors_present(
            events, {"sast_agent_scan", "injection_agent_scan", "security_aggregator_agent"}
        )
        assert result.passed is True

    def test_fails_when_one_expected_author_never_appears(self):
        events = [_event("sast_agent_scan"), _event("injection_agent_scan")]
        result = score_all_authors_present(
            events, {"sast_agent_scan", "injection_agent_scan", "security_aggregator_agent"}
        )
        assert result.passed is False
        assert "security_aggregator_agent" in result.detail

    def test_fails_on_empty_trajectory(self):
        result = score_all_authors_present([], {"sast_agent_scan"})
        assert result.passed is False
        assert "empty" in result.detail.lower()

    def test_extra_unrelated_authors_do_not_cause_a_failure(self):
        """Root-level or callback-only events with unrelated authors
        shouldn't break the check -- only missing EXPECTED authors should."""
        events = [_event("security_full_scan"), _event("sast_agent_scan"),
                  _event("injection_agent_scan")]
        result = score_all_authors_present(events, {"sast_agent_scan", "injection_agent_scan"})
        assert result.passed is True


# ---------------------------------------------------------------------------
# score_remediation_converges_early (traj-02)
# ---------------------------------------------------------------------------

class TestScoreRemediationConvergesEarly:

    def _passing_trace(self) -> list[dict]:
        return [
            _event("patch_generator_agent", ["remediation_tool"]),
            _event("patch_generator_agent", [], "Generated 1 patch."),
            _event("patch_verifier_step", ["patch_verifier_tool"]),
            _event("patch_verifier_step", ["exit_loop"]),
            _event("patch_verifier_step", [], "Exiting -- resolved."),
        ]

    def test_passes_on_exactly_one_generation_and_an_exit_loop_call(self):
        result = score_remediation_converges_early(self._passing_trace())
        assert result.passed is True

    def test_fails_if_generation_ran_more_than_once(self):
        events = self._passing_trace() + [
            _event("patch_generator_agent", ["remediation_tool"]),
        ]
        result = score_remediation_converges_early(events)
        assert result.passed is False
        assert "exactly once" in result.detail

    def test_fails_if_exit_loop_was_never_called(self):
        events = [
            _event("patch_generator_agent", ["remediation_tool"]),
            _event("patch_verifier_step", ["patch_verifier_tool"]),
            _event("patch_verifier_step", [], "Looks resolved, moving on."),
        ]
        result = score_remediation_converges_early(events)
        assert result.passed is False
        assert "exit_loop" in result.detail

    def test_fails_if_verifier_never_ran(self):
        events = [_event("patch_generator_agent", ["remediation_tool"])]
        result = score_remediation_converges_early(events)
        assert result.passed is False
        assert "patch_verifier_step" in result.detail

    def test_fails_on_empty_trajectory(self):
        result = score_remediation_converges_early([])
        assert result.passed is False


# ---------------------------------------------------------------------------
# score_remediation_exhausts_honestly (traj-03)
# ---------------------------------------------------------------------------

class TestScoreRemediationExhaustsHonestly:

    def _one_iteration(self) -> list[dict]:
        return [
            _event("patch_generator_agent", ["remediation_tool"]),
            _event("patch_generator_agent", [], "Generated 1 patch."),
            _event("patch_verifier_step", ["patch_verifier_tool"]),
            _event("patch_verifier_step", [], "Still unresolved; will retry."),
        ]

    def test_passes_after_exactly_max_iterations_with_no_exit_and_honest_report(self):
        events = self._one_iteration() * 3
        result = score_remediation_exhausts_honestly(events, max_iterations=3)
        assert result.passed is True

    def test_fails_if_exit_loop_was_called_at_all(self):
        events = self._one_iteration() * 2 + [
            _event("patch_generator_agent", ["remediation_tool"]),
            _event("patch_verifier_step", ["patch_verifier_tool"]),
            _event("patch_verifier_step", ["exit_loop"]),
        ]
        result = score_remediation_exhausts_honestly(events, max_iterations=3)
        assert result.passed is False
        assert "exit_loop" in result.detail

    def test_fails_if_generation_ran_fewer_than_max_iterations_times(self):
        events = self._one_iteration() * 2  # only 2, not 3
        result = score_remediation_exhausts_honestly(events, max_iterations=3)
        assert result.passed is False
        assert "exactly" in result.detail

    def test_fails_if_final_message_dishonestly_claims_success(self):
        events = self._one_iteration() * 2 + [
            _event("patch_generator_agent", ["remediation_tool"]),
            _event("patch_verifier_step", ["patch_verifier_tool"]),
            _event("patch_verifier_step", [], "All patches verified -- fully resolved!"),
        ]
        result = score_remediation_exhausts_honestly(events, max_iterations=3)
        assert result.passed is False
        assert "falsely claims success" in result.detail

    def test_fails_on_empty_trajectory(self):
        result = score_remediation_exhausts_honestly([], max_iterations=3)
        assert result.passed is False
