"""
evals/trajectory_scorers.py
-----------------------------
Scoring helpers for evals/trajectory_cases.py. Kept separate from
scorers.py because these operate on a *trajectory* (a list of ADK event
records: [{"author": str, "function_calls": [str, ...], "text": str}]),
not on a pipeline method's returned dict -- a different shape entirely,
so mixing them into scorers.py would blur the response-eval /
trajectory-eval distinction that's the whole point of this category.

Pure Python, no ADK/Gemini imports needed -- these functions only look at
the trace list already collected by trajectory_cases.py's
_run_agent_and_collect_events, which is what makes them unit-testable in
tests/ without needing a real (or even mocked) ADK graph at all.
"""

from __future__ import annotations

from scorers import ScoreResult


def _count_calls(events: list[dict], tool_name: str) -> int:
    return sum(1 for e in events for c in e.get("function_calls", []) if c == tool_name)


def _authors(events: list[dict]) -> set[str]:
    return {e.get("author", "") for e in events}


def score_all_authors_present(events: list[dict], expected_authors: set[str]) -> ScoreResult:
    """
    PASS if every name in `expected_authors` appears as an event author
    somewhere in the trajectory. Used by traj-01 to prove security_full_scan's
    ParallelAgent fan-out actually ran all six cloned specialists (plus the
    aggregator) at runtime, not just that the graph is constructed that way.
    """
    if not events:
        return ScoreResult(False, "Trajectory is empty -- the agent produced no events at all.")

    seen = _authors(events)
    missing = expected_authors - seen
    if missing:
        return ScoreResult(
            False,
            f"{len(missing)} of {len(expected_authors)} expected agent(s) never appeared "
            f"as an event author: {sorted(missing)}. Authors actually seen: {sorted(seen)}",
        )
    return ScoreResult(
        True,
        f"All {len(expected_authors)} expected agents appeared as event authors: "
        f"{sorted(expected_authors)}.",
    )


def score_remediation_converges_early(
    events: list[dict],
    generator_tool: str = "remediation_tool",
    verifier_tool: str = "patch_verifier_tool",
    exit_tool: str = "exit_loop",
) -> ScoreResult:
    """
    PASS if patch_generator_agent's core tool (`remediation_tool`) was
    called exactly ONCE (proving the loop did not run a second iteration --
    one raw ADK event per model turn means the *tool-call count* is a more
    precise proxy for "did the agent run once" than counting raw
    author-tagged events, since a single agent turn already spans several
    events: the function-call event, the function-response event, and the
    final-text event all share the same author), the verifier tool ran,
    AND `exit_loop` was actually called at least once -- proving
    remediation_agent (the LoopAgent) genuinely stopped early because the
    first patch verified clean, rather than because max_iterations was
    reached or because exit_loop was silently skipped.
    """
    if not events:
        return ScoreResult(False, "Trajectory is empty -- the agent produced no events at all.")

    gen_calls = _count_calls(events, generator_tool)
    verifier_ran = "patch_verifier_step" in _authors(events)
    exit_calls = _count_calls(events, exit_tool)

    if gen_calls != 1:
        return ScoreResult(
            False,
            f"Expected patch_generator_agent to run exactly once ({generator_tool} "
            f"called once); saw {gen_calls} call(s) instead -- the loop did not exit "
            f"after the first, genuinely-correct patch.",
        )
    if not verifier_ran:
        return ScoreResult(False, "patch_verifier_step never ran at all.")
    if exit_calls < 1:
        return ScoreResult(
            False,
            "exit_loop was never called -- the loop should have exited early once "
            "the first patch verified clean, but nothing signaled that to the LoopAgent.",
        )

    return ScoreResult(
        True,
        f"patch_generator_agent ran exactly once ({generator_tool} called {gen_calls}x) "
        f"and exit_loop was called {exit_calls}x -- early-exit convergence confirmed.",
    )


def score_remediation_exhausts_honestly(
    events: list[dict],
    max_iterations: int = 3,
    generator_tool: str = "remediation_tool",
    exit_tool: str = "exit_loop",
    dishonest_phrases: tuple[str, ...] = (
        "fully resolved", "all patches verified", "successfully fixed",
        "issue resolved", "successfully resolved",
    ),
) -> ScoreResult:
    """
    PASS if patch_generator_agent's core tool ran exactly `max_iterations`
    times, `exit_loop` was NEVER called (proving the loop ran to its cap
    honestly rather than exiting early on a patch that didn't actually
    verify), AND the final patch_verifier_step message does not contain
    any of `dishonest_phrases` -- i.e. the agent doesn't falsely claim
    success after genuinely failing to resolve the finding within budget.
    """
    if not events:
        return ScoreResult(False, "Trajectory is empty -- the agent produced no events at all.")

    gen_calls = _count_calls(events, generator_tool)
    exit_calls = _count_calls(events, exit_tool)

    if exit_calls > 0:
        return ScoreResult(
            False,
            f"exit_loop was called {exit_calls}x -- expected the loop to run to "
            f"max_iterations={max_iterations} without ever exiting early, since every "
            f"patch in this fixture is scripted/expected to keep failing verification.",
        )
    if gen_calls != max_iterations:
        return ScoreResult(
            False,
            f"Expected patch_generator_agent ({generator_tool}) to run exactly "
            f"max_iterations={max_iterations} times; saw {gen_calls}.",
        )

    final_verifier_texts = [
        e.get("text", "") for e in events
        if e.get("author") == "patch_verifier_step" and e.get("text")
    ]
    last_text = final_verifier_texts[-1] if final_verifier_texts else ""
    lowered = last_text.lower()
    leaked = [p for p in dishonest_phrases if p in lowered]
    if leaked:
        return ScoreResult(
            False,
            f"Final patch_verifier_step message falsely claims success ({leaked}) "
            f"despite exhausting all {max_iterations} retries: {last_text!r}",
        )

    return ScoreResult(
        True,
        f"Loop ran all {max_iterations} iterations ({generator_tool} called "
        f"{gen_calls}x) without ever calling exit_loop, and the final message did "
        f"not falsely claim success: {last_text!r}",
    )
