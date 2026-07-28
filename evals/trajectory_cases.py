"""
evals/trajectory_cases.py
---------------------------
Trajectory eval cases: verify security_full_scan and remediation_loop
actually BEHAVE the way they're built to at runtime -- which agents fired,
in what order, and (for remediation_loop) whether exit_loop was really
called -- not just that the ADK graph is *constructed* correctly.
tests/test_agent.py's TestSecurityFullScan / TestRemediationLoop classes
already cover construction (right agent types, right sub_agents, right
clones, right output_keys) by inspecting build_multi_agent_system()'s
returned tree without running it. This module is deliberately about the
other half: actually running the graph via InMemoryRunner and inspecting
the real event trace.

Structurally separate from cases.py (the 23 response-eval cases) because
the two eval flavors score fundamentally different things:

  response eval (cases.py)   -- does CodeReviewAgent's judgment/output
                                 look right for a given input?
  trajectory eval (this file) -- did the actual ADK agent graph run the
                                 SEQUENCE of agents/tool-calls it's
                                 supposed to?

Design decisions (see README.md's "Trajectory cases" section for the
full writeup):

1. ADK's own eval framework (AgentEvaluator / *.evalset.json / `adk eval`)
   expects a fixed on-disk agent module exposing `root_agent`, and scores
   tool-call trajectory against a hand-authored expected sequence loaded
   from JSON. Our agent is a factory (build_multi_agent_system(github_
   token, gemini_api_key)) needing runtime secrets, and what we actually
   want here is to verify a specific SUB-TREE's deterministic behavior
   (security_full_scan / remediation_agent), invoked directly rather than
   via root's own LLM-driven routing decision (which is a separate,
   already-tested concern -- root's routing instructions, not these two
   constructs' internal behavior). Hand-rolled trace inspection via
   InMemoryRunner is a better fit than forcing this through evalset JSON
   and a `root_agent`-shaped module this repo doesn't otherwise have.

2. security_full_scan's ParallelAgent/SequentialAgent fan-out is
   deterministic Python control flow in ADK (workflow agents don't make an
   LLM routing decision the way an Agent/LlmAgent does) -- once invoked,
   all 6 cloned specialists (sast_agent_scan, injection_agent_scan,
   auth_agent_scan, crypto_agent_scan, secrets_agent_scan,
   data_flow_agent_scan -- clones, not the plain-named L3 specialists; see
   agent.py's build_multi_agent_system docstring for why) run and the
   aggregator runs after, regardless of what each specialist's own LLM
   call says. So --mode mock for traj-01 only needs ONE canned,
   content-free Gemini response (no tool calls) to prove this
   trajectory-level guarantee -- the interesting judgment-call content
   (does each specialist actually find its bug) is already covered by
   sec-full-01 in cases.py and the detection-category cases.

3. remediation_loop's early-exit (traj-02) and honest-exhaustion (traj-03)
   behavior IS an LLM decision (patch_verifier_step deciding whether to
   call exit_loop) -- ADK's LoopAgent control flow can't prove this on its
   own the way ParallelAgent's fan-out can. So --mode mock for traj-02/03
   scripts the exact sequence of model turns via _ScriptedGemini, an
   ordered-queue patch of google.adk.models.google_llm.Gemini.
   generate_content_async -- the ADK graph's OWN network-call method. This
   is new mocking surface for this repo: distinct from GeminiReviewer's
   calls (mocked elsewhere via agent.GeminiReviewer, e.g.
   tests/test_agent.py's _build_root()), since no prior test ran the ADK
   graph end to end. Both mocks are used together for traj-02/03: agent.
   GeminiReviewer controls what CodeReviewAgent.generate_remediation_
   patches/verify_patch return (the business logic), _ScriptedGemini
   controls what the ADK LlmAgent turns actually decide to call (the
   graph-level routing/tool-call decisions).

4. --mode live: traj-01 and traj-02 run for real (real GitHub fetch, real
   Gemini judgment) -- traj-02 uses a deliberately unambiguous fixture
   (hardcoded password -> read from env var) so a real first-attempt
   patch is very likely to verify clean, same trade-off cases.py's own
   rem-01-verify-refine-converges-on-retry case already makes for its
   LLM-judged verification fallback. traj-03 needs the OPPOSITE guarantee
   (verification must keep failing for 3 full iterations), which no real
   fixture can reliably force -- a real model might generate a genuinely
   correct fix on attempt 2. Per the task's explicit allowance to mock at
   the tool level when a reliable live-failure scenario is impractical,
   traj-03's --mode live still uses REAL Gemini calls for the graph's own
   decisions (patch_generator_agent really generates, patch_verifier_step
   really decides whether to call exit_loop) but patches
   agent.CodeReviewAgent.verify_patch at the class level to always report
   "not resolved" -- forcing the one input this test needs to control
   (ground-truth verification) while leaving everything else live.

Kept intentionally minimal per repo convention: 3 concrete cases, one
shared runner helper (_run_events) and one shared mock helper
(_ScriptedGemini) -- no generic trajectory-testing framework.
"""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

_THIS_DIR = Path(__file__).parent
_REPO_ROOT = _THIS_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from google.adk.runners import InMemoryRunner
from google.adk.models import google_llm
from google.adk.models.llm_response import LlmResponse
from google.genai import types

from trajectory_scorers import (
    ScoreResult,
    score_all_authors_present,
    score_remediation_converges_early,
    score_remediation_exhausts_honestly,
)

DEMO_REPO_URL = "https://github.com/anxolerd/dvpwa"  # same demo repo scripts/adk_demo.py uses


@dataclass
class TrajectoryCase:
    id: str
    description: str
    run: Callable[[str], list[dict]]           # (mode: "mock"|"live") -> trajectory events
    score: Callable[[list[dict]], ScoreResult]


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------

def _find_agent(root, name):
    """Depth-first search of an ADK agent tree by name (same helper
    tests/test_agent.py uses; duplicated rather than imported so evals/
    doesn't take a dependency on tests/)."""
    if root.name == name:
        return root
    for sub in getattr(root, "sub_agents", None) or []:
        found = _find_agent(sub, name)
        if found is not None:
            return found
    return None


def _build_root_mock():
    """Build the full ADK graph with GitHubFetcher/SemgrepRunner/GeminiReviewer
    all replaced by MagicMocks (no network, no real credentials needed) --
    same construction pattern as tests/test_agent.py's _build_root(). Returns
    (root, reviewer_mock) so callers can configure reviewer_mock.
    generate_remediation_patches / .verify_patch_resolves_finding for the
    remediation cases."""
    with patch("agent.GitHubFetcher"), patch("agent.SemgrepRunner"), \
         patch("agent.GeminiReviewer") as mock_gemini_cls:
        from agent import build_multi_agent_system
        root = build_multi_agent_system(github_token="ghp_evaltoken", gemini_api_key="gem_evalkey")
        reviewer_mock = mock_gemini_cls.return_value
    return root, reviewer_mock


def _build_root_live():
    """Build the full ADK graph with real credentials -- real GitHub fetch
    calls and real Gemini calls happen once the graph actually runs."""
    from agent import build_multi_agent_system

    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    if not gemini_key or not github_token:
        raise RuntimeError(
            "trajectory cases in --mode live need both GEMINI_API_KEY and a real "
            "GITHUB_TOKEN (traj-01 makes a real GitHub fetch call; all three make "
            "real Gemini calls for at least part of their run)."
        )
    return build_multi_agent_system(github_token=github_token, gemini_api_key=gemini_key)


async def _collect_events(target_agent, prompt: str, app_name: str) -> list[dict]:
    """Run `target_agent` (any ADK BaseAgent -- a sub-tree obtained via
    _find_agent, not necessarily root) via InMemoryRunner against `prompt`,
    and return a simplified per-event trace: [{"author", "function_calls",
    "text"}]. This is the actual runtime trace the trajectory cases assert
    against -- not a simulation of one."""
    runner = InMemoryRunner(agent=target_agent, app_name=app_name)
    session = await runner.session_service.create_session(app_name=app_name, user_id="eval_user")
    message = types.Content(role="user", parts=[types.Part(text=prompt)])

    trace: list[dict] = []
    async for event in runner.run_async(user_id="eval_user", session_id=session.id, new_message=message):
        calls: list[str] = []
        text = None
        if event.content and event.content.parts:
            for part in event.content.parts:
                fc = getattr(part, "function_call", None)
                if fc is not None:
                    calls.append(fc.name)
                if getattr(part, "text", None):
                    text = part.text
        trace.append({"author": event.author, "function_calls": calls, "text": text})
    return trace


def _run_events(target_agent, prompt: str, app_name: str) -> list[dict]:
    return asyncio.run(_collect_events(target_agent, prompt, app_name))


class _ScriptedGemini:
    """Mock-mode stand-in for the ADK graph's own model calls. Patches
    google.adk.models.google_llm.Gemini.generate_content_async (the real
    network-call method every Agent(model=...) in agent.py ultimately
    invokes) with an ordered FIFO queue of canned LlmResponse objects, one
    per model turn, popped in call order.

    This is a strict queue, not an agent-aware router: callers must supply
    responses in the exact order ADK will invoke the model, given the
    (deterministic once no further LLM routing decision is left to make)
    shape of the sub-tree under test. That's a reasonable trade for 3 fixed
    cases -- it would NOT scale to testing arbitrary/branching LLM
    routing, which is exactly why this repo isn't building a generic
    trajectory-testing framework around it (see module docstring, point 3).

    If the queue is exhausted and no `default` was given, raises --
    needing more turns than scripted is a bug in the script, not something
    to paper over with a made-up response.
    """

    def __init__(self, responses: list[LlmResponse] | None = None, default: LlmResponse | None = None):
        self._responses = list(responses or [])
        self._default = default
        self._i = 0

    async def _fake_generate_content_async(self, llm_request, stream: bool = False):
        if self._i < len(self._responses):
            response = self._responses[self._i]
            self._i += 1
        elif self._default is not None:
            response = self._default
        else:
            raise AssertionError(
                f"_ScriptedGemini exhausted after {self._i} scripted call(s) with no "
                f"default -- the script needs another canned LlmResponse for this turn."
            )
        yield response

    def __enter__(self):
        self._patcher = patch.object(
            google_llm.Gemini, "generate_content_async", self._fake_generate_content_async
        )
        self._patcher.start()
        return self

    def __exit__(self, *exc):
        self._patcher.stop()


def _text_response(text: str) -> LlmResponse:
    return LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))


def _function_call_response(name: str, args: dict) -> LlmResponse:
    return LlmResponse(content=types.Content(
        role="model",
        parts=[types.Part(function_call=types.FunctionCall(name=name, args=args))],
    ))


# ---------------------------------------------------------------------------
# traj-01 -- security_full_scan fan-out
# ---------------------------------------------------------------------------

_FULL_SCAN_SPECIALISTS = {
    "sast_agent_scan", "injection_agent_scan", "auth_agent_scan",
    "crypto_agent_scan", "secrets_agent_scan", "data_flow_agent_scan",
}
_FULL_SCAN_EXPECTED_AUTHORS = _FULL_SCAN_SPECIALISTS | {"security_aggregator_agent"}


def _case_full_scan_fanout() -> TrajectoryCase:
    def run(mode: str) -> list[dict]:
        prompt = f"Run a full, comprehensive security review of {DEMO_REPO_URL}."
        if mode == "mock":
            root, _ = _build_root_mock()
            target = _find_agent(root, "security_full_scan")
            assert target is not None, "security_full_scan not found in the built agent tree"
            with _ScriptedGemini(default=_text_response(
                "Mock specialist pass: no findings to report in this scripted run."
            )):
                return _run_events(target, prompt, "traj-full-scan-mock")
        else:
            root = _build_root_live()
            target = _find_agent(root, "security_full_scan")
            assert target is not None, "security_full_scan not found in the built agent tree"
            return _run_events(target, prompt, "traj-full-scan-live")

    def score(events: list[dict]) -> ScoreResult:
        return score_all_authors_present(events, _FULL_SCAN_EXPECTED_AUTHORS)

    return TrajectoryCase(
        "traj-01-full-scan-fanout",
        "Invokes security_full_scan directly (bypassing root's own LLM routing "
        "decision, which is a separate concern) via InMemoryRunner and asserts all "
        "6 cloned parallel specialists plus security_aggregator_agent actually "
        "appear as event authors in a REAL ADK run -- proving the ParallelAgent "
        "fan-out really happens at runtime, not just that it's constructed that way.",
        run, score,
    )


# ---------------------------------------------------------------------------
# traj-02 -- remediation_loop early exit (first patch genuinely correct)
# ---------------------------------------------------------------------------

_REM_FINDING = {
    "path": "config.py", "line": 4, "title": "Hardcoded database password",
    "description": "DB_PASSWORD is hardcoded in source instead of read from the environment.",
    "vulnerable_code": 'DB_PASSWORD = "hunter2"',
}
_REM_FILES = [{"path": "config.py", "content": 'DB_PASSWORD = "hunter2"\n'}]
_REM_PATCH = {
    "finding_index": 0, "path": "config.py", "line": 4,
    "title": "Hardcoded database password",
    "before": 'DB_PASSWORD = "hunter2"',
    "after": 'DB_PASSWORD = os.environ["DB_PASSWORD"]',
    "explanation": "Read the password from the environment instead of hardcoding it.",
    "dependencies": [], "breaking_change": False,
}
_REM_LIVE_PROMPT = (
    "Generate a patch for this finding and verify it resolves the finding: a "
    "hardcoded database password `DB_PASSWORD = \"hunter2\"` in config.py (line 4). "
    "Fix it by reading the password from the DB_PASSWORD environment variable "
    "instead of hardcoding it."
)


def _generator_turn_responses() -> list[LlmResponse]:
    return [
        _function_call_response("remediation_tool", {"findings": [_REM_FINDING], "files": _REM_FILES}),
        _text_response("Generated 1 patch."),
    ]


def _verifier_turn_responses(exit_now: bool) -> list[LlmResponse]:
    responses = [_function_call_response("patch_verifier_tool", {"finding": _REM_FINDING, "patch": _REM_PATCH})]
    if exit_now:
        responses.append(_function_call_response("exit_loop", {}))
        responses.append(_text_response("Patch verified resolved -- exiting the loop."))
    else:
        responses.append(_text_response(
            "Patch still does not resolve the finding; will retry with feedback."
        ))
    return responses


def _case_remediation_early_exit() -> TrajectoryCase:
    def run(mode: str) -> list[dict]:
        if mode == "mock":
            root, reviewer_mock = _build_root_mock()
            reviewer_mock.generate_remediation_patches.return_value = {
                "patches": [_REM_PATCH], "summary": "1 patch generated.",
            }
            reviewer_mock.verify_patch_resolves_finding.return_value = {
                "resolved": True, "reason": "No longer hardcoded.", "method": "llm",
            }
            target = _find_agent(root, "remediation_agent")
            assert target is not None, "remediation_agent not found in the built agent tree"

            script = _generator_turn_responses() + _verifier_turn_responses(exit_now=True)
            with _ScriptedGemini(script):
                return _run_events(target, "fix the hardcoded db password", "traj-rem-exit-mock")
        else:
            root = _build_root_live()
            target = _find_agent(root, "remediation_agent")
            assert target is not None, "remediation_agent not found in the built agent tree"
            return _run_events(target, _REM_LIVE_PROMPT, "traj-rem-exit-live")

    def score(events: list[dict]) -> ScoreResult:
        return score_remediation_converges_early(events)

    return TrajectoryCase(
        "traj-02-remediation-early-exit",
        "Invokes remediation_agent (the LoopAgent) directly against a fixture "
        "whose first generated patch is genuinely correct -- asserts "
        "patch_generator_agent's remediation_tool ran exactly once and exit_loop "
        "was actually called, proving the loop really stops early instead of "
        "always running to max_iterations regardless of whether it needs to.",
        run, score,
    )


# ---------------------------------------------------------------------------
# traj-03 -- remediation_loop honestly exhausts all retries
# ---------------------------------------------------------------------------

_REM_EXHAUST_LIVE_PROMPT = (
    "Generate a patch for this finding and verify it resolves the finding: a "
    "hardcoded database password `DB_PASSWORD = \"hunter2\"` in config.py (line 4)."
)


def _case_remediation_exhausts_retries() -> TrajectoryCase:
    def run(mode: str) -> list[dict]:
        if mode == "mock":
            root, reviewer_mock = _build_root_mock()
            reviewer_mock.generate_remediation_patches.return_value = {
                "patches": [_REM_PATCH], "summary": "1 patch generated.",
            }
            # Ground truth for this case: verification NEVER succeeds, no matter
            # how many times it's retried -- this is the one input traj-03 needs
            # to control deterministically (see module docstring, point 4).
            reviewer_mock.verify_patch_resolves_finding.return_value = {
                "resolved": False, "reason": "Still hardcoded (scripted for eval determinism).",
                "method": "llm",
            }
            target = _find_agent(root, "remediation_agent")
            assert target is not None, "remediation_agent not found in the built agent tree"

            script: list[LlmResponse] = []
            for _ in range(3):
                script += _generator_turn_responses() + _verifier_turn_responses(exit_now=False)
            with _ScriptedGemini(script):
                return _run_events(target, "fix the hardcoded db password", "traj-rem-exhaust-mock")
        else:
            root = _build_root_live()
            target = _find_agent(root, "remediation_agent")
            assert target is not None, "remediation_agent not found in the built agent tree"
            # Real Gemini calls decide everything EXCEPT ground-truth
            # verification, which is forced to always fail -- no real fixture
            # can reliably guarantee a real model keeps failing for 3 full
            # iterations (see module docstring, point 4).
            with patch("agent.CodeReviewAgent.verify_patch", return_value={
                "resolved": False,
                "reason": "Forced unresolved for traj-03 (--mode live tool-level mock; "
                           "see evals/trajectory_cases.py module docstring).",
                "method": "forced-fail",
            }):
                return _run_events(target, _REM_EXHAUST_LIVE_PROMPT, "traj-rem-exhaust-live")

    def score(events: list[dict]) -> ScoreResult:
        return score_remediation_exhausts_honestly(events, max_iterations=3)

    return TrajectoryCase(
        "traj-03-remediation-exhausts-retries",
        "Invokes remediation_agent directly against a fixture whose patches never "
        "verify -- asserts the loop runs all 3 iterations (remediation_tool called "
        "3x), exit_loop is NEVER called, and the final patch_verifier_step message "
        "honestly reports non-resolution rather than falsely claiming success. "
        "--mode live forces ground-truth verification to always fail (via "
        "agent.CodeReviewAgent.verify_patch) since no real fixture can reliably "
        "guarantee a real model keeps failing for 3 full iterations -- everything "
        "else in the run (generation, the exit/continue decision) is a real "
        "Gemini call. See this module's docstring, point 4, for the full rationale.",
        run, score,
    )


TRAJECTORY_CASES: list[TrajectoryCase] = [
    _case_full_scan_fanout(),
    _case_remediation_early_exit(),
    _case_remediation_exhausts_retries(),
]
