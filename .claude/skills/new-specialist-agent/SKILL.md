---
name: new-specialist-agent
description: Scaffold a new ADK specialist agent for the code review agent's 5-layer multi-agent system, following this repo's full spec-driven convention end to end (spec, tool, agent, coordinator wiring, tests, eval case, README). Use when asked to add a new specialist, auditor, or check to the code review agent -- e.g. "add a specialist that checks for X", "add a new security/quality/intel agent".
---

# New Specialist Agent

Scaffolds a new specialist agent for `agent.py`'s 5-layer, 29-agent ADK graph,
producing every artifact this repo's conventions require -- not just the agent
definition. Skipping any step here is how a specialist ends up untested,
unrouted, or undocumented; don't skip steps to save time.

## Before starting: clarify with the user if not already clear

1. **What does it audit?** One narrow domain, same granularity as existing
   specialists (`crypto_agent` = weak hashing/ECB/hardcoded keys; not
   "general security" -- that's what `security_coordinator` is for).
2. **Which layer/coordinator does it belong under?**
   `security_coordinator` (security specialists), `quality_coordinator`
   (quality specialists), `intel_coordinator` (intel specialists), or is
   this actually a new Layer-1 strategic agent (rare -- only if it doesn't
   fit any existing domain, like `context_agent` or `pr_agent` didn't)?
3. **Does it need a sub-specialist of its own** (Layer 4, like
   `validator_agent` under `sast_agent`)? Most new specialists don't.

## Step 1 -- Spec first (specs/<name>_spec.md)

This repo writes a spec before implementing, always. Model it on
`specs/agent_spec.md` and `specs/gemini_reviewer_spec.md`. At minimum cover:
purpose, public interface (the tool function's signature and return dict
shape), behavior (what the audit actually checks for, step by step), error
handling (best-effort vs. fatal -- specialists should almost always be
best-effort, matching the rest of the pipeline's philosophy), and a test
table listing every planned test by name and expected outcome. Write the
test table BEFORE writing the tests -- that's the point of spec-driven
development here, not a formality.

## Step 2 -- The tool factory function (agent.py)

Follow the exact pattern of every existing `make_<x>_tool` function (e.g.
`make_crypto_audit_tool`, `make_injection_audit_tool`): a factory that takes
`agent: CodeReviewAgent` and returns a plain function with a docstring ADK
uses as the tool's description. The returned function validates its inputs,
calls into an underlying method (usually a new method on `GeminiReviewer` in
gemini_reviewer.py, following that file's `_call_model`/caching conventions
-- do not bypass the existing cache/retry/fallback machinery), and returns a
JSON-serializable dict via explicit field mapping (never `vars()`/`__dict__`
dumped wholesale -- see agent_spec.md section 3.5 for why).

## Step 3 -- The Agent definition (agent.py, inside build_multi_agent_system())

```python
new_specialist_agent = Agent(
    name="new_specialist_agent",
    model=DEFAULT_MODEL,
    description="One-line role, matching the style of every other agent's description field.",
    instruction=(
        "You are the <Role Name>. <one-sentence framing of the job>.\n\n"
        "WORKFLOW:\n"
        "1. fetch_repo_files_tool -- pull Python files.\n"
        "2. <new_tool_name> -- <what it checks>.\n\n"
        "<Any presentation format guidance -- e.g. CRITICAL->LOW ordering, "
        "file:line references, concrete attack vectors -- matching sibling "
        "specialists in the same coordinator.>\n\n"
        "Transfer back to <coordinator_name> when done. Use trigger phrases: "
        "'<phrase 1>', '<phrase 2>'."
    ),
    tools=[_ft(make_fetch_repo_files_tool), _ft(make_new_specialist_tool)],
)
```

Match the instruction TONE and STRUCTURE of sibling agents under the same
coordinator exactly -- read 2-3 of them first (e.g. if this is a security
specialist, read `injection_agent`, `auth_agent`, and `crypto_agent`'s
instructions before writing this one).

## Step 4 -- Wire into the coordinator

Add the new agent to the coordinator's `sub_agents=[...]` list, AND update
that coordinator's instruction ROUTING block (the bullet list mapping
trigger phrases to specialists) to include a line for the new specialist.
Both are required -- adding to `sub_agents` alone leaves the coordinator's
own LLM routing logic unaware the new option exists. If the coordinator has
a "full review -> all N sequentially" line, update the count.

If this specialist is part of a deterministic `ParallelAgent` fan-out (like
`security_full_scan`'s six specialists), it also needs an `output_key` and
must be added to that ParallelAgent's `sub_agents` list, and the aggregator
agent's instruction must be updated to read its new `{output_key}`.

## Step 5 -- Tests (tests/test_agent.py)

Mirror the existing construction-level test pattern for sibling agents:
agent exists and is reachable from its coordinator's `sub_agents`, has the
expected tools, and (if applicable) the expected `output_key`. Add these
as a new `TestNewSpecialistAgent`-style class, matching the style of
`TestSecurityFullScan`/`TestRemediationLoop`. Run `pytest -v` and confirm
100% of the existing suite still passes alongside the new tests -- do not
proceed to Step 6 if anything broke.

## Step 6 -- Eval case (evals/)

Add a `detection`-style case (see `evals/cases.py`'s `_detection_case`
helper and `evals/README.md`) with a new synthetic fixture in
`evals/fixtures/vulnerable/` (or `fixtures/clean/` if this is a
false-positive-style check) demonstrating the exact pattern this specialist
targets. Follow the existing scorer pattern in `evals/scorers.py` --
loose on wording, strict on the structural thing being measured (right
file, right category keyword). Do not mock the Gemini call in the eval
case itself -- that's what `tests/` is for; evals call the real method.

## Step 7 -- README.md

Update: the agent count badge, the mermaid architecture diagram (add the
node and its edge from the coordinator), the ASCII architecture block, the
agent roles table (add a row), and the routing table (add the trigger
phrase mapping). Every other agent added to this repo has all five of
these updated in the same commit that added the agent -- don't leave the
diagram or badge stale.

## Step 8 -- Verify before reporting done

```bash
pytest -v                                    # full suite still green
cd evals && python3 runner.py --category detection   # or the relevant category, mock mode
```

Report back: what the new specialist checks for, which coordinator it's
under, and confirm both commands above passed. If a `GEMINI_API_KEY` is
available, also run the new eval case in `--mode live` and report the
actual result -- mock mode only proves the harness plumbing, not that the
specialist's judgment is any good (see `evals/README.md`'s "Why this needs
a real API key" section).
