"""
evals/cases.py
----------------
20 scenario-based eval cases exercising the code-review pipeline end to
end -- not individual functions. Each case calls a real CodeReviewAgent
method (same objects the ADK tools proxy to) against realistic fixture
files or synthetic finding data, and scores the actual returned result.

Categories (see README.md for the full rationale):
  detection        (9 cases) -- does the pipeline catch known-bad patterns?
  false_positive    (4 cases) -- does validate_findings_tool reject
                                  fabricated findings against clean code?
  dedup             (3 cases) -- does dedup_agent merge true duplicates and
                                  leave distinct findings alone?
  risk_scoring      (2 cases) -- does risk_scorer_agent rank obvious
                                  CRITICAL above obvious LOW?
  cost_estimate     (2 cases) -- does the RPD/token math in server.py match
                                  its sibling in view_trace.py? (no LLM)

Only the cost_estimate cases require no live Gemini call. Every other
case's `run()` makes a real API call in --mode live, and returns a
pre-scripted "ideal" response in --mode mock (a harness self-test only --
see runner.py and README.md for what mock mode does and does NOT prove).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from scorers import (
    ScoreResult,
    score_dedup_merges,
    score_detection,
    score_false_positive,
    score_risk_ordering,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@dataclass
class EvalCase:
    id: str
    category: str
    description: str
    run: Callable[[Any, Path], Any]          # (agent, fixtures_dir) -> raw result
    score: Callable[[Any], ScoreResult]
    mock_text: str = ""                       # canned JSON text for --mode mock
    needs_agent: bool = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_file(relpath: str):
    """Load a fixture as a github_fetcher.FileResult-shaped object."""
    from github_fetcher import FileResult
    full = FIXTURES_DIR / relpath
    content = full.read_text()
    return FileResult(path=relpath, content=content, sha="eval", size=len(content), url="")


def _review_issue(path: str, line: int, severity: str, title: str, description: str):
    from gemini_reviewer import ReviewIssue
    return ReviewIssue(
        path=path, line=line, severity=severity, title=title,
        description=description, suggested_fix="", rule_id=None,
    )


# ---------------------------------------------------------------------------
# Category 1 — Detection accuracy (9 cases)
# ---------------------------------------------------------------------------

def _detection_case(id_, description, fixture, method_name, path_kw, keywords, mock_findings,
                     result_key="findings"):
    def run(agent, fixtures_dir):
        files = [_load_file(fixture)]
        method = getattr(agent, method_name)
        return method(files)

    def score(result):
        return score_detection(result, expected_path_substring=path_kw, expected_keywords=keywords,
                                result_key=result_key)

    mock = json.dumps({result_key: mock_findings, "summary": "mock summary"})
    return EvalCase(id_, "detection", description, run, score, mock_text=mock)


DETECTION_CASES = [
    _detection_case(
        "det-01-sqli", "SQL injection via f-string in a Flask route",
        "vulnerable/sqli.py", "generate_injection_audit", "sqli.py",
        ["sql", "injection"],
        [{"path": "vulnerable/sqli.py", "line": 20, "severity": "CRITICAL",
          "injection_type": "SQL", "vulnerable_code": "f\"SELECT ... {name}\"",
          "attack_vector": "' OR 1=1--", "attack_chain": "unsanitized name -> query",
          "impact": "data exfiltration", "fix": "use parameterized queries"}],
    ),
    _detection_case(
        "det-02-command-injection", "Command injection via shell=True with user input",
        "vulnerable/command_injection.py", "generate_injection_audit", "command_injection.py",
        ["command", "shell"],
        [{"path": "vulnerable/command_injection.py", "line": 15, "severity": "CRITICAL",
          "injection_type": "CMD", "vulnerable_code": "shell=True",
          "attack_vector": "; rm -rf /", "attack_chain": "host param -> subprocess",
          "impact": "RCE", "fix": "use shlex + shell=False"}],
    ),
    _detection_case(
        "det-03-hardcoded-secrets", "Hardcoded AWS keys, DB password, and Stripe key",
        "vulnerable/hardcoded_secrets.py", "generate_secrets_audit", "hardcoded_secrets.py",
        ["secret", "key", "password", "credential"],
        [{"path": "vulnerable/hardcoded_secrets.py", "line": 8, "severity": "CRITICAL",
          "secret_type": "AWS access key", "description": "hardcoded AWS credentials"}],
    ),
    _detection_case(
        "det-04-weak-crypto-md5", "MD5 used for password hashing",
        "vulnerable/weak_crypto.py", "generate_crypto_audit", "weak_crypto.py",
        ["md5"],
        [{"path": "vulnerable/weak_crypto.py", "line": 12, "severity": "HIGH",
          "pattern": "MD5 password hashing", "current_code": "hashlib.md5(...)",
          "why_dangerous": "no salt, fast to brute force",
          "correct_alternative": "bcrypt", "attacker_effort": "minutes"}],
    ),
    _detection_case(
        "det-05-idor", "IDOR: no ownership check on invoice lookup by ID",
        "vulnerable/idor.py", "generate_auth_audit", "idor.py",
        ["idor", "ownership", "access control", "authorization"],
        [{"path": "vulnerable/idor.py", "line": 20, "severity": "HIGH",
          "vuln_type": "IDOR", "description": "no ownership check on invoice_id"}],
    ),
    _detection_case(
        "det-06-ssrf", "SSRF via unvalidated user-supplied URL",
        "vulnerable/ssrf.py", "generate_injection_audit", "ssrf.py",
        ["ssrf"],
        [{"path": "vulnerable/ssrf.py", "line": 13, "severity": "HIGH",
          "injection_type": "SSRF", "vulnerable_code": "requests.get(url)",
          "attack_vector": "http://169.254.169.254/", "attack_chain": "url param -> requests.get",
          "impact": "cloud metadata read", "fix": "allowlist destinations"}],
    ),
    _detection_case(
        "det-07-path-traversal", "Path traversal via unsanitized filename",
        "vulnerable/path_traversal.py", "generate_injection_audit", "path_traversal.py",
        ["path traversal", "traversal"],
        [{"path": "vulnerable/path_traversal.py", "line": 14, "severity": "HIGH",
          "injection_type": "PATH_TRAVERSAL", "vulnerable_code": "os.path.join(UPLOAD_DIR, filename)",
          "attack_vector": "../../../../etc/passwd", "attack_chain": "filename -> os.path.join",
          "impact": "arbitrary file read", "fix": "normalize + containment check"}],
    ),
    _detection_case(
        "det-08-taint-dataflow", "Multi-hop taint flow: query param -> 2 helpers -> os.system",
        "vulnerable/taint_dataflow.py", "generate_data_flow_analysis", "taint_dataflow.py",
        ["os.system", "cmd"],
        [{"path": "vulnerable/taint_dataflow.py", "source_line": 22, "sink_line": 27,
          "source": "request.args.get('report_name')", "sink": "os.system(command)",
          "sink_type": "CMD", "intermediate_steps": ["_normalize_report_name", "_build_export_command"],
          "sanitizers_present": ["none"], "sanitization_adequate": False,
          "severity": "CRITICAL", "exploit": "report_name='x; rm -rf /' -> arbitrary command execution"}],
        # generate_data_flow_analysis is the one specialist method whose JSON
        # schema doesn't use "findings" as the top-level list key -- it uses
        # "tainted_paths" (see DATA_FLOW_SYSTEM_INSTRUCTION in
        # gemini_reviewer.py). Scoring this case against "findings" like
        # every other detection case silently always fails, regardless of
        # what the model actually returns -- caught by the first live eval
        # run (det-08 reported "no findings" when the real bug was in this
        # scorer, not the pipeline).
        result_key="tainted_paths",
    ),
    _detection_case(
        "det-09-xxe", "XXE via ElementTree.fromstring on untrusted XML",
        "vulnerable/xxe.py", "generate_injection_audit", "xxe.py",
        ["xxe", "xml", "entity"],
        [{"path": "vulnerable/xxe.py", "line": 15, "severity": "HIGH",
          "injection_type": "XXE", "vulnerable_code": "ET.fromstring(xml_body)",
          "attack_vector": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>",
          "attack_chain": "request body -> ET.fromstring", "impact": "local file read",
          "fix": "use defusedxml"}],
    ),
]


# ---------------------------------------------------------------------------
# Category 2 — False-positive rate (4 cases)
# ---------------------------------------------------------------------------

def _false_positive_case(id_, description, fixture, fabricated_issue, mock_confidence="LOW", mock_fp=True):
    def run(agent, fixtures_dir):
        files = [_load_file(fixture)]
        issues = [fabricated_issue]
        return agent.validate_review_findings(issues, files)

    def score(result):
        return score_false_positive(result, target_index=0)

    mock = json.dumps({"validations": [
        {"index": 0, "confidence": mock_confidence, "false_positive": mock_fp,
         "note": "mock: code is actually safe"},
    ]})
    return EvalCase(id_, "false_positive", description, run, score, mock_text=mock)


FALSE_POSITIVE_CASES = [
    _false_positive_case(
        "fp-01-safe-parameterized-login",
        "Fabricated 'SQL injection' claim against a query that is actually parameterized",
        "clean/safe_auth.py",
        _review_issue("clean/safe_auth.py", 36, "CRITICAL", "SQL Injection",
                       "User input is concatenated directly into the SQL query at this line."),
    ),
    _false_positive_case(
        "fp-02-enum-table-name",
        "Fabricated 'SQL injection' claim against an f-string that only interpolates a "
        "fixed internal enum value, never user input",
        "clean/parameterized_sql.py",
        _review_issue("clean/parameterized_sql.py", 24, "HIGH", "SQL Injection",
                       "The table name is built with an f-string, allowing SQL injection."),
    ),
    _false_positive_case(
        "fp-03-stale-scary-comment",
        "Fabricated 'plaintext password storage' claim against code whose scary-sounding "
        "comment/variable names don't reflect what the code actually does (bcrypt)",
        "clean/commented_todo.py",
        _review_issue("clean/commented_todo.py", 20, "CRITICAL", "Plaintext Password Storage",
                       "The TODO comment confirms passwords are stored insecurely at this line."),
    ),
    _false_positive_case(
        "fp-04-secure-token-gen",
        "Fabricated 'predictable token' claim against code using the `secrets` module correctly",
        "clean/safe_token_gen.py",
        _review_issue("clean/safe_token_gen.py", 10, "HIGH", "Predictable Token Generation",
                       "Token generation uses a non-cryptographic random source, making tokens guessable."),
    ),
]


# ---------------------------------------------------------------------------
# Category 3 — Dedup effectiveness (3 cases)
# ---------------------------------------------------------------------------

def _finding(source_agent, path, line, severity, title, description):
    return {
        "source_agent": source_agent, "path": path, "line": line,
        "severity": severity, "title": title, "description": description,
    }


DEDUP_EXACT_DUPLICATE = [
    _finding("sast_agent", "vulnerable/sqli.py", 20, "CRITICAL",
              "SQL Injection", "User input concatenated into SQL query via f-string."),
    _finding("injection_agent", "vulnerable/sqli.py", 20, "CRITICAL",
              "SQL injection vulnerability", "Unsanitized 'name' parameter reaches a raw SQL query."),
]

DEDUP_NEAR_DUPLICATE = [
    _finding("sast_agent", "vulnerable/sqli.py", 20, "CRITICAL",
              "SQL Injection in search_users", "f-string query built from request.args."),
    _finding("injection_agent", "vulnerable/sqli.py", 21, "CRITICAL",
              "SQL Injection", "Same query construction, flagged one line later (the execute() call)."),
]

DEDUP_DISTINCT = [
    _finding("sast_agent", "vulnerable/sqli.py", 20, "CRITICAL",
              "SQL Injection", "f-string query in search_users."),
    _finding("secrets_agent", "vulnerable/hardcoded_secrets.py", 8, "CRITICAL",
              "Hardcoded AWS Key", "AWS access key hardcoded in source."),
    _finding("crypto_agent", "vulnerable/weak_crypto.py", 12, "HIGH",
              "Weak Hash (MD5)", "MD5 used for password hashing."),
]


def _dedup_case(id_, description, findings, expect_merge, mock_dedup_count):
    def run(agent, fixtures_dir):
        return agent.deduplicate_findings(findings)

    def score(result):
        return score_dedup_merges(result, original_count=len(findings), expect_merge=expect_merge)

    mock = json.dumps({
        "deduplicated_findings": findings[:mock_dedup_count],
        "original_count": len(findings),
        "deduplicated_count": mock_dedup_count,
        "merges_performed": len(findings) - mock_dedup_count,
        "summary": "mock dedup summary",
    })
    return EvalCase(id_, "dedup", description, run, score, mock_text=mock)


DEDUP_CASES = [
    _dedup_case(
        "dedup-01-exact-duplicate",
        "Same SQLi at the exact same file+line, reported by sast_agent and injection_agent "
        "under different titles -- should merge into 1",
        DEDUP_EXACT_DUPLICATE, expect_merge=True, mock_dedup_count=1,
    ),
    _dedup_case(
        "dedup-02-near-duplicate",
        "Same SQLi reported at adjacent lines (20 vs 21) by two agents describing the query "
        "build vs. the execute() call -- should still merge into 1",
        DEDUP_NEAR_DUPLICATE, expect_merge=True, mock_dedup_count=1,
    ),
    _dedup_case(
        "dedup-03-distinct-not-merged",
        "Three genuinely different findings (SQLi, hardcoded key, weak hash) in three "
        "different files -- must NOT be collapsed into fewer than 3",
        DEDUP_DISTINCT, expect_merge=False, mock_dedup_count=3,
    ),
]


# ---------------------------------------------------------------------------
# Category 4 — Risk scoring correctness (2 cases)
# ---------------------------------------------------------------------------

RISK_CRITICAL_VS_LOW = [
    _finding("secrets_agent", "vulnerable/hardcoded_secrets.py", 12, "CRITICAL",
              "Hardcoded Production Database Password",
              "The production database password is committed in plaintext in source control, "
              "reachable by anyone with repo read access, granting full read/write to prod data."),
    _finding("quality_agent", "app.py", 200, "LOW",
              "Verbose Error Message",
              "A caught exception's str() is included in a log line at DEBUG level; "
              "not exposed to end users, low information value to an attacker."),
]

RISK_RCE_VS_INFO_LEAK = [
    _finding("injection_agent", "vulnerable/command_injection.py", 15, "CRITICAL",
              "Remote Code Execution via Command Injection",
              "Unauthenticated endpoint passes user input directly to shell=True subprocess, "
              "allowing arbitrary command execution with the application's privileges."),
    _finding("doc_agent", "utils.py", 5, "LOW",
              "Missing Docstring on Internal Helper",
              "A private helper function has no docstring; purely a maintainability concern, "
              "no security relevance."),
]


def _risk_case(id_, description, findings, high_title_kw, low_title_kw, mock_scores):
    def run(agent, fixtures_dir):
        return agent.generate_risk_scores(findings)

    def score(result):
        return score_risk_ordering(result, high_finding_title=high_title_kw, low_finding_title=low_title_kw)

    mock = json.dumps({
        "scored_findings": mock_scores,
        "overall_project_score": 7.5, "overall_risk_level": "HIGH",
        "immediate_action_required": [findings[0]["title"]],
        "summary": "mock risk summary",
    })
    return EvalCase(id_, "risk_scoring", description, run, score, mock_text=mock)


RISK_SCORING_CASES = [
    _risk_case(
        "risk-01-critical-vs-low",
        "Hardcoded prod DB password (CRITICAL) must outrank a DEBUG-level log message (LOW)",
        RISK_CRITICAL_VS_LOW, "Hardcoded Production Database Password", "Verbose Error Message",
        mock_scores=[
            {"finding_index": 0, "title": "Hardcoded Production Database Password",
             "impact_score": 9.0, "exploitability_score": 9.0, "scope_score": 9.0,
             "detectability_score": 3.0, "composite_score": 8.4, "risk_level": "CRITICAL",
             "priority_rank": 1, "rationale": "mock"},
            {"finding_index": 1, "title": "Verbose Error Message",
             "impact_score": 2.0, "exploitability_score": 1.0, "scope_score": 1.0,
             "detectability_score": 8.0, "composite_score": 1.9, "risk_level": "LOW",
             "priority_rank": 2, "rationale": "mock"},
        ],
    ),
    _risk_case(
        "risk-02-rce-vs-doc-gap",
        "Unauthenticated RCE (CRITICAL) must outrank a missing docstring (LOW)",
        RISK_RCE_VS_INFO_LEAK, "Remote Code Execution", "Missing Docstring",
        mock_scores=[
            {"finding_index": 0, "title": "Remote Code Execution via Command Injection",
             "impact_score": 10.0, "exploitability_score": 9.0, "scope_score": 10.0,
             "detectability_score": 4.0, "composite_score": 9.4, "risk_level": "CRITICAL",
             "priority_rank": 1, "rationale": "mock"},
            {"finding_index": 1, "title": "Missing Docstring on Internal Helper",
             "impact_score": 0.5, "exploitability_score": 0.0, "scope_score": 0.5,
             "detectability_score": 9.0, "composite_score": 1.1, "risk_level": "LOW",
             "priority_rank": 2, "rationale": "mock"},
        ],
    ),
]


# ---------------------------------------------------------------------------
# Category 5 — Cost-estimate correctness (2 cases, no LLM)
# ---------------------------------------------------------------------------
# Defined in eval_cost_estimate.py (kept separate: these don't take the
# (agent, fixtures_dir) -> raw_result shape the LLM-backed cases use, since
# they operate on synthetic trace.jsonl spans instead).

ALL_CASES: list[EvalCase] = (
    DETECTION_CASES + FALSE_POSITIVE_CASES + DEDUP_CASES + RISK_SCORING_CASES
)
