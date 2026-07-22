"""
tests/test_gemini_reviewer.py
-------------------------------
Full test suite for gemini_reviewer.py.
The Gemini SDK client is fully mocked — no live API calls, no real key
required.

Run with:
    pytest tests/test_gemini_reviewer.py -v
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from google.genai import errors as genai_errors

from gemini_reviewer import (
    DEFAULT_MODEL,
    FALLBACK_MODEL,
    MAX_RETRIES,
    SEMANTIC_CACHE_MODEL,
    SYSTEM_INSTRUCTION,
    GeminiAPIError,
    GeminiAuthenticationError,
    GeminiRateLimitError,
    GeminiResponseValidationError,
    GeminiReviewer,
    ReviewReport,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_file(path: str, content: str = "x = 1\n") -> SimpleNamespace:
    """Stand-in for github_fetcher.FileResult — only .path/.content are used."""
    return SimpleNamespace(path=path, content=content)


def make_finding(path: str, rule_id: str = "rule.x", severity: str = "WARNING",
                  line_start: int = 1, message: str = "msg") -> SimpleNamespace:
    """Stand-in for semgrep_runner.Finding."""
    return SimpleNamespace(path=path, rule_id=rule_id, severity=severity,
                            line_start=line_start, message=message)


def make_scan_report(findings=None) -> SimpleNamespace:
    """Stand-in for semgrep_runner.ScanReport."""
    return SimpleNamespace(findings=findings or [])


def response_text(summary: str = "ok", issues: list | None = None) -> SimpleNamespace:
    """Build a fake Gemini response object with a .text attribute."""
    payload = {"summary": summary, "issues": issues or []}
    return SimpleNamespace(text=json.dumps(payload))


def embedding_response(vector: list[float]) -> SimpleNamespace:
    """Stand-in for genai.types.EmbedContentResponse — only
    .embeddings[0].values is used by GeminiReviewer._embed()."""
    return SimpleNamespace(embeddings=[SimpleNamespace(values=vector)])


# Two near-unit vectors ~8 degrees apart -> cosine similarity ~0.99, above
# the 0.98 default threshold. Represents e.g. the same file with only a
# comment/whitespace change -- textually different, semantically almost
# identical.
NEAR_DUPLICATE_VECTOR_A = [1.0, 0.0]
NEAR_DUPLICATE_VECTOR_B = [0.99, 0.14107]  # cos(A, B) ≈ 0.99

# Orthogonal vector -> cosine similarity 0.0, a clear miss.
DISSIMILAR_VECTOR = [0.0, 1.0]


def make_reviewer(**kwargs) -> tuple[GeminiReviewer, MagicMock]:
    """Construct a GeminiReviewer with genai.Client mocked out entirely."""
    with patch("gemini_reviewer.genai.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        reviewer = GeminiReviewer(api_key="fake-key-123", **kwargs)
    return reviewer, mock_client


# ---------------------------------------------------------------------------
# 1. Construction / input validation
# ---------------------------------------------------------------------------

class TestConstruction:

    def test_empty_api_key_raises(self):
        with pytest.raises(ValueError, match="GEMINI_API_KEY must not be empty"):
            GeminiReviewer(api_key="")

    def test_empty_files_raises(self):
        reviewer, _ = make_reviewer()
        with pytest.raises(ValueError, match="No files to review"):
            reviewer.review([], make_scan_report())


# ---------------------------------------------------------------------------
# 2. Batching
# ---------------------------------------------------------------------------

class TestBatching:

    def test_batches_respect_max_files(self):
        reviewer, mock_client = make_reviewer(max_files_per_batch=10, max_chars_per_batch=1_000_000)
        files = [make_file(f"f{i}.py") for i in range(25)]
        mock_client.models.generate_content.return_value = response_text()

        reviewer.review(files, make_scan_report())

        assert mock_client.models.generate_content.call_count == 3

    def test_batches_respect_max_chars(self):
        reviewer, mock_client = make_reviewer(max_files_per_batch=100, max_chars_per_batch=100)
        big_content = "x" * 80
        files = [make_file("a.py", big_content), make_file("b.py", big_content)]
        mock_client.models.generate_content.return_value = response_text()

        reviewer.review(files, make_scan_report())

        assert mock_client.models.generate_content.call_count == 2

    def test_findings_filtered_per_batch(self):
        reviewer, mock_client = make_reviewer(max_files_per_batch=1, max_chars_per_batch=1_000_000)
        files = [make_file("a.py"), make_file("b.py")]
        findings = [make_finding("b.py", rule_id="rule.b")]
        mock_client.models.generate_content.return_value = response_text()

        reviewer.review(files, make_scan_report(findings))

        calls = mock_client.models.generate_content.call_args_list
        assert len(calls) == 2
        prompt_a = calls[0].kwargs["contents"]
        prompt_b = calls[1].kwargs["contents"]
        assert "rule.b" not in prompt_a
        assert "rule.b" in prompt_b


# ---------------------------------------------------------------------------
# 3. Output parsing
# ---------------------------------------------------------------------------

class TestOutputParsing:

    def test_parses_issues_correctly(self):
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        issues_payload = [
            {
                "path": "a.py", "line": 3, "severity": "HIGH",
                "title": "SQL injection risk", "description": "desc",
                "suggested_fix": "use parameterized queries", "rule_id": "rule.sql",
            },
            {
                "path": "a.py", "line": 10, "severity": "LOW",
                "title": "Unused import", "description": "desc2",
                "suggested_fix": "remove it", "rule_id": None,
            },
        ]
        mock_client.models.generate_content.return_value = response_text(issues=issues_payload)

        report = reviewer.review(files, make_scan_report())

        assert len(report.issues) == 2
        first = [i for i in report.issues if i.title == "SQL injection risk"][0]
        assert first.path == "a.py"
        assert first.line == 3
        assert first.severity == "HIGH"
        assert first.rule_id == "rule.sql"

    def test_invalid_severity_rejected(self):
        # Behavior change: an out-of-enum severity used to be silently
        # coerced to "MEDIUM" (a hijacked/malformed response could smuggle
        # bad data straight through). It's now a hard schema-validation
        # failure — the batch is dropped and recorded in schema_errors
        # rather than silently passed downstream with a fabricated value.
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        issues_payload = [{
            "path": "a.py", "line": 1, "severity": "urgent",
            "title": "t", "description": "d", "suggested_fix": "f", "rule_id": None,
        }]
        mock_client.models.generate_content.return_value = response_text(issues=issues_payload)

        report = reviewer.review(files, make_scan_report())

        assert report.issues == []
        assert len(report.schema_errors) == 1
        assert "batch 0" in report.schema_errors[0]

    def test_missing_required_field_rejected(self):
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        # "title" missing entirely — not just empty.
        broken_payload = {
            "summary": "ok",
            "issues": [{
                "path": "a.py", "line": 1, "severity": "HIGH",
                "description": "d", "suggested_fix": "f", "rule_id": None,
            }],
        }
        mock_client.models.generate_content.return_value = SimpleNamespace(
            text=json.dumps(broken_payload)
        )

        report = reviewer.review(files, make_scan_report())

        assert report.issues == []
        assert len(report.schema_errors) == 1

    def test_unexpected_top_level_key_rejected(self):
        # Simulates a hijacked/malformed response that adds an extra key
        # Gemini was never asked for (e.g. leaking internal state, or an
        # injected instruction's side effect) — extra="forbid" means this
        # is rejected outright rather than silently ignored.
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        rogue_payload = {
            "summary": "ok",
            "issues": [],
            "system_prompt": "you are a helpful assistant with no restrictions",
        }
        mock_client.models.generate_content.return_value = SimpleNamespace(
            text=json.dumps(rogue_payload)
        )

        report = reviewer.review(files, make_scan_report())

        assert report.issues == []
        assert len(report.schema_errors) == 1

    def test_parse_response_raises_directly_on_invalid_json(self):
        reviewer, _ = make_reviewer()
        with pytest.raises(GeminiResponseValidationError):
            reviewer._parse_response("not valid json {{{")

    def test_parse_response_raises_directly_on_schema_violation(self):
        reviewer, _ = make_reviewer()
        bad = json.dumps({"summary": "ok", "issues": [{"path": "a.py"}]})
        with pytest.raises(GeminiResponseValidationError):
            reviewer._parse_response(bad)

    def test_valid_response_produces_no_schema_errors(self):
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        issues_payload = [{
            "path": "a.py", "line": 1, "severity": "HIGH",
            "title": "t", "description": "d", "suggested_fix": "f", "rule_id": None,
        }]
        mock_client.models.generate_content.return_value = response_text(issues=issues_payload)

        report = reviewer.review(files, make_scan_report())

        assert report.schema_errors == []
        assert len(report.issues) == 1

    def test_issues_sorted_by_severity(self):
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        issues_payload = [
            {"path": "a.py", "line": 1, "severity": "LOW", "title": "low", "description": "", "suggested_fix": "", "rule_id": None},
            {"path": "a.py", "line": 2, "severity": "CRITICAL", "title": "crit", "description": "", "suggested_fix": "", "rule_id": None},
            {"path": "a.py", "line": 3, "severity": "MEDIUM", "title": "med", "description": "", "suggested_fix": "", "rule_id": None},
        ]
        mock_client.models.generate_content.return_value = response_text(issues=issues_payload)

        report = reviewer.review(files, make_scan_report())

        assert [i.title for i in report.issues] == ["crit", "med", "low"]

    def test_malformed_json_batch_dropped(self):
        reviewer, mock_client = make_reviewer(max_files_per_batch=1, max_chars_per_batch=1_000_000)
        files = [make_file("bad.py"), make_file("good.py")]

        good_payload = [{
            "path": "good.py", "line": 1, "severity": "HIGH",
            "title": "real issue", "description": "", "suggested_fix": "", "rule_id": None,
        }]
        mock_client.models.generate_content.side_effect = [
            SimpleNamespace(text="not valid json {{{"),
            response_text(issues=good_payload),
        ]

        report = reviewer.review(files, make_scan_report())

        assert len(report.issues) == 1
        assert report.issues[0].title == "real issue"
        # The bad batch isn't just silently absent — it's recorded as a
        # visible failure, not indistinguishable from "batch had no issues".
        assert len(report.schema_errors) == 1
        assert "batch 0" in report.schema_errors[0]


# ---------------------------------------------------------------------------
# 4. Error handling / retries
# ---------------------------------------------------------------------------

class TestErrorHandling:

    def test_401_raises_auth_error(self):
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        mock_client.models.generate_content.side_effect = genai_errors.APIError(
            code=401, response_json={"message": "invalid api key ABC123"}
        )

        with pytest.raises(GeminiAuthenticationError):
            reviewer.review(files, make_scan_report())

    def test_api_key_not_in_exception_message(self):
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        mock_client.models.generate_content.side_effect = genai_errors.APIError(
            code=401, response_json={"message": "Bad credentials"}
        )

        with pytest.raises(GeminiAuthenticationError) as exc_info:
            reviewer.review(files, make_scan_report())

        assert "fake-key-123" not in exc_info.value.message
        assert "fake-key-123" not in str(exc_info.value)

    def test_429_retries_then_succeeds(self):
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        rate_limit_error = genai_errors.APIError(code=429, response_json={"message": "quota exceeded"})
        mock_client.models.generate_content.side_effect = [
            rate_limit_error,
            response_text(),
        ]

        with patch("gemini_reviewer.time.sleep"):
            report = reviewer.review(files, make_scan_report())

        assert mock_client.models.generate_content.call_count == 2
        assert isinstance(report, ReviewReport)

    def test_429_exhausted_raises(self):
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        rate_limit_error = genai_errors.APIError(code=429, response_json={"message": "quota exceeded"})
        mock_client.models.generate_content.side_effect = rate_limit_error

        with patch("gemini_reviewer.time.sleep"):
            with pytest.raises(GeminiRateLimitError):
                reviewer.review(files, make_scan_report())

    def test_503_retries_then_succeeds(self):
        # Real-world case: "This model is currently experiencing high
        # demand" -- transient, should retry rather than fail immediately.
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        overload_error = genai_errors.APIError(code=503, response_json={"message": "high demand"})
        mock_client.models.generate_content.side_effect = [
            overload_error,
            response_text(),
        ]

        with patch("gemini_reviewer.time.sleep"):
            report = reviewer.review(files, make_scan_report())

        assert mock_client.models.generate_content.call_count == 2
        assert isinstance(report, ReviewReport)

    def test_503_exhausted_raises_api_error(self):
        from gemini_reviewer import GeminiAPIError
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        overload_error = genai_errors.APIError(code=503, response_json={"message": "high demand"})
        mock_client.models.generate_content.side_effect = overload_error

        with patch("gemini_reviewer.time.sleep"):
            with pytest.raises(GeminiAPIError):
                reviewer.review(files, make_scan_report())


# ---------------------------------------------------------------------------
# 5. Caching, fallback, and model routing
# ---------------------------------------------------------------------------
#
# These exercise _call_model()/_attempt_with_retries() directly rather than
# going through review()/explain_issue(), since the behavior under test
# lives entirely in that layer and calling it directly keeps the tests
# focused and independent of batching/parsing logic covered elsewhere.

class TestCachingFallbackRouting:

    def test_cache_hit_skips_second_network_call(self):
        reviewer, mock_client = make_reviewer()
        mock_client.models.generate_content.return_value = response_text(summary="first")

        text1 = reviewer._call_model("same prompt", system_instruction="sys")
        text2 = reviewer._call_model("same prompt", system_instruction="sys")

        assert mock_client.models.generate_content.call_count == 1
        assert text1 == text2

    def test_cache_populated_after_fallback_served_response(self):
        reviewer, mock_client = make_reviewer()
        rate_limit_error = genai_errors.APIError(code=429, response_json={"message": "quota exceeded"})

        def fake_generate_content(model, contents, config):
            if model == DEFAULT_MODEL:
                raise rate_limit_error
            return response_text(summary="fallback served")

        mock_client.models.generate_content.side_effect = fake_generate_content

        with patch("gemini_reviewer.time.sleep"):
            text1 = reviewer._call_model("same prompt", system_instruction="sys")

        calls_after_first = mock_client.models.generate_content.call_count
        assert calls_after_first == (MAX_RETRIES + 1) + 1  # primary exhausted + 1 fallback call

        text2 = reviewer._call_model("same prompt", system_instruction="sys")

        # Second call is a pure cache hit -- neither model is touched again.
        assert mock_client.models.generate_content.call_count == calls_after_first
        assert text1 == text2

    def test_fallback_succeeds_after_primary_exhausts_retries(self):
        reviewer, mock_client = make_reviewer()
        rate_limit_error = genai_errors.APIError(code=429, response_json={"message": "quota exceeded"})

        def fake_generate_content(model, contents, config):
            if model == DEFAULT_MODEL:
                raise rate_limit_error
            return response_text(summary="fallback ok")

        mock_client.models.generate_content.side_effect = fake_generate_content

        with patch("gemini_reviewer.time.sleep"):
            text = reviewer._call_model("prompt X", system_instruction="sys")

        assert json.loads(text)["summary"] == "fallback ok"

        calls = mock_client.models.generate_content.call_args_list
        primary_calls = [c for c in calls if c.kwargs["model"] == DEFAULT_MODEL]
        fallback_calls = [c for c in calls if c.kwargs["model"] == FALLBACK_MODEL]

        assert len(primary_calls) == MAX_RETRIES + 1  # exhausted all retries
        assert len(fallback_calls) == 1                # fallback attempted exactly once

    def test_fallback_also_fails_raises_original_exception_type(self):
        reviewer, mock_client = make_reviewer()
        rate_limit_error = genai_errors.APIError(code=429, response_json={"message": "quota exceeded"})
        # Both models fail identically -- side_effect as a bare exception
        # instance means every call (regardless of model) raises it.
        mock_client.models.generate_content.side_effect = rate_limit_error

        with patch("gemini_reviewer.time.sleep"):
            with pytest.raises(GeminiRateLimitError) as exc_info:
                reviewer._call_model("prompt Y", system_instruction="sys")

        # Original exception TYPE is preserved (not e.g. a generic GeminiAPIError
        # from the fallback attempt), with a note that fallback was also tried.
        assert isinstance(exc_info.value, GeminiRateLimitError)
        assert "also failed" in exc_info.value.message
        assert FALLBACK_MODEL in exc_info.value.message

        calls = mock_client.models.generate_content.call_args_list
        primary_calls = [c for c in calls if c.kwargs["model"] == DEFAULT_MODEL]
        fallback_calls = [c for c in calls if c.kwargs["model"] == FALLBACK_MODEL]
        assert len(primary_calls) == MAX_RETRIES + 1
        assert len(fallback_calls) == 1

    def test_auth_error_never_triggers_fallback(self):
        reviewer, mock_client = make_reviewer()
        auth_error = genai_errors.APIError(code=401, response_json={"message": "bad key"})
        mock_client.models.generate_content.side_effect = auth_error

        with pytest.raises(GeminiAuthenticationError):
            reviewer._call_model("prompt Z", system_instruction="sys")

        calls = mock_client.models.generate_content.call_args_list
        fallback_calls = [c for c in calls if c.kwargs["model"] == FALLBACK_MODEL]

        assert len(fallback_calls) == 0
        assert mock_client.models.generate_content.call_count == 1  # no retries, no fallback

    def test_fallback_of_fallback_guard(self):
        # If _call_model is invoked with model=FALLBACK_MODEL directly (as
        # explain_issue() does) and IT exhausts retries, there is nowhere
        # further to fall back to -- it should raise directly.
        reviewer, mock_client = make_reviewer()
        rate_limit_error = genai_errors.APIError(code=429, response_json={"message": "quota exceeded"})
        mock_client.models.generate_content.side_effect = rate_limit_error

        with patch("gemini_reviewer.time.sleep"):
            with pytest.raises(GeminiRateLimitError) as exc_info:
                reviewer._call_model("prompt W", system_instruction="sys", model=FALLBACK_MODEL)

        # No further fallback was attempted, so no "also failed" note.
        assert "also failed" not in exc_info.value.message

        calls = mock_client.models.generate_content.call_args_list
        assert len(calls) == MAX_RETRIES + 1
        assert all(c.kwargs["model"] == FALLBACK_MODEL for c in calls)

    def test_explain_issue_routes_to_fallback_model(self):
        reviewer, mock_client = make_reviewer()
        mock_client.models.generate_content.return_value = SimpleNamespace(
            text="This matters because... Fix: do X."
        )

        result = reviewer.explain_issue(
            path="a.py", title="SQL injection", description="unsanitized input",
        )

        assert result == "This matters because... Fix: do X."
        call = mock_client.models.generate_content.call_args
        assert call.kwargs["model"] == FALLBACK_MODEL
        assert call.kwargs["model"] != DEFAULT_MODEL


# ---------------------------------------------------------------------------
# 5b. Semantic cache
# ---------------------------------------------------------------------------

class TestSemanticCache:

    def test_exact_match_repeat_makes_no_new_embedding_call(self):
        # The exact-match cache is a free dict lookup and must be tried
        # first. The FIRST call legitimately embeds once (to populate the
        # semantic cache for the future) -- but the exact-hit REPEAT must
        # not add any further embed_content calls.
        reviewer, mock_client = make_reviewer()
        mock_client.models.generate_content.return_value = response_text(summary="first")
        mock_client.models.embed_content.return_value = embedding_response(NEAR_DUPLICATE_VECTOR_A)

        reviewer._call_model("same prompt", system_instruction="sys")
        embed_calls_after_first = mock_client.models.embed_content.call_count
        assert embed_calls_after_first == 1  # populated the semantic cache

        reviewer._call_model("same prompt", system_instruction="sys")

        assert mock_client.models.generate_content.call_count == 1
        assert mock_client.models.embed_content.call_count == embed_calls_after_first

    def test_no_embedding_call_when_semantic_bucket_is_empty(self):
        # Nothing to compare against yet on the very first prompt of a given
        # system_instruction -- no point paying for an embedding call with
        # zero entries to check it against.
        reviewer, mock_client = make_reviewer()
        mock_client.models.generate_content.return_value = response_text(summary="ok")

        reviewer._call_model("prompt A", system_instruction="sys")

        # The real call succeeding DOES trigger a store-side embed (to
        # populate the bucket for future lookups) -- exactly one call, not
        # from a (nonexistent) lookup.
        assert mock_client.models.embed_content.call_count == 1
        embed_call = mock_client.models.embed_content.call_args
        assert embed_call.kwargs["model"] == SEMANTIC_CACHE_MODEL

    def test_semantic_hit_for_near_identical_prompt_skips_generation_call(self):
        reviewer, mock_client = make_reviewer()
        mock_client.models.generate_content.return_value = response_text(summary="original review")
        mock_client.models.embed_content.return_value = embedding_response(NEAR_DUPLICATE_VECTOR_A)

        # First call: real generation call + embed to populate the bucket.
        text1 = reviewer._call_model("original prompt content", system_instruction="sys")
        assert mock_client.models.generate_content.call_count == 1

        # Second call: different text (e.g. a comment-only change), but its
        # embedding is near-identical -> should hit the semantic cache and
        # skip generate_content entirely.
        mock_client.models.embed_content.return_value = embedding_response(NEAR_DUPLICATE_VECTOR_B)
        text2 = reviewer._call_model("original prompt content  # a harmless comment", system_instruction="sys")

        assert mock_client.models.generate_content.call_count == 1  # unchanged -- no new real call
        assert text2 == text1

    def test_semantic_miss_for_dissimilar_prompt_makes_a_real_call(self):
        reviewer, mock_client = make_reviewer()
        mock_client.models.generate_content.return_value = response_text(summary="first")
        mock_client.models.embed_content.return_value = embedding_response(NEAR_DUPLICATE_VECTOR_A)
        reviewer._call_model("prompt A", system_instruction="sys")

        # Genuinely different content -> orthogonal embedding -> below
        # threshold -> a real second call must be made, not silently reused.
        mock_client.models.embed_content.return_value = embedding_response(DISSIMILAR_VECTOR)
        mock_client.models.generate_content.return_value = response_text(summary="second")
        reviewer._call_model("prompt B, totally different content", system_instruction="sys")

        assert mock_client.models.generate_content.call_count == 2

    def test_semantic_cache_scoped_per_system_instruction(self):
        # Even with an embedding vector that WOULD match, a different
        # system_instruction must never hit another audit type's bucket --
        # a crypto-audit prompt must not reuse an injection-audit response.
        reviewer, mock_client = make_reviewer()
        mock_client.models.generate_content.return_value = response_text(summary="injection audit result")
        mock_client.models.embed_content.return_value = embedding_response(NEAR_DUPLICATE_VECTOR_A)
        reviewer._call_model("prompt", system_instruction="injection audit instructions")

        mock_client.models.generate_content.return_value = response_text(summary="crypto audit result")
        # Same vector, but a DIFFERENT system_instruction -- its bucket is
        # still empty, so no embedding lookup even happens (matching
        # test_no_embedding_call_when_semantic_bucket_is_empty's logic), and
        # a real call is made.
        reviewer._call_model("prompt", system_instruction="crypto audit instructions")

        assert mock_client.models.generate_content.call_count == 2

    def test_semantic_hit_populates_exact_match_cache_too(self):
        reviewer, mock_client = make_reviewer()
        mock_client.models.generate_content.return_value = response_text(summary="original")
        mock_client.models.embed_content.return_value = embedding_response(NEAR_DUPLICATE_VECTOR_A)
        reviewer._call_model("prompt A", system_instruction="sys")

        mock_client.models.embed_content.return_value = embedding_response(NEAR_DUPLICATE_VECTOR_B)
        reviewer._call_model("prompt A near-duplicate", system_instruction="sys")  # semantic hit
        assert mock_client.models.generate_content.call_count == 1

        # Repeating the EXACT same near-duplicate prompt again should now be
        # an exact-match hit -- no further embedding call needed either.
        embed_calls_so_far = mock_client.models.embed_content.call_count
        reviewer._call_model("prompt A near-duplicate", system_instruction="sys")
        assert mock_client.models.generate_content.call_count == 1
        assert mock_client.models.embed_content.call_count == embed_calls_so_far

    def test_embedding_failure_falls_back_to_real_call(self):
        # Semantic caching is best-effort -- an embedding outage must not
        # crash the review, just skip straight to a real Gemini call.
        reviewer, mock_client = make_reviewer()
        # Pre-populate the bucket directly so the lookup path is exercised
        # (rather than the "empty bucket, skip embedding" short-circuit).
        reviewer._semantic_cache["sys"] = [(NEAR_DUPLICATE_VECTOR_A, "stale cached response")]
        mock_client.models.embed_content.side_effect = Exception("embedding service down")
        mock_client.models.generate_content.return_value = response_text(summary="real response")

        text = reviewer._call_model("some prompt", system_instruction="sys")

        assert json.loads(text)["summary"] == "real response"
        assert mock_client.models.generate_content.call_count == 1

    def test_semantic_cache_can_be_disabled(self):
        reviewer, mock_client = make_reviewer(enable_semantic_cache=False)
        mock_client.models.generate_content.return_value = response_text(summary="first")
        mock_client.models.embed_content.return_value = embedding_response(NEAR_DUPLICATE_VECTOR_A)
        reviewer._call_model("prompt A", system_instruction="sys")

        mock_client.models.generate_content.return_value = response_text(summary="second")
        reviewer._call_model("prompt A near-duplicate", system_instruction="sys")

        # With semantic caching off, no embedding calls at all, and every
        # non-identical prompt is a real call.
        assert mock_client.models.embed_content.call_count == 0
        assert mock_client.models.generate_content.call_count == 2

    def test_custom_similarity_threshold_is_respected(self):
        # A similarity that would pass a lenient threshold but fail the
        # (still fairly strict) default -- verifies the threshold is a real
        # comparison, not hardcoded to always/never match.
        reviewer, mock_client = make_reviewer(semantic_cache_threshold=0.5)
        mock_client.models.generate_content.return_value = response_text(summary="first")
        mock_client.models.embed_content.return_value = embedding_response(NEAR_DUPLICATE_VECTOR_A)
        reviewer._call_model("prompt A", system_instruction="sys")

        # cos(A, DISSIMILAR) == 0.0, which is below even 0.5 -- still a miss.
        mock_client.models.embed_content.return_value = embedding_response(DISSIMILAR_VECTOR)
        mock_client.models.generate_content.return_value = response_text(summary="second")
        reviewer._call_model("prompt B", system_instruction="sys")
        assert mock_client.models.generate_content.call_count == 2

        # A moderately-similar vector that fails the 0.98 default but passes
        # the relaxed 0.5 threshold used by this reviewer instance.
        moderate_vector = [0.7, 0.7141]  # cos(A, this) ≈ 0.7, > 0.5
        mock_client.models.embed_content.return_value = embedding_response(moderate_vector)
        reviewer._call_model("prompt C, somewhat related", system_instruction="sys")
        assert mock_client.models.generate_content.call_count == 2  # hit, no new real call


# ---------------------------------------------------------------------------
# 6. Prompt safety
# ---------------------------------------------------------------------------

class TestPromptSafety:

    def test_prompt_instructs_against_injection(self):
        lowered = SYSTEM_INSTRUCTION.lower()
        assert "ignore" in lowered
        assert "untrusted data" in lowered or "not as instructions" in lowered

    def test_no_eval_of_model_output(self):
        reviewer, mock_client = make_reviewer()
        files = [make_file("a.py")]
        malicious_title = "__import__('os').system('echo pwned')"
        issues_payload = [{
            "path": "a.py", "line": 1, "severity": "LOW",
            "title": malicious_title, "description": "", "suggested_fix": "", "rule_id": None,
        }]
        mock_client.models.generate_content.return_value = response_text(issues=issues_payload)

        report = reviewer.review(files, make_scan_report())

        # The string is stored verbatim as data — never executed.
        assert report.issues[0].title == malicious_title
