"""Tests for the Input Triage (Interactive Pre-Analysis) module."""

import pytest

from agentictm.agents.input_triage import (
    triage_input,
    enrich_with_answers,
    TriageResult,
    _score_dimensions,
    _generate_fallback_questions,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MINIMAL_INPUT = "A simple web app"

_GOOD_INPUT = """
Our system is an e-commerce platform built with React frontend and Node.js backend.
The backend uses PostgreSQL for persistent storage and Redis for session caching.
Authentication is handled via JWT tokens with OAuth2 for social logins.
The API Gateway (Nginx) handles TLS termination and rate limiting.
Data flows: Client -> API Gateway -> Backend Services -> PostgreSQL.
User PII (email, address, payment info) is stored encrypted at rest.
Deployment: Kubernetes cluster on AWS EKS with separate VPCs for production and staging.
Trust boundaries: Internet <-> DMZ (API Gateway) <-> Internal (services) <-> Data tier.
"""

_MODERATE_INPUT = """
We have a web application with a React frontend, a Python FastAPI backend,
and a PostgreSQL database. Users can log in with username and password.
The app is deployed on AWS.
"""


class TestScoreDimensions:
    """Tests for the deterministic quality scoring."""

    def test_minimal_input_scores_low(self):
        score, dims = _score_dimensions(_MINIMAL_INPUT)
        assert score < 30
        assert len(dims) > 0

    def test_good_input_scores_high(self):
        score, dims = _score_dimensions(_GOOD_INPUT)
        assert score >= 55
        # Should find most dimensions
        found_count = sum(1 for d in dims if d.get("found", False))
        assert found_count >= 6

    def test_moderate_input_scores_middle(self):
        score, dims = _score_dimensions(_MODERATE_INPUT)
        assert 20 < score < 80

    def test_empty_input_scores_zero(self):
        score, dims = _score_dimensions("")
        assert score <= 10

    def test_dimensions_have_required_fields(self):
        _, dims = _score_dimensions(_GOOD_INPUT)
        for d in dims:
            assert "name" in d
            assert "label" in d
            assert "score" in d
            assert "found" in d


class TestTriageInput:
    """Tests for the triage_input function (no LLM)."""

    def test_good_input_returns_ready(self):
        result = triage_input(_GOOD_INPUT)
        assert result.verdict == "ready"
        assert result.quality_score >= 55
        assert len(result.questions) == 0  # No questions needed

    def test_minimal_input_returns_needs_info(self):
        result = triage_input(_MINIMAL_INPUT)
        assert result.verdict == "needs_info"
        assert result.quality_score < 55
        assert len(result.questions) > 0  # Fallback questions generated

    def test_session_id_generated(self):
        result = triage_input(_MINIMAL_INPUT)
        assert result.session_id
        assert len(result.session_id) == 12

    def test_original_input_stored(self):
        result = triage_input(_MINIMAL_INPUT)
        assert result.original_input == _MINIMAL_INPUT

    def test_custom_threshold(self):
        result = triage_input(_MODERATE_INPUT, threshold=90)
        assert result.verdict == "needs_info"

        result2 = triage_input(_MODERATE_INPUT, threshold=10)
        assert result2.verdict == "ready"

    def test_result_is_dataclass(self):
        result = triage_input(_MINIMAL_INPUT)
        assert isinstance(result, TriageResult)


class TestFallbackQuestions:
    """Tests for rule-based fallback question generation."""

    def test_minimal_input_generates_questions(self):
        _, dims = _score_dimensions(_MINIMAL_INPUT)
        questions = _generate_fallback_questions(dims)
        assert len(questions) > 0
        assert len(questions) <= 5

    def test_good_input_generates_fewer_questions(self):
        _, dims_minimal = _score_dimensions(_MINIMAL_INPUT)
        _, dims_good = _score_dimensions(_GOOD_INPUT)

        q_minimal = _generate_fallback_questions(dims_minimal)
        q_good = _generate_fallback_questions(dims_good)

        assert len(q_minimal) >= len(q_good)

    def test_questions_are_strings(self):
        _, dims = _score_dimensions(_MINIMAL_INPUT)
        questions = _generate_fallback_questions(dims)
        for q in questions:
            assert isinstance(q, str)
            assert len(q) > 10


class TestEnrichWithAnswers:
    """Tests for the input enrichment function."""

    def test_enriches_with_answers(self):
        original = "A web app"
        questions = ["What database?", "What framework?"]
        answers = ["PostgreSQL", "React + FastAPI"]

        enriched = enrich_with_answers(original, questions, answers)
        assert "A web app" in enriched
        assert "PostgreSQL" in enriched
        assert "React + FastAPI" in enriched
        assert "Additional Details" in enriched

    def test_skips_empty_answers(self):
        original = "A web app"
        questions = ["Q1?", "Q2?"]
        answers = ["Answer1", ""]

        enriched = enrich_with_answers(original, questions, answers)
        assert "Answer1" in enriched
        assert "Q2" not in enriched  # Skipped because empty

    def test_no_answers_returns_original(self):
        original = "A web app"
        enriched = enrich_with_answers(original, ["Q?"], [])
        assert enriched == original

    def test_enriched_input_scores_higher(self):
        """The whole point — enriched input should score better than original."""
        result1 = triage_input(_MINIMAL_INPUT)

        enriched = enrich_with_answers(
            _MINIMAL_INPUT,
            result1.questions[:3],
            [
                "React frontend, Node.js backend, PostgreSQL database",
                "REST API with JWT authentication",
                "Deployed on AWS EKS with Docker containers",
            ],
        )
        result2 = triage_input(enriched)
        assert result2.quality_score > result1.quality_score
