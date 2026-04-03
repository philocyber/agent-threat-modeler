"""Tests for Quality Judge and Compliance Mapper agents."""

import pytest

from agentictm.agents.quality_judge import evaluate_threat_model, QualityReport
from agentictm.agents.compliance_mapper import map_threats_to_controls, generate_compliance_summary


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

def _make_threat(
    *,
    threat_id: str = "TM-001",
    description: str = "SQL Injection via unsanitized user input in the login form allows data exfiltration",
    stride: str = "T",
    damage: int = 8,
    reproducibility: int = 7,
    exploitability: int = 6,
    affected_users: int = 9,
    discoverability: int = 5,
    mitigation: str = "Use parameterized queries and input validation for all database operations",
    evidence: list | None = None,
) -> dict:
    return {
        "id": threat_id,
        "component": "API Gateway",
        "description": description,
        "methodology": "STRIDE",
        "stride_category": stride,
        "damage": damage,
        "reproducibility": reproducibility,
        "exploitability": exploitability,
        "affected_users": affected_users,
        "discoverability": discoverability,
        "dread_total": damage + reproducibility + exploitability + affected_users + discoverability,
        "priority": "High",
        "mitigation": mitigation,
        "status": "Open",
        "evidence_sources": evidence or [],
    }


def _make_full_stride_threats() -> list[dict]:
    """Create threats covering all 6 STRIDE categories."""
    return [
        _make_threat(threat_id="TM-001", stride="S", description="Spoofing attack on authentication mechanism via stolen JWT tokens"),
        _make_threat(threat_id="TM-002", stride="T", description="SQL injection tampering with database records through unvalidated input"),
        _make_threat(threat_id="TM-003", stride="R", description="Repudiation risk due to insufficient audit logging and monitoring"),
        _make_threat(threat_id="TM-004", stride="I", description="Information disclosure through verbose API error messages and stack traces"),
        _make_threat(threat_id="TM-005", stride="D", description="Denial of service attack on API rate limiting bypass through resource exhaustion"),
        _make_threat(threat_id="TM-006", stride="E", description="Elevation of privilege through IDOR vulnerability in access control mechanism"),
        _make_threat(threat_id="TM-007", stride="S", description="Credential stuffing attack on authentication endpoint exploiting weak password policy"),
    ]


# ---------------------------------------------------------------------------
# Quality Judge Tests
# ---------------------------------------------------------------------------

class TestQualityJudge:
    """Tests for the quality evaluation module."""

    def test_empty_threats_returns_fail(self):
        report = evaluate_threat_model([])
        assert report.verdict == "FAIL"
        assert report.overall_score == 0
        assert report.threats_evaluated == 0

    def test_good_threats_return_pass(self):
        threats = _make_full_stride_threats()
        report = evaluate_threat_model(threats, min_threats=5)
        assert report.verdict == "PASS"
        assert report.overall_score >= 70
        assert report.threats_evaluated == 7

    def test_stride_coverage_all_covered(self):
        threats = _make_full_stride_threats()
        report = evaluate_threat_model(threats)
        stride_criterion = next(c for c in report.criteria if c.name == "stride_coverage")
        assert stride_criterion.score == 1.0
        assert stride_criterion.passed

    def test_stride_coverage_partial(self):
        threats = [_make_threat(stride="S"), _make_threat(stride="T", threat_id="TM-002")]
        report = evaluate_threat_model(threats, min_threats=1)
        stride_criterion = next(c for c in report.criteria if c.name == "stride_coverage")
        assert stride_criterion.score < 1.0

    def test_dread_completeness(self):
        threats = _make_full_stride_threats()
        report = evaluate_threat_model(threats)
        dread_criterion = next(c for c in report.criteria if c.name == "dread_completeness")
        assert dread_criterion.score == 1.0

    def test_dread_incomplete_scores(self):
        threats = [_make_threat(damage=0, reproducibility=0)]
        report = evaluate_threat_model(threats, min_threats=1)
        dread_criterion = next(c for c in report.criteria if c.name == "dread_completeness")
        assert dread_criterion.score == 0.0

    def test_mitigation_quality(self):
        threats = _make_full_stride_threats()
        report = evaluate_threat_model(threats)
        mit_criterion = next(c for c in report.criteria if c.name == "mitigation_quality")
        assert mit_criterion.score > 0.5
        assert mit_criterion.passed

    def test_poor_mitigations(self):
        threats = [_make_threat(mitigation="Fix it")]
        report = evaluate_threat_model(threats, min_threats=1)
        mit_criterion = next(c for c in report.criteria if c.name == "mitigation_quality")
        assert mit_criterion.score < 1.0

    def test_too_few_threats_penalized(self):
        threats = [_make_threat()]
        report = evaluate_threat_model(threats, min_threats=10)
        count_criterion = next(c for c in report.criteria if c.name == "threat_count")
        assert count_criterion.score < 1.0

    def test_recommendations_generated_for_failures(self):
        threats = [_make_threat(stride="S", mitigation="Fix")]
        report = evaluate_threat_model(threats, min_threats=10)
        assert len(report.recommendations) > 0

    def test_report_is_dataclass(self):
        report = evaluate_threat_model([_make_threat()])
        assert isinstance(report, QualityReport)


# ---------------------------------------------------------------------------
# Compliance Mapper Tests
# ---------------------------------------------------------------------------

class TestComplianceMapper:
    """Tests for the compliance mapping module."""

    def test_sql_injection_maps_to_validation_controls(self):
        threats = [_make_threat(description="SQL injection attack through unvalidated input")]
        mappings = map_threats_to_controls(threats)
        assert len(mappings) == 1
        controls = mappings[0]["controls"]
        assert len(controls) > 0
        frameworks = {c["framework"] for c in controls}
        assert "NIST 800-53" in frameworks

    def test_authentication_threat_maps_correctly(self):
        threats = [_make_threat(description="Brute force attack on login endpoint to guess passwords")]
        mappings = map_threats_to_controls(threats)
        controls = mappings[0]["controls"]
        nist_ids = [c["control_id"] for c in controls if c["framework"] == "NIST 800-53"]
        assert "IA-2" in nist_ids  # Identification and Authentication

    def test_encryption_threat(self):
        threats = [_make_threat(description="Data transmitted over plaintext HTTP without TLS encryption")]
        mappings = map_threats_to_controls(threats)
        controls = mappings[0]["controls"]
        nist_ids = [c["control_id"] for c in controls if c["framework"] == "NIST 800-53"]
        assert "SC-8" in nist_ids  # Transmission Confidentiality

    def test_multiple_threats_mapped(self):
        threats = _make_full_stride_threats()
        mappings = map_threats_to_controls(threats)
        assert len(mappings) == 7
        mapped = sum(1 for m in mappings if m["controls_count"] > 0)
        assert mapped >= 5  # Most should map to something

    def test_no_duplicate_controls_per_threat(self):
        threats = [_make_threat(
            description="SQL injection and command injection in the API authentication endpoint with no input validation"
        )]
        mappings = map_threats_to_controls(threats)
        controls = mappings[0]["controls"]
        control_keys = [f"{c['framework']}:{c['control_id']}" for c in controls]
        assert len(control_keys) == len(set(control_keys))

    def test_summary_generation(self):
        threats = _make_full_stride_threats()
        mappings = map_threats_to_controls(threats)
        summary = generate_compliance_summary(mappings)
        assert "frameworks" in summary
        assert summary["total_unique_controls"] > 0
        assert "NIST 800-53" in summary["frameworks"]

    def test_unknown_threat_returns_empty_controls(self):
        threats = [_make_threat(
            description="Generic unclassifiable risk",
            mitigation="Apply general security practices"
        )]
        mappings = map_threats_to_controls(threats)
        # May or may not map — but shouldn't crash
        assert len(mappings) == 1
