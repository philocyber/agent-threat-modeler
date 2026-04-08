from __future__ import annotations

import logging
from pathlib import Path

from agentictm.agents.architecture_reviewer import (
    run_architecture_reviewer,
    _detect_mandatory_patterns,
)
from agentictm.agents.synthesis.deduplication import (
    _deduplicate_threats,
    _SAME_STRIDE_INTRA_THRESHOLD,
    _tokenize,
    _weighted_jaccard,
)
from agentictm.agents.synthesis.quality_gates import (
    _recover_unmatched_baseline,
    _apply_quality_gates,
)
from agentictm.agents.synthesis.orchestrator import _audit_mandatory_coverage
from agentictm.agents.synthesis.classification import (
    _asymmetric_dread,
    _infer_stride_category,
)
from agentictm.config import PipelineConfig
from agentictm.graph import builder
from agentictm.logging import (
    get_agent_name,
    get_correlation_id,
    set_agent_name,
    set_correlation_id,
    set_logging_context,
    with_logging_context,
)
from run import _StatusPollAccessFilter


NON_AI_STATE = {
    "system_name": "Document Portal",
    "raw_input": (
        "A multi-tenant document portal with a React frontend, REST API, PostgreSQL, "
        "and S3-style object storage. There is no AI, LLM, ML, or agentic component "
        "in this system. Users upload files, share links, and download documents after "
        "authorization checks."
    ),
    "system_description": (
        "React frontend -> REST API -> PostgreSQL and object storage. "
        "No AI or LLM features are present."
    ),
    "components": [
        {"name": "React Frontend", "type": "web", "description": "Browser UI"},
        {"name": "REST API", "type": "process", "description": "Handles auth and document actions"},
        {"name": "PostgreSQL", "type": "data_store", "description": "Stores metadata and tenant mappings"},
    ],
    "data_flows": [
        {"source": "React Frontend", "destination": "REST API", "protocol": "HTTPS", "data_type": "JSON"},
        {"source": "REST API", "destination": "PostgreSQL", "protocol": "TLS", "data_type": "SQL"},
    ],
    "trust_boundaries": [{"name": "Internet", "components_inside": ["REST API"], "components_outside": ["React Frontend"]}],
    "external_entities": [],
    "data_stores": [{"name": "Object Storage", "type": "data_store", "description": "Stores uploaded files"}],
    "scope_notes": "Explicitly non-AI system. Multi-tenant access with share links and tenant-scoped doc_id values.",
}

MINIMAL_STATE = {
    "system_name": "Minimal",
    "raw_input": "A simple web app.",
    "system_description": "A simple web app.",
    "components": [{"name": "Web App", "type": "process"}],
    "data_flows": [],
    "trust_boundaries": [],
    "external_entities": [],
    "data_stores": [],
    "scope_notes": "",
}


def test_reviewer_avoids_fake_ai_scope_for_explicit_non_ai_systems():
    result = run_architecture_reviewer(NON_AI_STATE, llm=None)
    review = result["architecture_review"]

    assert review["complexity"]["has_ai_components"] is False
    assert review["threat_surfaces"]["agentic"] == []
    assert all(comp.get("type") != "ai_infrastructure" for comp in review["inferred_components"])
    assert review["complexity"]["ai_evidence"]["negations"]


def test_reviewer_requests_clarification_after_review_for_thin_architecture():
    result = run_architecture_reviewer(MINIMAL_STATE, llm=None)

    assert result["clarification_needed"] is True
    assert result["quality_score"] == result["architecture_review"]["quality_score"]
    assert result["architecture_review"]["clarification_focus"]


def test_builder_routes_review_before_clarification():
    source = Path(builder.__file__).read_text(encoding="utf-8")

    assert 'graph.add_edge("architecture_parser", "architecture_reviewer")' in source
    assert 'graph.add_conditional_edges(' in source
    assert '"architecture_reviewer"' in source
    assert '"analysts": "stride_analyst"' in source


def test_default_pipeline_mode_is_cascade():
    assert PipelineConfig().analyst_execution_mode == "cascade"


def test_status_poll_access_filter_drops_status_noise_only():
    filt = _StatusPollAccessFilter()
    noisy = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg='127.0.0.1:1 - "GET /api/analysis/abc123/status HTTP/1.1" 200 OK',
        args=(),
        exc_info=None,
    )
    useful = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg='127.0.0.1:1 - "GET /api/health HTTP/1.1" 200 OK',
        args=(),
        exc_info=None,
    )

    assert filt.filter(noisy) is False
    assert filt.filter(useful) is True


def test_with_logging_context_restores_parent_context():
    set_correlation_id("cid-parent")
    set_agent_name("reviewer")
    wrapped = with_logging_context(lambda: (get_correlation_id(), get_agent_name()))

    set_logging_context({})
    assert wrapped() == ("cid-parent", "reviewer")
    assert get_correlation_id() == ""
    assert get_agent_name() == ""


# ---------------------------------------------------------------------------
# Coverage Reconciliation
# ---------------------------------------------------------------------------

def test_recover_unmatched_baseline_recovers_unique_threats():
    baseline = [
        {"description": "SQL injection in the login form via unsanitized user input parameters"},
        {"description": "Weak MFA enforcement allows credential stuffing attacks on Cognito"},
        {"description": "SQS message replay attack without message signing or integrity"},
    ]
    llm = [
        {"description": "SQL injection vulnerability in user login input parameters"},
    ]
    recovered = _recover_unmatched_baseline(baseline, llm)
    descs = [r["description"] for r in recovered]
    assert len(recovered) >= 2
    assert any("MFA" in d for d in descs)
    assert any("SQS" in d for d in descs)
    assert all("[Baseline-Recovered]" in (r.get("observations") or "") for r in recovered)


def test_recover_unmatched_baseline_does_not_recover_duplicates():
    baseline = [
        {"description": "SQL injection vulnerability in the login form via unsanitized input"},
    ]
    llm = [
        {"description": "SQL injection in the login endpoint through unsanitized user input parameters"},
    ]
    recovered = _recover_unmatched_baseline(baseline, llm)
    assert len(recovered) == 0


# ---------------------------------------------------------------------------
# Mandatory Threat Patterns
# ---------------------------------------------------------------------------

DOCUSHARE_STATE = {
    "system_name": "DocuShare",
    "raw_input": (
        "DocuShare is a multi-tenant document management system built on AWS. "
        "Users upload documents to S3 via presigned URLs. ClamAV scans uploaded files "
        "asynchronously. Clean files are served through CloudFront. "
        "Authentication via Cognito. DynamoDB stores metadata keyed by tenant_id and doc_id. "
        "SQS triggers Lambda for async scan. npm/pip packages used in Lambda."
    ),
    "system_description": (
        "React SPA -> API Gateway -> Lambda -> DynamoDB / S3 / SQS. "
        "ClamAV quarantine pipeline. CloudFront CDN. Cognito auth."
    ),
    "components": [
        {"name": "API Gateway", "type": "process", "description": "REST API"},
        {"name": "Lambda", "type": "process", "description": "Serverless compute"},
        {"name": "DynamoDB", "type": "data_store", "description": "Document metadata"},
        {"name": "S3", "type": "data_store", "description": "File storage"},
        {"name": "SQS", "type": "queue", "description": "Async scan trigger"},
        {"name": "ClamAV", "type": "process", "description": "Antivirus scanner"},
    ],
    "data_flows": [
        {"source": "API Gateway", "destination": "Lambda", "protocol": "HTTPS", "data_type": "JSON"},
        {"source": "Lambda", "destination": "DynamoDB", "protocol": "TLS", "data_type": "metadata"},
        {"source": "Lambda", "destination": "S3", "protocol": "HTTPS", "data_type": "files"},
        {"source": "SQS", "destination": "Lambda", "protocol": "internal", "data_type": "event"},
    ],
    "trust_boundaries": [],
    "external_entities": [],
    "data_stores": [
        {"name": "DynamoDB", "type": "data_store"},
        {"name": "S3", "type": "data_store"},
    ],
    "scope_notes": (
        "Multi-tenant with tenant_id and doc_id. Async upload-scan-download workflow. "
        "No AI/LLM/agentic components."
    ),
}


def test_detect_mandatory_patterns_for_docushare():
    patterns = _detect_mandatory_patterns(
        DOCUSHARE_STATE,
        gaps=[],
        surfaces={},
    )
    ids = {p["pattern_id"] for p in patterns}
    assert "IDOR_BOLA" in ids, f"Expected IDOR_BOLA, got {ids}"
    assert "TOCTOU_SCAN_RACE" in ids, f"Expected TOCTOU_SCAN_RACE, got {ids}"
    assert "MFA_ENFORCEMENT" in ids, f"Expected MFA_ENFORCEMENT, got {ids}"
    assert "QUEUE_REPLAY" in ids, f"Expected QUEUE_REPLAY, got {ids}"
    assert "SUPPLY_CHAIN" in ids, f"Expected SUPPLY_CHAIN, got {ids}"


def test_mandatory_patterns_in_reviewer_output():
    result = run_architecture_reviewer(DOCUSHARE_STATE, llm=None)
    patterns = result.get("mandatory_threat_patterns", [])
    assert len(patterns) >= 3
    briefing = result.get("threat_surface_summary", "")
    assert "Mandatory Coverage Requirements" in briefing


def test_audit_mandatory_coverage_generates_stubs():
    patterns = [
        {
            "pattern_id": "TEST_GAP",
            "name": "Test Gap",
            "description": "A test gap that must be covered in the output.",
            "keywords": ["zzz_unique_keyword_not_in_any_threat", "yyy_another_unique"],
            "stride_category": "I",
        }
    ]
    threats = [
        {"description": "SQL injection in login form", "component": "API"},
    ]
    stubs = _audit_mandatory_coverage(threats, patterns)
    assert len(stubs) == 1
    assert "TEST_GAP" in stubs[0]["observations"]
    assert stubs[0]["confidence_score"] == 0.6


def test_audit_mandatory_coverage_no_stub_when_covered():
    patterns = [
        {
            "pattern_id": "IDOR_BOLA",
            "name": "IDOR / BOLA",
            "description": "Direct object reference bypass",
            "keywords": ["idor", "bola", "tenant", "authorization"],
            "stride_category": "E",
        }
    ]
    threats = [
        {"description": "IDOR on tenant_id allows cross-tenant access with broken authorization", "component": "DynamoDB"},
    ]
    stubs = _audit_mandatory_coverage(threats, patterns)
    assert len(stubs) == 0


# ---------------------------------------------------------------------------
# STRIDE Validation
# ---------------------------------------------------------------------------

def test_stride_validation_overrides_misclassified_repudiation():
    threats = [
        {
            "description": (
                "The public S3 bucket exposes API keys and application secrets. "
                "An attacker can exfiltrate sensitive data and configuration by "
                "directly accessing the bucket. This is information disclosure "
                "via a misconfigured storage endpoint exposing confidential data."
            ),
            "stride_category": "R",
            "attack_path": "Access public S3 bucket to read exposed API keys",
            "component": "S3 Bucket",
            "damage": 7, "reproducibility": 8, "exploitability": 9,
            "affected_users": 6, "discoverability": 8,
            "mitigation": "", "control_reference": "",
        }
    ]
    result = _apply_quality_gates(threats, max_threats=50)
    assert len(result) == 1
    assert result[0]["stride_category"] == "I"


# ---------------------------------------------------------------------------
# Uniform DREAD Correction
# ---------------------------------------------------------------------------

def test_asymmetric_dread_produces_varied_scores():
    scores = _asymmetric_dread(5, "T", "SQL injection in login form")
    values = list(scores.values())
    assert len(set(values)) > 1, f"Expected varied scores, got {values}"


def test_infer_stride_prefers_info_disclosure_for_exposure():
    threat = {
        "description": "S3 bucket public exposure leaks sensitive data and API keys",
        "attack_path": "Access public bucket directly",
        "component": "S3",
        "methodology": "STRIDE",
    }
    cat = _infer_stride_category(threat)
    assert cat == "I", f"Expected I, got {cat}"


# ---------------------------------------------------------------------------
# Dedup Threshold Tuning
# ---------------------------------------------------------------------------

def test_dedup_same_stride_threshold_is_0_22():
    assert _SAME_STRIDE_INTRA_THRESHOLD == 0.22


def test_dedup_preserves_distinct_same_component_threats():
    threats = [
        {
            "description": "JWT token aud claim bypass allows cross-tenant access through audience validation weakness",
            "component": "API Gateway",
            "stride_category": "S",
        },
        {
            "description": "CloudFront origin bypass enables direct access to S3 bucket skipping WAF rules",
            "component": "API Gateway",
            "stride_category": "I",
        },
    ]
    result = _deduplicate_threats(threats)
    assert len(result) == 2, f"Expected 2 distinct threats, got {len(result)}"
