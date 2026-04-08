"""Unified Pydantic schemas for AgenticTM.

Canonical data models used for validation, serialization, and
contract enforcement across all agents and API endpoints.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class StrideCategory(str, Enum):
    SPOOFING = "S"
    TAMPERING = "T"
    REPUDIATION = "R"
    INFORMATION_DISCLOSURE = "I"
    DENIAL_OF_SERVICE = "D"
    ELEVATION_OF_PRIVILEGE = "E"
    AGENT_THREAT = "A"  # ASTRIDE extension (arXiv:2512.04785) for agentic AI attacks


class Priority(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Effort(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class ThreatStatus(str, Enum):
    OPEN = "Open"
    MITIGATED = "Mitigated"
    ACCEPTED = "Accepted"


class JustificationDecision(str, Enum):
    """User-provided disposition for a threat after review."""
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MITIGATED_BY_INFRA = "MITIGATED_BY_INFRA"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EvidenceType(str, Enum):
    RAG = "rag"
    LLM_KNOWLEDGE = "llm_knowledge"
    CONTEXTUAL = "contextual"
    ARCHITECTURE = "architecture"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class EvidenceSource(BaseModel):
    """A single piece of evidence backing a threat finding."""
    source_type: EvidenceType = Field(
        description="Origin of the evidence: rag, llm_knowledge, contextual, or architecture"
    )
    source_name: str = Field(
        description="Name/identifier of the source (e.g., 'OWASP Top 10', 'NIST SP 800-53', 'system architecture')"
    )
    excerpt: str = Field(
        default="",
        description="Relevant excerpt or quote from the source"
    )


class ThreatJustification(BaseModel):
    """User-provided justification/disposition for a threat."""
    decision: JustificationDecision = Field(
        description="Disposition decision for this threat"
    )
    reason_text: str = Field(
        min_length=50,
        description="Explanation for the justification decision (minimum 50 characters)"
    )
    justified_by: str = Field(
        default="",
        description="Name or identifier of the person who made the decision"
    )
    justified_at: datetime = Field(
        default_factory=datetime.now,
        description="Timestamp of when the justification was made"
    )
    context_snapshot: dict = Field(
        default_factory=dict,
        description="Snapshot of relevant context at justification time (e.g., infrastructure state)"
    )


class ComponentModel(BaseModel):
    """A system component identified during architecture parsing."""
    name: str
    type: str = Field(default="process", description="process | data_store | external_entity")
    description: str = ""
    scope: str = Field(default="internal", description="internal | dmz | public | cloud")


class DataFlowModel(BaseModel):
    """A data flow between components."""
    source: str
    destination: str
    protocol: str = ""
    data_type: str = ""
    bidirectional: bool = False


class TrustBoundaryModel(BaseModel):
    """A trust boundary in the architecture."""
    name: str
    components_inside: list[str] = Field(default_factory=list)
    components_outside: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Unified Threat Model
# ---------------------------------------------------------------------------

class UnifiedThreat(BaseModel):
    """Canonical threat representation used across all pipeline stages.

    Every agent output is normalized to this schema before synthesis.
    """

    # ── Identity ──
    id: str = Field(description="Unique threat identifier (e.g., INF-01, WEB-03)")
    component: str = Field(default="", description="Affected system component")
    description: str = Field(description="Detailed threat scenario description")

    # ── Classification ──
    methodology: str = Field(
        default="",
        description="Source methodology or methodologies (e.g., 'STRIDE', 'STRIDE, PASTA')"
    )
    stride_category: str = Field(
        default="",
        description="STRIDE category: S, T, R, I, D, or E"
    )
    attack_path: str = Field(
        default="",
        description="Step-by-step attack path description"
    )

    # ── DREAD Scoring ──
    damage: int = Field(default=0, ge=0, le=10, description="DREAD: Damage potential (0-10)")
    reproducibility: int = Field(default=0, ge=0, le=10, description="DREAD: Reproducibility (0-10)")
    exploitability: int = Field(default=0, ge=0, le=10, description="DREAD: Exploitability (0-10)")
    affected_users: int = Field(default=0, ge=0, le=10, description="DREAD: Affected users (0-10)")
    discoverability: int = Field(default=0, ge=0, le=10, description="DREAD: Discoverability (0-10)")
    dread_total: int = Field(default=0, ge=0, le=50, description="DREAD total score (0-50)")

    # ── Risk ──
    priority: str = Field(default="Medium", description="Critical | High | Medium | Low")
    mitigation: str = Field(default="", description="Recommended mitigation strategy")
    control_reference: str = Field(default="", description="Reference to a security control framework")
    effort: str = Field(default="Medium", description="Mitigation effort: Low | Medium | High")
    observations: str = Field(default="", description="Additional notes and observations")
    status: str = Field(default="Open", description="Open | Mitigated | Accepted")

    # ── Evidence & Confidence (new) ──
    evidence_sources: list[EvidenceSource] = Field(
        default_factory=list,
        description="Evidence backing this threat finding"
    )
    confidence_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Agent confidence in this threat (0.0 = low, 1.0 = high)"
    )

    # ── Justification (populated post-analysis by user) ──
    justification: Optional[ThreatJustification] = Field(
        default=None,
        description="User-provided justification/disposition (applied after analysis)"
    )

    @field_validator("priority")
    @classmethod
    def normalize_priority(cls, v: str) -> str:
        mapping = {
            "critical": "Critical", "high": "High",
            "medium": "Medium", "low": "Low",
            "crítico": "Critical", "alto": "High",
            "medio": "Medium", "bajo": "Low",
        }
        return mapping.get(v.lower(), v)

    @field_validator("stride_category")
    @classmethod
    def normalize_stride(cls, v: str) -> str:
        if v and len(v) == 1 and v.upper() in "STRIDEA":
            return v.upper()
        full_map = {
            "spoofing": "S", "tampering": "T", "repudiation": "R",
            "information disclosure": "I", "denial of service": "D",
            "elevation of privilege": "E", "agent threat": "A",
            "agent": "A", "agentic": "A",
        }
        return full_map.get(v.lower(), v)

    def to_state_dict(self) -> dict:
        """Convert to plain dict compatible with ThreatModelState TypedDict."""
        d = self.model_dump()
        # Serialize evidence_sources as list of dicts
        d["evidence_sources"] = [e.model_dump() for e in self.evidence_sources]
        # Serialize justification
        if self.justification:
            j = self.justification.model_dump()
            j["justified_at"] = j["justified_at"].isoformat()
            d["justification"] = j
        else:
            d["justification"] = None
        return d

    @classmethod
    def from_state_dict(cls, data: dict) -> "UnifiedThreat":
        """Create from a plain dict (e.g., from ThreatModelState)."""
        return cls.model_validate(data)


# ---------------------------------------------------------------------------
# Schema Boundary Layer — Pydantic ↔ TypedDict conversion utilities
# ---------------------------------------------------------------------------

def threat_to_dict(threat: UnifiedThreat) -> dict:
    """Convert a Pydantic UnifiedThreat → plain dict for LangGraph state.

    This is the canonical way to go from the validated Pydantic world into
    the TypedDict-based ``ThreatModelState.threats_final`` list.  Ensures
    all nested models (EvidenceSource, ThreatJustification) are serialized
    to JSON-safe primitives (no datetime objects, no Pydantic models).
    """
    return threat.to_state_dict()


def dict_to_threat(d: dict) -> UnifiedThreat:
    """Convert a plain dict → validated Pydantic UnifiedThreat.

    Use this when you need to apply Pydantic validation/normalization to
    a threat dict coming from the LangGraph state or from raw LLM output.
    Raises ``pydantic.ValidationError`` if the dict is invalid.
    """
    return UnifiedThreat.from_state_dict(d)


def validate_state_threats(threats: list[dict]) -> list[dict]:
    """Validate a list of threat dicts through Pydantic, returning cleaned dicts.

    Each dict is round-tripped through ``UnifiedThreat`` validation:
    1. Normalizes priority (e.g. "alto" → "High")
    2. Normalizes stride_category (e.g. "spoofing" → "S")
    3. Clamps DREAD scores to valid ranges (0-10 per dimension, 0-50 total)
    4. Ensures all required fields have defaults

    Invalid dicts are logged and skipped (never raises for individual items).
    Returns only the successfully validated dicts.
    """
    import logging
    _logger = logging.getLogger(__name__)
    validated: list[dict] = []
    for i, raw in enumerate(threats):
        try:
            model = UnifiedThreat.model_validate(raw)
            validated.append(model.to_state_dict())
        except Exception as exc:
            _logger.warning(
                "validate_state_threats: item %d failed validation: %s",
                i, exc,
            )
    return validated


# ---------------------------------------------------------------------------
# Methodology Report Schema
# ---------------------------------------------------------------------------

class MethodologyReport(BaseModel):
    """Output schema for individual methodology agents."""
    methodology: str
    agent: str = ""
    report: str = ""
    threats_raw: list[dict] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Quality Metrics
# ---------------------------------------------------------------------------

class AgentMetrics(BaseModel):
    """Quality metrics collected during agent execution."""
    agent_name: str
    execution_time_seconds: float = 0.0
    llm_calls: int = 0
    tool_calls: int = 0
    json_parse_strategy: str = Field(
        default="direct",
        description="Which JSON parsing strategy succeeded: direct | cleaned | regex | markdown_extract | fallback"
    )
    threats_produced: int = 0
    self_reflection_applied: bool = False
    errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# API Request/Response schemas
# ---------------------------------------------------------------------------

class JustifyThreatRequest(BaseModel):
    """Request body for PUT /api/results/{id}/threats/{threat_id}/justify."""
    decision: JustificationDecision
    reason_text: str = Field(min_length=50)
    justified_by: str = ""
    context_snapshot: dict = Field(default_factory=dict)


class JustifyThreatResponse(BaseModel):
    """Response for a successful threat justification."""
    threat_id: str
    decision: JustificationDecision
    justified_at: datetime
    message: str = "Justification saved successfully"
