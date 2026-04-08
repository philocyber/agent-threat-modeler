"""Shared pipeline state — LangGraph TypedDict."""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


# ---------------------------------------------------------------------------
# Sub-types
# ---------------------------------------------------------------------------

class Component(TypedDict, total=False):
    name: str
    type: str           # "process" | "data_store" | "external_entity"
    description: str
    scope: str          # "internal" | "dmz" | "public" | "cloud"


class DataFlow(TypedDict, total=False):
    source: str
    destination: str
    protocol: str
    data_type: str
    bidirectional: bool


class TrustBoundary(TypedDict, total=False):
    name: str
    components_inside: list[str]
    components_outside: list[str]


class Threat(TypedDict, total=False):
    id: str
    component: str
    description: str
    methodology: str        # "STRIDE" | "PASTA" | "ATTACK_TREE" | "MAESTRO"
    stride_category: str    # S | T | R | I | D | E | A (ASTRIDE)
    attack_path: str
    damage: int             # DREAD 0-10
    reproducibility: int
    exploitability: int
    affected_users: int
    discoverability: int
    dread_total: int        # Sum 5-50 (avg: Critical>=9, High>=7, Medium>=4, Low<4)
    priority: str           # "Critical" | "High" | "Medium" | "Low"
    mitigation: str
    control_reference: str
    effort: str             # "Low" | "Medium" | "High"
    observations: str
    status: str             # "Open" | "Mitigated" | "Accepted"

    # ── Evidence & Confidence ──
    evidence_sources: list[dict[str, str]]  # [{source_type, source_name, excerpt}]
    confidence_score: float                  # 0.0 – 1.0

    # ── Post-analysis user justification ──
    justification: dict[str, Any] | None     # ThreatJustification serialized


class DebateEntry(TypedDict, total=False):
    round: int
    side: str               # "red" | "blue"
    argument: str           # Prose argument (for report rendering)
    threat_assessments: list[dict[str, Any]]  # Structured per-threat verdicts


# ---------------------------------------------------------------------------
# Main State — flows through the entire LangGraph graph
# ---------------------------------------------------------------------------

class ThreatModelState(TypedDict, total=False):
    """Shared state flowing through the LangGraph pipeline.

    Each agent reads what it needs and writes its section.
    Fields with Annotated[list, operator.add] accumulate
    automatically when multiple nodes write in parallel.
    """

    # ── Identification ──
    system_name: str
    analysis_date: str

    # ── User input ──
    raw_input: str
    input_type: str  # "text" | "mermaid" | "image" | "drawio"

    # ── Phase I — System model ──
    system_description: str
    components: list[Component]
    data_flows: list[DataFlow]
    trust_boundaries: list[TrustBoundary]
    external_entities: list[Component]
    data_stores: list[Component]
    scope_notes: str
    mermaid_dfd: str

    # ── Phase II — Methodology reports (accumulated in parallel) ──
    methodology_reports: Annotated[list[dict[str, Any]], operator.add]
    # Each dict: {"methodology": str, "agent": str, "report": str, "threats_raw": list[dict]}

    # ── RAG Context ──
    rag_context: dict[str, str]
    previous_tm_context: str
    threat_categories: list[str]  # Active categories: "base", "aws", "ai", etc.

    # ── Phase III — Debate ──
    debate_history: Annotated[list[DebateEntry], operator.add]
    debate_round: int
    max_debate_rounds: int  # per-request cap; defaults to config.pipeline.max_debate_rounds if absent

    # ── Phase III — Synthesis ──
    threats_final: list[Threat]
    executive_summary: str

    # ── Localized debate (non-append, set by output_localizer) ──
    debate_history_localized: list[dict[str, Any]]

    # ── Phase IV — Output ──
    csv_output: str
    report_output: str

    # ── Flow control ──
    iteration_count: int
    validation_result: dict[str, Any]

    # ── Error tracking — accumulated from failed nodes (C07) ──
    _errors: Annotated[list[dict[str, Any]], operator.add]

    # ── Memory / Feedback ──
    feedback_context: str

    # ── Architecture Clarification ──
    clarification_needed: bool
    clarification_questions: list[str]
    user_answers: list[str]
    quality_score: int

    # ── Architecture Review (Phase I.5) ──
    architecture_review: dict[str, Any]  # Full review results (gaps, inferred components, complexity, surfaces)
    threat_surface_summary: str          # Analyst briefing text
    system_complexity: str               # "simple" | "moderate" | "complex"
    mandatory_threat_patterns: list[dict[str, Any]]  # [{pattern_id, name, description, keywords, stride_category}]
