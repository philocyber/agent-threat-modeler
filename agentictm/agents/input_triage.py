"""Input Triage Agent — evaluates input quality and asks clarifying questions.

This agent runs BEFORE the full analysis pipeline starts. It uses a lightweight
LLM call to assess the user's system description and generate targeted questions
to improve the input quality.

Flow:
    1. Rule-based scoring (deterministic) — checks for components, data flows,
       tech stack, deployment model, auth, etc.
    2. If score < threshold → LLM generates specific clarifying questions
    3. User answers → enriched input → re-evaluate or proceed

Usage::

    from agentictm.agents.input_triage import triage_input, enrich_with_answers

    result = triage_input(system_input, llm)
    # result.verdict = "ready" | "needs_info"
    # result.questions = ["What database...?", "How is auth...?"]

    if result.verdict == "needs_info":
        enriched = enrich_with_answers(system_input, result.questions, user_answers)
        result2 = triage_input(enriched, llm)
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Quality dimensions to check (rule-based)
# ---------------------------------------------------------------------------

_DIMENSION_CHECKS: list[tuple[str, str, list[str], float]] = [
    # (dimension_name, description, keywords_to_look_for, weight)
    (
        "components",
        "System components (servers, databases, services, APIs)",
        ["server", "service", "api", "database", "db", "frontend", "backend",
         "gateway", "proxy", "cache", "queue", "worker", "microservice",
         "container", "lambda", "function", "app", "application", "web"],
        0.20,
    ),
    (
        "data_flows",
        "Data flows between components (who sends what to whom)",
        ["sends", "receives", "communicates", "connects", "calls", "requests",
         "responds", "publishes", "subscribes", "flow", "transfer", "sync",
         "stream", "push", "pull", "webhook", "event", "message", "payload"],
        0.15,
    ),
    (
        "tech_stack",
        "Technologies used (languages, frameworks, databases, cloud services)",
        ["python", "java", "node", "react", "angular", "vue", "django", "flask",
         "spring", "express", "fastapi", "postgresql", "mysql", "mongodb",
         "redis", "kafka", "rabbitmq", "elasticsearch", "nginx", "apache",
         "docker", "kubernetes", "terraform", "aws", "azure", "gcp",
         "lambda", "s3", "ec2", "rds", "dynamodb", "cosmos", "bigquery"],
        0.15,
    ),
    (
        "authentication",
        "Authentication and authorization mechanisms",
        ["auth", "login", "jwt", "oauth", "oidc", "saml", "ldap", "sso",
         "token", "session", "cookie", "api key", "certificate", "mtls",
         "rbac", "acl", "permission", "role", "credential", "password",
         "mfa", "2fa", "biometric"],
        0.15,
    ),
    (
        "data_sensitivity",
        "Types of data handled (PII, financial, health, etc.)",
        ["pii", "personal", "financial", "payment", "credit card", "ssn",
         "health", "medical", "phi", "hipaa", "gdpr", "sensitive",
         "confidential", "secret", "credential", "password", "encrypted",
         "user data", "customer", "email", "address", "phone"],
        0.10,
    ),
    (
        "deployment",
        "Deployment model and infrastructure",
        ["cloud", "on-prem", "hybrid", "kubernetes", "k8s", "docker",
         "container", "serverless", "vm", "vpc", "subnet", "firewall",
         "load balancer", "cdn", "dns", "ssl", "tls", "https",
         "production", "staging", "dev", "ci/cd", "pipeline"],
        0.10,
    ),
    (
        "trust_boundaries",
        "Trust boundaries and network zones",
        ["dmz", "internal", "external", "public", "private", "internet",
         "intranet", "vpn", "firewall", "boundary", "zone", "segment",
         "trust", "untrusted", "third-party", "partner", "vendor",
         "client", "user", "admin"],
        0.10,
    ),
    (
        "scale_context",
        "Scale and usage context",
        ["users", "requests", "concurrent", "traffic", "load", "scale",
         "availability", "uptime", "sla", "performance", "latency",
         "throughput", "region", "multi-region", "geo", "replicate"],
        0.05,
    ),
]

# Minimum word count for a "useful" description
_MIN_WORDS = 30
_GOOD_WORDS = 100
_GREAT_WORDS = 300

# Threshold for "ready" verdict (0-100)
_READY_THRESHOLD = 55


@dataclass
class TriageResult:
    """Result of input quality assessment."""
    session_id: str = ""
    verdict: str = "needs_info"  # "ready" | "needs_info"
    quality_score: int = 0  # 0-100
    dimensions: list[dict[str, Any]] = field(default_factory=list)
    questions: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    enriched_input: str = ""  # original + user answers combined
    original_input: str = ""


def _score_dimensions(text: str) -> tuple[int, list[dict[str, Any]]]:
    """Score input quality across all dimensions (deterministic, no LLM).

    Returns (score_0_100, dimension_details).
    """
    text_lower = text.lower()
    words = text.split()
    word_count = len(words)

    dimensions: list[dict[str, Any]] = []
    weighted_score = 0.0

    # Word count bonus
    if word_count >= _GREAT_WORDS:
        length_bonus = 1.0
    elif word_count >= _GOOD_WORDS:
        length_bonus = 0.7
    elif word_count >= _MIN_WORDS:
        length_bonus = 0.4
    else:
        length_bonus = 0.1

    dimensions.append({
        "name": "input_length",
        "label": "Description depth",
        "score": round(length_bonus, 2),
        "detail": f"{word_count} words",
        "found": word_count >= _MIN_WORDS,
    })

    for name, description, keywords, weight in _DIMENSION_CHECKS:
        matches = [kw for kw in keywords if kw in text_lower]
        hit_ratio = min(1.0, len(matches) / max(3, len(keywords) * 0.15))
        found = len(matches) > 0

        dimensions.append({
            "name": name,
            "label": description,
            "score": round(hit_ratio, 2),
            "detail": f"Found: {', '.join(matches[:5])}" if matches else "Not mentioned",
            "found": found,
            "weight": weight,
        })

        weighted_score += hit_ratio * weight

    # Length contributes to score too
    weighted_score = (weighted_score * 0.75 + length_bonus * 0.25)
    overall = int(round(weighted_score * 100))

    return min(100, overall), dimensions


_TRIAGE_SYSTEM_PROMPT = """\
You are a senior security architect helping a user prepare their system \
description for automated threat modeling. Your job is to review their input \
and ask smart, specific clarifying questions that will improve the quality \
of the threat model.

RULES:
- Ask 3-5 questions maximum
- Questions must be SPECIFIC and ACTIONABLE (not generic)
- Focus on what's MISSING, not what's already described
- Use the user's language (if they write in Spanish, ask in Spanish)
- Each question should be short (1-2 sentences)
- Group related questions when possible
- Prioritize: architecture gaps > auth details > data sensitivity > deployment

FORMAT: Return a JSON object:
{
  "questions": ["question 1", "question 2", ...],
  "suggestions": ["suggestion 1", ...]
}

"suggestions" are optional tips about what documentation/diagrams would help \
(e.g., "uploading an architecture diagram would significantly improve the analysis").
"""


def triage_input(
    system_input: str,
    llm: "BaseChatModel | None" = None,
    *,
    threshold: int = _READY_THRESHOLD,
) -> TriageResult:
    """Evaluate input quality and optionally generate clarifying questions.

    Args:
        system_input: The user's system description
        llm: Optional LLM for generating questions (if None, only rule-based)
        threshold: Score threshold for "ready" verdict (0-100)

    Returns:
        TriageResult with verdict, score, dimensions, and questions
    """
    session_id = uuid.uuid4().hex[:12]
    score, dimensions = _score_dimensions(system_input)

    result = TriageResult(
        session_id=session_id,
        quality_score=score,
        dimensions=dimensions,
        original_input=system_input,
        enriched_input=system_input,
    )

    if score >= threshold:
        result.verdict = "ready"
        logger.info("[Triage] Input quality sufficient (score=%d/%d threshold). Proceeding.", score, threshold)
        return result

    result.verdict = "needs_info"

    # Generate questions with LLM if available
    if llm is not None:
        try:
            missing_dims = [d for d in dimensions if not d.get("found", True)]
            missing_summary = ", ".join(d["label"] for d in missing_dims[:5])

            user_prompt = (
                f"The user wants to perform threat modeling on their system. "
                f"Here is their current description:\n\n---\n{system_input}\n---\n\n"
                f"The following aspects are missing or insufficient: {missing_summary}.\n"
                f"Quality score: {score}/100 (threshold: {threshold}).\n\n"
                f"Generate clarifying questions to fill the gaps."
            )

            from agentictm.agents.base import build_messages, extract_json_from_response, ensure_str_content
            messages = build_messages(_TRIAGE_SYSTEM_PROMPT, user_prompt)
            response = llm.invoke(messages)
            content = ensure_str_content(response.content) if hasattr(response, "content") else str(response)

            parsed = extract_json_from_response(content)
            if parsed:
                result.questions = parsed.get("questions", [])[:5]
                result.suggestions = parsed.get("suggestions", [])[:3]

            logger.info(
                "[Triage] Generated %d questions for user (score=%d, missing=%s)",
                len(result.questions), score, missing_summary,
            )
        except Exception as e:
            logger.warning("[Triage] LLM question generation failed: %s", e)
            # Fall back to rule-based questions
            result.questions = _generate_fallback_questions(dimensions)
    else:
        result.questions = _generate_fallback_questions(dimensions)

    return result


def _generate_fallback_questions(dimensions: list[dict[str, Any]]) -> list[str]:
    """Generate fallback questions based on missing dimensions (no LLM needed)."""
    questions = []
    missing = {d["name"] for d in dimensions if not d.get("found", True)}

    if "components" in missing:
        questions.append(
            "¿Cuáles son los componentes principales de tu sistema? "
            "(ej: frontend, backend, base de datos, APIs, servicios externos)"
        )
    if "data_flows" in missing:
        questions.append(
            "¿Cómo se comunican los componentes entre sí? "
            "¿Qué protocolos usan? (ej: REST, gRPC, WebSocket, mensajería)"
        )
    if "tech_stack" in missing:
        questions.append(
            "¿Qué tecnologías usa cada componente? "
            "(ej: Python/FastAPI, React, PostgreSQL, Redis, Docker)"
        )
    if "authentication" in missing:
        questions.append(
            "¿Cómo se autentican los usuarios y servicios? "
            "(ej: JWT, OAuth2, API keys, certificados mTLS)"
        )
    if "data_sensitivity" in missing:
        questions.append(
            "¿Qué tipos de datos sensibles maneja el sistema? "
            "(ej: datos personales/PII, financieros, de salud, credenciales)"
        )
    if "deployment" in missing and len(questions) < 5:
        questions.append(
            "¿Dónde se despliega el sistema? "
            "(ej: AWS, Azure, on-premise, Kubernetes, Docker Compose)"
        )

    return questions[:5]


def enrich_with_answers(
    original_input: str,
    questions: list[str],
    answers: list[str],
) -> str:
    """Combine the original input with user answers to create enriched input.

    Args:
        original_input: The original system description
        questions: Questions that were asked
        answers: User's answers to those questions

    Returns:
        Enriched system description with answers appended
    """
    if not answers:
        return original_input

    enrichment_parts = [original_input, "\n\n--- Additional Details (from user) ---\n"]

    for i, (q, a) in enumerate(zip(questions, answers), 1):
        if a.strip():
            enrichment_parts.append(f"\n**Q{i}**: {q}\n**A{i}**: {a}\n")

    return "\n".join(enrichment_parts)
