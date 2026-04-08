"""Agent: Architecture Clarifier.

Generates specific questions for the user when the architecture model
initially extracted (Phase I) has low quality or is missing critical details.
Enables the back-and-forth requested by the user to guide them.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from agentictm.agents.base import build_messages, ensure_str_content, extract_json_from_response

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel
    from agentictm.state import ThreatModelState

logger = logging.getLogger(__name__)

CLARIFIER_SYSTEM_PROMPT = """\
You are a senior security architect. You have just analyzed a user's system 
description and/or architecture diagrams, but the information is INCOMPLETE 
or AMBIGUOUS. 

Your goal is to ask 3-5 high-quality, targeted clarifying questions that will 
help the user provide the missing details needed for a professional threat model.

Focus on:
1. Missing components (what's hidden or not named?)
2. Unclear data flows (how exactly does A talk to B?)
3. Technical gaps (what's the tech stack or cloud provider?)
4. Authentication/Authorization (how are sessions managed?)
5. Trust boundaries (where does the public internet end and the private network begin?)

RULES:
- Be professional and encouraging.
- Do NOT be generic. Mention specific components found so far.
- If the Vision AI (VLM) failed on some images, ask about them.
- If the user wrote in Spanish, ask in Spanish.
- Return ONLY valid JSON.

Format:
{
  "questions": ["...", "...", "..."],
  "suggestions": ["...", "..."]
}
"""

def run_arch_clarifier(state: ThreatModelState, llm: BaseChatModel) -> dict:
    """Generation node for clarification questions."""
    review = state.get("architecture_review", {}) if isinstance(state.get("architecture_review"), dict) else {}

    # Context of what we already know and what we're missing
    summary = {
        "system_description": state.get("system_description", ""),
        "components_found": [c.get("name") for c in state.get("components", [])],
        "flows_found": len(state.get("data_flows", [])),
        "quality_score": state.get("quality_score", 0),
        "input_type": state.get("input_type", "text"),
        "review_gaps": [g.get("finding") for g in review.get("gaps", []) if isinstance(g, dict)],
        "clarification_focus": review.get("clarification_focus", []),
        "inferred_components": [c.get("name") for c in review.get("inferred_components", []) if isinstance(c, dict)],
    }

    user_prompt = (
        f"The user wants to threat model their system. Here is what we extracted and reviewed so far:\n\n"
        f"MODEL SUMMARY:\n{json.dumps(summary, indent=2, ensure_ascii=False)}\n\n"
        f"USER ORIGINAL INPUT:\n{state.get('raw_input', '')[:5000]}\n\n"
        "Generate 3-5 specific clarifying questions that resolve the most important review gaps. "
        "Prefer questions that confirm missing architecture details instead of inventing new components."
    )

    logger.info("[Arch Clarifier] Generating questions | score=%d", summary["quality_score"])

    messages = build_messages(CLARIFIER_SYSTEM_PROMPT, user_prompt)
    response = llm.invoke(messages)
    content = ensure_str_content(response.content) if hasattr(response, "content") else str(response)

    parsed = extract_json_from_response(content)
    questions = []
    if parsed:
        questions = parsed.get("questions", [])

    if not questions:
        # Fallback simplistic questions
        questions = [
            "Could you provide more details about the main components of the system?",
            "How do users authenticate and how does information flow between services?",
            "What specific technologies are you using (languages, databases)?",
        ]

    return {
        "clarification_questions": questions,
        "clarification_needed": True,
    }
