"""Agente: Architecture Clarifier.

Genera preguntas específicas para el usuario cuando el modelo de arquitectura
extraído inicialmente (Fase I) tiene una calidad baja o faltan detalles críticos.
Permite el "ida y vuelta" solicitado por el usuario para guiarlo.
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
    
    # Contexto de lo que ya sabemos y lo que nos falta
    summary = {
        "system_description": state.get("system_description", ""),
        "components_found": [c.get("name") for c in state.get("components", [])],
        "flows_found": len(state.get("data_flows", [])),
        "quality_score": state.get("quality_score", 0),
        "input_type": state.get("input_type", "text")
    }
    
    user_prompt = (
        f"The user wants to threat model their system. Here is what we extracted so far:\n\n"
        f"MODEL SUMMARY:\n{json.dumps(summary, indent=2, ensure_ascii=False)}\n\n"
        f"USER ORIGINAL INPUT:\n{state.get('raw_input', '')[:5000]}\n\n"
        f"Generate 3-5 specific clarifying questions to improve this model."
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
            "¿Podrías dar más detalles sobre los componentes principales del sistema?",
            "¿Cómo se autentican los usuarios y cómo fluye la información entre los servicios?",
            "¿Qué tecnologías específicas estás utilizando (lenguajes, bases de datos)?",
        ]

    return {
        "clarification_questions": questions,
    }
