"""Agent: Output Localizer — Final translation layer.

Keeps the internal multi-agent pipeline in English and translates final
user-facing outputs to Spanish:
  - debate_history arguments  (prose from Red/Blue teams)
  - mermaid_dfd labels        (DFD node/edge text)
  - attack_tree report labels (Mermaid tree text)

NOTE: threats_final and executive_summary are now generated in Spanish
directly by the Threat Synthesizer when output_language='es', so this
agent only handles the debate and diagram translations — much smaller
payload, much higher success rate.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING

from agentictm.agents.base import extract_json_from_response, invoke_agent
from agentictm.state import ThreatModelState

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel
    from agentictm.config import AgenticTMConfig

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a security content localizer.

Task: translate specific threat-model outputs from English to neutral professional Spanish.

Rules:
1) Preserve JSON structure and field names exactly.
2) Do NOT modify numeric values, IDs, priorities, or control references.
3) Translate only natural-language text fields.
4) For Mermaid diagrams:
   - Preserve Mermaid syntax (graph/flowchart, arrows, brackets, IDs).
   - Translate node labels and edge labels to Spanish.
   - Keep diagram valid Mermaid.
5) Keep terminology professional and concise.
6) For debate arguments: preserve any references to threat IDs (TM-001, etc.)
   and technical terms (JWT, SSRF, XSS) in English.
7) Return ONLY a valid JSON object.

Output schema:
{
  "mermaid_dfd": "...",
  "debate_history": [ ... same entries with translated argument ... ],
  "attack_tree_reports": [
    {"index": 0, "methodology": "ATTACK_TREE", "report": "<valid JSON string with Spanish labels>"}
  ]
}
"""


def _build_prompt(state: ThreatModelState) -> str:
    mermaid_dfd = state.get("mermaid_dfd", "")

    # Only include debate arguments (not the full threat_assessments JSON)
    debate_history = []
    for entry in state.get("debate_history", []):
        side = entry.get("side", "") if isinstance(entry, dict) else getattr(entry, "side", "")
        rnd = entry.get("round", "") if isinstance(entry, dict) else getattr(entry, "round", "")
        arg = entry.get("argument", "") if isinstance(entry, dict) else getattr(entry, "argument", "")
        # Truncate very long debate arguments to keep payload manageable
        if len(arg) > 3000:
            arg = arg[:3000] + "\n... [truncated]"
        debate_history.append({"round": rnd, "side": side, "argument": arg})

    attack_tree_reports = []
    for index, report in enumerate(state.get("methodology_reports", [])):
        methodology = report.get("methodology", "")
        if methodology in {"ATTACK_TREE", "ATTACK_TREE_ENRICHED"}:
            report_text = report.get("report", "")
            if len(report_text) > 4000:
                report_text = report_text[:4000] + "..."
            attack_tree_reports.append(
                {
                    "index": index,
                    "methodology": methodology,
                    "report": report_text,
                }
            )

    payload = {
        "mermaid_dfd": mermaid_dfd,
        "debate_history": debate_history,
        "attack_tree_reports": attack_tree_reports,
    }
    return (
        "Translate this payload to Spanish following the rules.\n\n"
        "```json\n"
        f"{json.dumps(payload, ensure_ascii=False)}\n"
        "```"
    )


def run_output_localizer(
    state: ThreatModelState,
    llm: BaseChatModel,
    config: "AgenticTMConfig | None" = None,
) -> dict:
    """LangGraph node: translate user-facing final outputs to Spanish.

    Only translates debate_history, mermaid_dfd, and attack_tree labels.
    Threats and executive summary are generated in Spanish by the synthesizer.
    """
    output_lang = "es"
    if config:
        output_lang = config.pipeline.output_language
    if output_lang != "es":
        logger.info("[Output Localizer] output_language=%s, skipping localization", output_lang)
        return {}

    debate = state.get("debate_history", [])
    mermaid = state.get("mermaid_dfd", "")
    if not debate and not mermaid:
        logger.info("[Output Localizer] No debate or DFD to translate, skipping")
        return {}

    logger.info("[Output Localizer] Translating debate (%d entries) + DFD to Spanish...", len(debate))
    t0 = time.perf_counter()
    response = invoke_agent(
        llm,
        SYSTEM_PROMPT,
        _build_prompt(state),
        tools=None,
        max_tool_rounds=1,
        agent_name="Output Localizer",
    )
    elapsed = time.perf_counter() - t0

    parsed = extract_json_from_response(response)
    if not isinstance(parsed, dict):
        logger.warning("[Output Localizer] Could not parse translation JSON, keeping originals")
        return {}

    result: dict = {}

    # ── DFD translation ──
    localized_dfd = parsed.get("mermaid_dfd", "")
    if localized_dfd and isinstance(localized_dfd, str) and len(localized_dfd) > 10:
        result["mermaid_dfd"] = localized_dfd

    # ── Debate history translation ──
    # NOTE: debate_history uses Annotated[list, operator.add] in state, so
    # returning it here would APPEND translated entries as duplicates.
    # We intentionally skip writing debate_history to avoid duplication.
    # The debate is technical security content best kept in English.
    localized_debate = parsed.get("debate_history", [])
    if localized_debate:
        logger.info(
            "[Output Localizer] Debate translation produced %d entries (not stored to avoid duplication)",
            len(localized_debate),
        )

    # ── Attack tree reports ──
    methodology_reports = list(state.get("methodology_reports", []))
    for translated in parsed.get("attack_tree_reports", []) or []:
        if not isinstance(translated, dict):
            continue
        index = translated.get("index")
        report_text = translated.get("report")
        if isinstance(index, int) and 0 <= index < len(methodology_reports) and isinstance(report_text, str):
            methodology_reports[index] = {
                **methodology_reports[index],
                "report": report_text,
            }
            result["methodology_reports"] = methodology_reports

    logger.info(
        "[Output Localizer] Completed in %.1fs | translated keys: %s",
        elapsed, list(result.keys()),
    )
    return result
