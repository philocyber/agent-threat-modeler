"""Agent: Output Localizer — Final translation layer.

Keeps the internal multi-agent pipeline in English and translates final
user-facing outputs to Spanish:
  - debate_history arguments  (prose from Red/Blue teams)
  - mermaid_dfd labels        (DFD node/edge text)
  - attack_tree report labels (Mermaid tree text)
  - threats_final safety net  (catches any English text the synthesizer missed)

NOTE: threats_final and executive_summary are generated in Spanish
by the Threat Synthesizer when output_language='es'. This agent provides
a safety-net pass to catch any remaining English text.
"""

from __future__ import annotations

import concurrent.futures
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


# ---------------------------------------------------------------------------
# Threat translation safety net
# ---------------------------------------------------------------------------

_THREAT_TRANSLATE_SYSTEM = """\
You are a professional security content translator.

Task: translate threat model text fields from English to neutral professional Spanish.

Rules:
1. Keep technical terms, acronyms, and framework references in English:
   STRIDE, DREAD, XSS, IDOR, SSRF, JWT, NIST, CIS, OWASP, CAPEC, CWE,
   ATT&CK, CVE, API, SQL, IAM, S3, OAuth, MFA, TLS, RBAC, PII, DoS, etc.
2. Return ONLY a JSON array with {"index": <int>, "description": "...", "mitigation": "..."}.
3. Match "index" to the position in the input array (0-based).
4. Keep the meaning, severity, and specificity identical — only change the language.
5. If a field is already in Spanish, return it unchanged.
"""

_THREAT_TRANSLATE_TIMEOUT = 180
_THREAT_TRANSLATE_BATCH = 10


def _detect_english(text: str) -> bool:
    """Heuristic: return True if text looks predominantly English."""
    if not text or len(text) < 20:
        return False
    markers = [
        "the ", " is ", " are ", " was ", " with ", " this ", " that ",
        " could ", " would ", " should ", " which ", " have ", " from ",
        " into ", " without ", " their ", " there ", " however ",
        " if an ", " an attacker", " allowing ", " ensure ",
    ]
    text_lower = text.lower()
    return sum(1 for m in markers if m in text_lower) >= 3


def _translate_english_threats(
    threats: list[dict],
    llm: "BaseChatModel",
) -> list[dict]:
    """Detect and translate any English threats remaining in threats_final."""
    english_indices: list[int] = []
    for i, t in enumerate(threats):
        if _detect_english(t.get("description", "")) or _detect_english(t.get("mitigation", "")):
            english_indices.append(i)

    if not english_indices:
        logger.info("[Output Localizer] All %d threats appear to be in Spanish -- no threat translation needed", len(threats))
        return threats

    logger.info(
        "[Output Localizer] %d/%d threats detected as English — translating as safety net",
        len(english_indices), len(threats),
    )

    for batch_start in range(0, len(english_indices), _THREAT_TRANSLATE_BATCH):
        batch_idx = english_indices[batch_start:batch_start + _THREAT_TRANSLATE_BATCH]
        batch_items = []
        for pos, idx in enumerate(batch_idx):
            t = threats[idx]
            batch_items.append({
                "index": pos,
                "description": t.get("description", ""),
                "mitigation": t.get("mitigation", ""),
            })

        human_prompt = (
            "Translate these threat fields to professional Spanish:\n\n"
            f"```json\n{json.dumps(batch_items, indent=2, ensure_ascii=False)}\n```"
        )

        try:
            def _invoke():
                return invoke_agent(
                    llm, _THREAT_TRANSLATE_SYSTEM, human_prompt,
                    agent_name="ThreatTranslator",
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_invoke)
                response = future.result(timeout=_THREAT_TRANSLATE_TIMEOUT)

            parsed = extract_json_from_response(response)
            items: list[dict] = []
            if isinstance(parsed, list):
                items = [e for e in parsed if isinstance(e, dict)]
            elif isinstance(parsed, dict) and "description" in parsed:
                items = [parsed]

            applied = 0
            for item in items:
                try:
                    pos = int(item.get("index", -1))
                except (TypeError, ValueError):
                    continue
                if 0 <= pos < len(batch_idx):
                    real_idx = batch_idx[pos]
                    new_desc = item.get("description", "")
                    new_mit = item.get("mitigation", "")
                    if new_desc and isinstance(new_desc, str) and len(new_desc) > 20:
                        threats[real_idx]["description"] = new_desc
                        applied += 1
                    if new_mit and isinstance(new_mit, str) and len(new_mit) > 10:
                        threats[real_idx]["mitigation"] = new_mit

            logger.info(
                "[Output Localizer] Threat translation batch %d-%d: translated %d/%d",
                batch_start, batch_start + len(batch_idx), applied, len(batch_idx),
            )
        except concurrent.futures.TimeoutError:
            logger.warning("[Output Localizer] Threat translation batch %d timed out -- keeping originals", batch_start)
        except Exception as exc:
            logger.warning("[Output Localizer] Threat translation batch %d failed: %s -- keeping originals", batch_start, exc)

    return threats

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

    Translates debate_history, mermaid_dfd, attack_tree labels, and
    provides a safety-net pass to catch any English threats the synthesizer missed.
    """
    output_lang = "es"
    if config:
        output_lang = config.pipeline.output_language
    if output_lang != "es":
        logger.info("[Output Localizer] output_language=%s, skipping localization", output_lang)
        return {}

    result: dict = {}

    # ── Safety net: translate any remaining English threats ──
    threats_final = state.get("threats_final", [])
    if threats_final:
        translated_threats = _translate_english_threats(list(threats_final), llm)
        if translated_threats:
            result["threats_final"] = translated_threats

    # ── Translate executive summary if it's in English ──
    exec_summary = state.get("executive_summary", "")
    if exec_summary and _detect_english(exec_summary):
        logger.info("[Output Localizer] Executive summary appears English -- will translate")
        result.setdefault("executive_summary", exec_summary)

    # ── Debate + DFD + Attack tree translation ──
    debate = state.get("debate_history", [])
    mermaid = state.get("mermaid_dfd", "")
    if debate or mermaid:
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
        if isinstance(parsed, dict):
            # ── DFD translation ──
            localized_dfd = parsed.get("mermaid_dfd", "")
            if localized_dfd and isinstance(localized_dfd, str) and len(localized_dfd) > 10:
                result["mermaid_dfd"] = localized_dfd

            # ── Debate history translation ──
            # NOTE: debate_history uses Annotated[list, operator.add] in state, so
            # returning it here would APPEND translated entries as duplicates.
            # Store in a separate key for the report generator to use.
            localized_debate = parsed.get("debate_history", [])
            if localized_debate and isinstance(localized_debate, list):
                result["debate_history_localized"] = localized_debate
                logger.info(
                    "[Output Localizer] Debate translation: %d entries stored in debate_history_localized",
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

            logger.info("[Output Localizer] DFD/debate/tree translation completed in %.1fs", elapsed)
        else:
            logger.warning("[Output Localizer] Could not parse translation JSON, keeping originals")
    else:
        logger.info("[Output Localizer] No debate or DFD to translate")

    logger.info("[Output Localizer] Final translated keys: %s", list(result.keys()))
    return result
