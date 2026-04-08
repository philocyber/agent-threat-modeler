"""LLM-based enrichment and translation of baseline threats."""

from __future__ import annotations

import concurrent.futures
import json
import logging
from typing import TYPE_CHECKING

from agentictm.agents.base import invoke_agent, extract_json_from_response
from agentictm.agents.synthesis.classification import (
    _to_str,
    _DEFAULT_MITIGATIONS,
    _find_threats_array,
)
from agentictm.logging import with_logging_context

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Translation constants
# ---------------------------------------------------------------------------

_TRANSLATE_SYSTEM_PROMPT = """\
You are a professional security content translator.

Task: translate threat model text fields from English to neutral professional Spanish.

Rules:
1. Keep technical terms, acronyms, and framework references in English:
   STRIDE, DREAD, XSS, IDOR, SSRF, JWT, NIST, CIS, OWASP, CAPEC, CWE,
   ATT&CK, CVE, API, SQL, IAM, S3, OAuth, MFA, TLS, RBAC, PII, DoS, etc.
2. Return ONLY a JSON array with {"index": <int>, "description": "...", "mitigation": "...", "attack_path": "..."}.
3. Match the "index" to the position in the input array (0-based).
4. Keep the meaning, severity, and specificity identical — only change the language.
5. If a field is already in Spanish, return it unchanged.
"""

_TRANSLATE_BATCH_SIZE = 12
_TRANSLATE_TIMEOUT = 180


def _detect_english(text: str) -> bool:
    """Heuristic: return True if text looks predominantly English."""
    if not text or len(text) < 20:
        return False
    english_markers = [
        "the ", " is ", " are ", " was ", " with ", " this ", " that ",
        " could ", " would ", " should ", " which ", " have ", " from ",
        " into ", " without ", " their ", " there ", " however ",
        " if an ", " an attacker", " allowing ", " ensure ",
    ]
    text_lower = text.lower()
    hits = sum(1 for m in english_markers if m in text_lower)
    return hits >= 3


def _translate_baseline_threats(
    threats: list[dict],
    llm: BaseChatModel,
    output_language: str = "en",
) -> list[dict]:
    """Translate English baseline threats to the target language via batched LLM calls.

    Only processes threats whose description looks English. On failure, returns
    originals unchanged (never loses data).
    """
    if output_language != "es":
        return threats

    english_indices: list[int] = []
    for i, t in enumerate(threats):
        desc = t.get("description", "")
        mit = t.get("mitigation", "")
        if _detect_english(desc) or _detect_english(mit):
            english_indices.append(i)

    if not english_indices:
        logger.info("[Translate] All %d baseline threats appear to be in Spanish -- skipping", len(threats))
        return threats

    logger.info(
        "[Translate] %d/%d baseline threats detected as English — translating to Spanish",
        len(english_indices), len(threats),
    )

    for batch_start in range(0, len(english_indices), _TRANSLATE_BATCH_SIZE):
        batch_idx = english_indices[batch_start:batch_start + _TRANSLATE_BATCH_SIZE]
        batch_items = []
        for pos, idx in enumerate(batch_idx):
            t = threats[idx]
            batch_items.append({
                "index": pos,
                "description": t.get("description", ""),
                "mitigation": t.get("mitigation", ""),
                "attack_path": t.get("attack_path", ""),
            })

        human_prompt = (
            "Translate these threat fields to professional Spanish:\n\n"
            f"```json\n{json.dumps(batch_items, indent=2, ensure_ascii=False)}\n```"
        )

        try:
            def _invoke_translate():
                return invoke_agent(
                    llm, _TRANSLATE_SYSTEM_PROMPT, human_prompt,
                    agent_name="BaselineTranslator",
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(with_logging_context(_invoke_translate))
                response = future.result(timeout=_TRANSLATE_TIMEOUT)

            parsed = extract_json_from_response(response)
            translated_items: list[dict] = []
            if isinstance(parsed, list):
                translated_items = [e for e in parsed if isinstance(e, dict)]
            elif isinstance(parsed, dict):
                translated_items = _find_threats_array(parsed) or ([parsed] if "description" in parsed else [])

            applied = 0
            for item in translated_items:
                try:
                    pos = int(item.get("index", -1))
                except (TypeError, ValueError):
                    continue
                if 0 <= pos < len(batch_idx):
                    real_idx = batch_idx[pos]
                    new_desc = _to_str(item.get("description", ""))
                    new_mit = _to_str(item.get("mitigation", ""))
                    new_path = _to_str(item.get("attack_path", ""))
                    if new_desc and len(new_desc) > 20:
                        threats[real_idx]["description"] = new_desc
                        applied += 1
                    if new_mit and len(new_mit) > 10:
                        threats[real_idx]["mitigation"] = new_mit
                    if new_path and len(new_path) > 10:
                        threats[real_idx]["attack_path"] = new_path

            logger.info(
                "[Translate] Batch %d-%d: translated %d/%d threats",
                batch_start, batch_start + len(batch_idx), applied, len(batch_idx),
            )
        except concurrent.futures.TimeoutError:
            logger.warning("[Translate] Batch %d timed out after %ds -- keeping originals", batch_start, _TRANSLATE_TIMEOUT)
        except Exception as exc:
            logger.warning("[Translate] Batch %d failed: %s -- keeping originals", batch_start, exc)

    return threats


# ---------------------------------------------------------------------------
# Enrichment constants
# ---------------------------------------------------------------------------

_ENRICH_SYSTEM_PROMPT = """\
You are a senior security engineer improving threat descriptions for developers.

You receive a list of threats that are too short or vague. For EACH threat, you must:

1. EXPAND the description to 3-5 sentences that explain:
   - WHAT the vulnerability is (specific CWE/technique if applicable)
   - HOW an attacker exploits it step-by-step against the given component
   - WHAT concrete harm results (data exfiltration, service disruption, etc.)
   Write for developers who are smart but lack security expertise.

2. PROVIDE a specific mitigation (2-3 sentences) with concrete implementation steps.
   Reference the component name and suggest actual code/config changes.

3. PROVIDE a control_reference (NIST 800-53, OWASP ASVS, CIS controls).

Return ONLY a JSON array where each element has:
  {"index": 0, "description": "...", "mitigation": "...", "control_reference": "..."}

Match the "index" to the position in the input array (0-based).
Generate ALL text in professional English.
"""

_ENRICH_BATCH_SIZE = 10
_ENRICH_TIMEOUT = 180


def _enrich_weak_threats(
    threats: list[dict],
    llm: BaseChatModel,
    system_description: str = "",
    known_components: list[str] | None = None,
) -> list[dict]:
    """Expand short descriptions and fill empty mitigations via a batched LLM call.

    Only processes threats below quality threshold.  On failure, returns
    originals unchanged (never loses data).
    """
    weak_indices: list[int] = []
    default_mit_set = set(_DEFAULT_MITIGATIONS.values())

    for i, t in enumerate(threats):
        desc_len = len((t.get("description") or "").strip())
        mit = (t.get("mitigation") or "").strip()
        is_default_mit = mit in default_mit_set
        if desc_len < 150 or not mit or is_default_mit:
            weak_indices.append(i)

    if not weak_indices:
        logger.info("[Enrich] All %d threats meet quality threshold -- skipping enrichment", len(threats))
        return threats

    logger.info(
        "[Enrich] %d/%d threats below quality threshold — enriching in batches of %d",
        len(weak_indices), len(threats), _ENRICH_BATCH_SIZE,
    )

    for batch_start in range(0, len(weak_indices), _ENRICH_BATCH_SIZE):
        batch_idx = weak_indices[batch_start:batch_start + _ENRICH_BATCH_SIZE]
        batch_items = []
        for pos, idx in enumerate(batch_idx):
            t = threats[idx]
            batch_items.append({
                "index": pos,
                "component": t.get("component", "Unknown"),
                "description": t.get("description", ""),
                "stride_category": t.get("stride_category", ""),
                "attack_path": t.get("attack_path", ""),
            })

        human_prompt = f"System context: {system_description[:2000]}\n\nThreats to enrich:\n{json.dumps(batch_items, indent=2, ensure_ascii=False)}"

        try:
            def _invoke():
                return invoke_agent(
                    llm, _ENRICH_SYSTEM_PROMPT, human_prompt,
                    agent_name="Enrichment",
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(with_logging_context(_invoke))
                response = future.result(timeout=_ENRICH_TIMEOUT)

            parsed = extract_json_from_response(response)
            enriched_items: list[dict] = []
            if isinstance(parsed, list):
                enriched_items = [e for e in parsed if isinstance(e, dict)]
            elif isinstance(parsed, dict):
                enriched_items = _find_threats_array(parsed) or ([parsed] if "description" in parsed else [])

            applied = 0
            for item in enriched_items:
                try:
                    pos = int(item.get("index", -1))
                except (TypeError, ValueError):
                    continue
                if 0 <= pos < len(batch_idx):
                    real_idx = batch_idx[pos]
                    new_desc = _to_str(item.get("description", ""))
                    new_mit = _to_str(item.get("mitigation", ""))
                    new_ctrl = _to_str(item.get("control_reference", ""))
                    if new_desc and len(new_desc) > len(threats[real_idx].get("description", "")):
                        threats[real_idx]["description"] = new_desc
                        applied += 1
                    if new_mit and len(new_mit) > len(threats[real_idx].get("mitigation", "")):
                        threats[real_idx]["mitigation"] = new_mit
                    if new_ctrl and len(new_ctrl) > len(threats[real_idx].get("control_reference", "")):
                        threats[real_idx]["control_reference"] = new_ctrl

            logger.info(
                "[Enrich] Batch %d-%d: enriched %d/%d threats",
                batch_start, batch_start + len(batch_idx), applied, len(batch_idx),
            )
        except concurrent.futures.TimeoutError:
            logger.warning("[Enrich] Batch %d timed out after %ds -- keeping originals", batch_start, _ENRICH_TIMEOUT)
        except Exception as exc:
            logger.warning("[Enrich] Batch %d failed: %s -- keeping originals", batch_start, exc)

    # ── LLM-based component inference for remaining empty components ──
    empty_comp_indices = [
        i for i, t in enumerate(threats)
        if not (t.get("component") or "").strip()
    ]
    if empty_comp_indices and len(empty_comp_indices) >= 2:
        logger.info("[Enrich] %d threats still have empty components — LLM inference", len(empty_comp_indices))
        comp_items = []
        for pos, idx in enumerate(empty_comp_indices[:15]):
            comp_items.append({
                "index": pos,
                "description": threats[idx].get("description", "")[:300],
            })
        comp_prompt = (
            f"Known components: {', '.join(c for c in (known_components or []) if c)}\n\n"
            f"For each threat below, identify the SINGLE most affected component from the list above.\n"
            f"Return JSON: [{{'index': 0, 'component': 'ComponentName'}}, ...]\n\n"
            + json.dumps(comp_items, indent=1, ensure_ascii=False)
        )
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                comp_future = executor.submit(
                    with_logging_context(lambda: invoke_agent(llm, "You map threat descriptions to architecture components. Return ONLY JSON.", comp_prompt, agent_name="ComponentInfer"))
                )
                comp_resp = comp_future.result(timeout=60)
            comp_parsed = extract_json_from_response(comp_resp)
            if isinstance(comp_parsed, list):
                comp_filled = 0
                for item in comp_parsed:
                    if not isinstance(item, dict):
                        continue
                    try:
                        pos = int(item.get("index", -1))
                    except (TypeError, ValueError):
                        continue
                    comp_name = _to_str(item.get("component", ""))
                    if 0 <= pos < len(empty_comp_indices) and comp_name:
                        threats[empty_comp_indices[pos]]["component"] = comp_name
                        comp_filled += 1
                logger.info("[Enrich] LLM inferred components for %d/%d threats", comp_filled, len(empty_comp_indices))
        except Exception as comp_exc:
            logger.warning("[Enrich] LLM component inference failed: %s", comp_exc)

    return threats
