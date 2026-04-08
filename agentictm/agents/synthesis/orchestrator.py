"""Threat Synthesizer orchestrator — main LangGraph node entry point.

Combines the best of each methodology (STRIDE, PASTA, Attack Tree, MAESTRO),
incorporates the Red/Blue debate results, and produces the final list of
threats with DREAD scores and mitigations.

This is a Deep Thinker agent — uses the most capable model.

**Hybrid strategy**: Always starts with a BASELINE of ALL raw threats from
every analyst, then asks the LLM to enrich/deduplicate.  If the LLM
produces fewer threats than a safety threshold, the baseline is used
(supplemented with any LLM enrichments that match).
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import time
from typing import TYPE_CHECKING

from agentictm.agents.base import (
    invoke_agent,
    extract_json_from_response,
    extract_threats_from_markdown,
)
from agentictm.rag.tools import ALL_RAG_TOOLS
from agentictm.state import ThreatModelState
from agentictm.logging import with_logging_context

from agentictm.agents.synthesis.classification import (
    _to_str,
    _estimate_expected_threat_count,
    _normalize_stride_category,
    _infer_stride_category,
    _clamp_dread,
    _asymmetric_dread,
    _compute_priority,
    _find_threats_array,
    _assign_category_ids,
    _DEFAULT_MITIGATIONS,
    _DEFAULT_CONTROLS,
)
from agentictm.agents.synthesis.deduplication import _deduplicate_threats
from agentictm.agents.synthesis.quality_gates import (
    _extract_threats_from_reports,
    _apply_quality_gates,
    _filter_irrelevant_threats,
    _recover_unmatched_baseline,
)
from agentictm.agents.synthesis.enrichment import _enrich_weak_threats

if TYPE_CHECKING:
    from agentictm.config import AgenticTMConfig
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

_MANDATORY_KEYWORD_MIN_HITS = 2


def _audit_mandatory_coverage(
    threats: list[dict],
    mandatory_patterns: list[dict],
) -> list[dict]:
    """Check that each mandatory pattern is covered by at least one threat.

    For any uncovered pattern, generate a stub threat so the gap is visible in
    the final report.  Returns generated stubs only (caller extends the list).
    """
    if not mandatory_patterns:
        return []

    stubs: list[dict] = []
    for pat in mandatory_patterns:
        keywords = [kw.lower() for kw in pat.get("keywords", [])]
        if not keywords:
            continue

        covered = False
        for t in threats:
            text = (
                (t.get("description") or "") + " " + (t.get("component") or "")
            ).lower()
            hits = sum(1 for kw in keywords if kw in text)
            if hits >= _MANDATORY_KEYWORD_MIN_HITS:
                covered = True
                break

        if not covered:
            stride = pat.get("stride_category", "I")
            scores = _asymmetric_dread(6, stride, pat["description"])
            total = sum(scores.values())
            stubs.append({
                "id": "",
                "component": "",
                "description": pat["description"],
                "methodology": "MandatoryPattern",
                "stride_category": stride,
                "attack_path": "",
                "damage": scores["damage"],
                "reproducibility": scores["reproducibility"],
                "exploitability": scores["exploitability"],
                "affected_users": scores["affected_users"],
                "discoverability": scores["discoverability"],
                "dread_total": total,
                "priority": _compute_priority(total),
                "mitigation": _DEFAULT_MITIGATIONS.get(stride, ""),
                "control_reference": _DEFAULT_CONTROLS.get(stride, ""),
                "effort": "Medium",
                "observations": f"[Auto-generated: mandatory pattern {pat['pattern_id']} uncovered]",
                "status": "Open",
                "evidence_sources": [
                    {"source_type": "architecture", "source_name": pat["name"],
                     "excerpt": pat["description"]},
                ],
                "confidence_score": 0.6,
                "justification": None,
            })
            logger.warning(
                "[MandatoryAudit] Pattern %s (%s) not covered by any threat — stub generated",
                pat["pattern_id"], pat["name"],
            )

    if stubs:
        logger.info("[MandatoryAudit] Generated %d stub threats for uncovered mandatory patterns", len(stubs))
    else:
        logger.info("[MandatoryAudit] All %d mandatory patterns covered", len(mandatory_patterns))
    return stubs


SYSTEM_PROMPT = """\
You are the Lead Security Architect and final threat model synthesizer.

Your task is the most critical in the pipeline: combine the best findings
from every methodology and the adversarial debate to produce THE final,
comprehensive, prioritized threat model.

You receive:
- Structured threat lists from 4-5 analysts (STRIDE, PASTA, Attack Tree, MAESTRO, AI Threat)
- Full debate between Red Team and Blue Team
- Previous threat model context (via RAG tools)
- System components, trust boundaries, data flows

Your job:

1. CONSOLIDATE: Merge threats from all methodologies.
   - STRIDE: per-element coverage (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation)
   - PASTA: business risk and attack scenarios
   - Attack Tree: structured attack paths and leaf actions
   - MAESTRO/AI Threat: AI/ML-specific risks (if applicable)
   Deduplicate but preserve each methodology's unique angle.

   PRIORITIZE COVERAGE OVER COUNT. Generate enough distinct, well-defined threats
   to cover the real attack surface of this specific system. Use the system's
   components, trust boundaries, data flows, and active categories to decide
   whether the result looks complete. If coverage feels thin after deduplication,
   revisit the methodology outputs — there are often overlooked vectors such as:
   denial of service, supply chain, configuration drift, insider threat,
   credential stuffing, session hijacking, crypto weaknesses, logging gaps,
   trust boundary violations, API abuse, object-level authorization failures,
   cross-tenant data access, state-machine bypasses, and asynchronous workflow races.

2. INCORPORATE DEBATE: The Red Team may have found threats the analysts
   missed. The Blue Team may have correctly dismissed some with good arguments.
   Use the debate to calibrate risk scores. Red Team arguments that went
   unchallenged or poorly rebutted should become HIGH priority threats.

3. ASSIGN DREAD SCORES for every threat (each dimension 1-10):
   - damage (1-10): how bad is it if the attack succeeds?
   - reproducibility (1-10): how easy to repeat the attack?
   - exploitability (1-10): how easy to launch? (10 = trivial script, 1 = nation-state)
   - affected_users (1-10): breadth of impact (10 = all users, 1 = single admin)
   - discoverability (1-10): how easy to find the vulnerability?
   - dread_total = sum of all five (5-50)

   CRITICAL SCORING RULES:
   - Each dimension MUST have a DIFFERENT value. Real vulnerabilities have varying
     impact across dimensions. Uniform scores like 8/8/8/8/8 are NEVER acceptable.
   - Be REALISTIC for THIS specific system, not generic worst-case.
   - Internal systems behind VPNs/firewalls → lower Exploitability (3-5)
   - Systems without PII → lower Affected Users (2-4)
   - Well-known attack patterns → higher Discoverability (7-9)
   - Complex multi-step attacks → lower Reproducibility (2-4)
   - Example of GOOD asymmetric scoring: D=7, R=5, E=4, A=8, D=3 (total=27, High)

4. PRIORITIZE based on average score (total / 5):
   - avg >= 9.0 (total 45-50): Critical — fix immediately (RARE: max 2-3 per model)
   - avg >= 7.0 (total 35-44): High — fix this sprint
   - avg >= 4.0 (total 20-34): Medium — plan for next cycle
   - avg < 4.0  (total 5-19):  Low — monitor, accept risk
   Most threats in a well-scoped system should be Medium or High.
   Having more than 2-3 Critical threats is unusual and suggests score inflation.

5. PROPOSE MITIGATIONS that are concrete and specific to this system.
   Map to NIST 800-53, OWASP ASVS, or CIS controls when possible.
   Each mitigation MUST be actionable (e.g., "Implement WAF rule X" not just "Use WAF").

6. WRITE VERBOSE, DEVELOPER-FRIENDLY DESCRIPTIONS:
   Your threat model will be read by software developers with LIMITED security knowledge.
   Each threat's "description" field MUST be 4–6 sentences that:
   a) Explain WHAT the vulnerability or weakness is (define any security term used)
   b) Describe EXACTLY HOW an attacker would exploit it step by step against THIS specific system
   c) Name the specific components, endpoints, or data stores involved
   d) State WHAT concrete harm results (accounts compromised, data exfiltrated, service disrupted, etc.)
   e) Optionally: mention what a developer can look for in code to spot this issue
   AVOID vague one-liners like "Injection attack via user input". BE SPECIFIC.

   GOOD EXAMPLE:
   "The /api/search endpoint in the Express server passes the user-supplied 'query'
   parameter directly to a MongoDB $where clause without sanitization. An attacker
   crafts a query like \\"this.password.match(/^a.*/)\\\" to enumerate password characters
   through boolean-based extraction (NoSQL Injection, CWE-943). By sending thousands
   of requests iterating through each character, the attacker can reconstruct all user
   passwords in plain text within hours. Every user account in the system would be
   fully compromised, including admin accounts, with no authentication required."

   Each "attack_path" MUST be a numbered sequence of concrete attacker steps:
   '1. Attacker identifies unauthenticated /admin endpoint via Shodan -> 2. Sends
    POST request with default credentials admin:admin -> 3. Receives admin session
    token -> 4. Exports full user database via /admin/export endpoint'

   Each "mitigation" MUST include what the developer should actually change in code
   or infrastructure (e.g., 'Replace string concatenation in UserRepository.findById()
   with parameterized query: db.query("SELECT * FROM users WHERE id = ?", [userId])').

CRITICAL OUTPUT RULE: Your entire response MUST be a single valid JSON object.
Do NOT include any markdown, explanations, reasoning, or code fences outside the JSON.
Start your response with { and end with }.

Required JSON schema:
{
    "threats": [
        {
            "id": "TM-001",
            "component": "affected component name",
            "description": "4-6 sentence developer-friendly description: what the vulnerability is, how an attacker exploits it step-by-step against THIS system, which components/endpoints are involved, and what concrete harm results",
            "methodology_sources": ["STRIDE", "PASTA"],
            "stride_category": "S or T or R or I or D or E",
            "attack_path": "1. Attacker does X against component Y -> 2. System responds with Z -> 3. Attacker achieves goal W (be specific to this system)",
            "damage": 8,
            "reproducibility": 7,
            "exploitability": 6,
            "affected_users": 9,
            "discoverability": 5,
            "dread_total": 35,
            "priority": "High",
            "mitigation": "specific, actionable mitigation with concrete implementation steps",
            "control_reference": "NIST AC-3, OWASP ASVS V3.5",
            "effort": "Low|Medium|High",
            "observations": "additional notes, cross-references to other threats",
            "status": "Open",
            "evidence_sources": [
                {"source_type": "rag|llm_knowledge|contextual|architecture", "source_name": "e.g. OWASP Top 10 2021 - A03", "excerpt": "relevant quote or reference supporting this threat"}
            ],
            "confidence_score": 0.85
        }
    ],
    "executive_summary": "executive summary of the complete threat model (3-5 sentences)",
    "methodology_contributions": {
        "STRIDE": "key contributions and unique findings",
        "PASTA": "key contributions and unique findings",
        "ATTACK_TREE": "key contributions and unique findings",
        "MAESTRO": "key contributions if applicable"
    }
}

EVIDENCE RULES:
- Every threat MUST have at least 1 evidence_source explaining WHERE the finding comes from.
- source_type "rag" = from retrieved documentation or knowledge base.
- source_type "llm_knowledge" = from your training data (cite the standard or framework).
- source_type "contextual" = derived from the specific system architecture or debate.
- source_type "architecture" = from the analyzed architecture diagram/description.
- The excerpt should be a concise reference (max 2 sentences) supporting the threat.

CONFIDENCE RULES:
- confidence_score is 0.0 to 1.0, reflecting how certain you are this threat is real and applicable.
- 0.9-1.0: Confirmed by multiple methodologies + architecture evidence
- 0.7-0.89: Supported by at least one methodology with clear architectural basis
- 0.5-0.69: Plausible but based on general knowledge, architecture details ambiguous
- 0.3-0.49: Speculative, included for completeness
- Below 0.3: Do not include — insufficient evidence

REMEMBER: The threats array MUST contain at least 15 items. This is non-negotiable.
- If the architecture explicitly states there are no AI/LLM/agentic components, do NOT include prompt injection or other AI-only threats.
"""


def _build_human_prompt(state: ThreatModelState) -> str:
    seen_methodologies: set[str] = set()
    unique_reports: list[dict] = []
    for r in state.get("methodology_reports", []):
        methodology = r.get("methodology", "Unknown")
        if methodology in seen_methodologies:
            continue
        seen_methodologies.add(methodology)
        unique_reports.append(r)

    structured_threats_text = ""
    total_raw = 0
    for r in unique_reports:
        methodology = r.get("methodology", "Unknown")
        threats_raw = r.get("threats_raw", [])
        total_raw += len(threats_raw)
        if threats_raw:
            structured_threats_text += (
                f"\n### {methodology} — {len(threats_raw)} structured threats:\n"
                + json.dumps(threats_raw[:100], indent=2, ensure_ascii=False)[:40000]
                + "\n"
            )
        else:
            report = r.get("report", "")
            if len(report) > 15000:
                report = report[:15000] + "\n... [truncated]"
            structured_threats_text += (
                f"\n### {methodology} — narrative report:\n{report}\n"
            )

    debate_text = ""
    debate_verdicts_text = ""
    for entry in state.get("debate_history", []):
        side = entry.get("side", "?") if isinstance(entry, dict) else getattr(entry, "side", "?")
        rnd = entry.get("round", "?") if isinstance(entry, dict) else getattr(entry, "round", "?")
        arg = entry.get("argument", "") if isinstance(entry, dict) else getattr(entry, "argument", "")
        assessments = entry.get("threat_assessments", []) if isinstance(entry, dict) else getattr(entry, "threat_assessments", [])
        tag = "[RED TEAM]" if side == "red" else "[BLUE TEAM]"
        if len(arg) > 10000:
            arg = arg[:10000] + "\n... [truncated]"
        debate_text += f"\n{tag} (Round {rnd}):\n{arg}\n"

        if assessments:
            for ta in assessments[:30]:
                threat_id = ta.get("threat_id", "?")
                if side == "red":
                    action = ta.get("action", "?")
                    reasoning = ta.get("reasoning", "")[:600]
                    proposed = ta.get("proposed_dread_total", "")
                    debate_verdicts_text += f"  RED {action}: {threat_id}"
                    if proposed:
                        debate_verdicts_text += f" (proposed DREAD: {proposed})"
                    debate_verdicts_text += f" — {reasoning}\n"
                else:
                    verdict = ta.get("verdict", "?")
                    mitigation = ta.get("mitigation", "")
                    control = ta.get("control_reference", "")
                    debate_verdicts_text += f"  BLUE {verdict}: {threat_id}"
                    if mitigation:
                        debate_verdicts_text += f" -> Mitigation: {mitigation[:400]}"
                    if control:
                        debate_verdicts_text += f" [{control}]"
                    debate_verdicts_text += "\n"

    from agentictm.agents.prompt_budget import PromptBudget

    pb = PromptBudget(system_prompt_chars=len(SYSTEM_PROMPT))

    components_json = json.dumps(state.get("components", []), indent=2, ensure_ascii=False)
    trust_json = json.dumps(state.get("trust_boundaries", []), indent=2, ensure_ascii=False)
    flows_json = json.dumps(state.get("data_flows", [])[:60], indent=2, ensure_ascii=False)

    fitted = pb.fit(
        sections={
            "system_description": state.get("system_description", "Not available"),
            "components": components_json,
            "trust_boundaries": trust_json,
            "data_flows": flows_json,
            "threat_surface_summary": state.get("threat_surface_summary", "No architecture review briefing available."),
            "methodology": structured_threats_text,
            "debate": debate_text + "\n" + debate_verdicts_text,
            "raw_input": state.get("previous_tm_context", "No previous threat models available."),
        },
        priorities=[
            "system_description", "components", "data_flows",
            "trust_boundaries", "threat_surface_summary", "methodology", "debate", "raw_input",
        ],
    )

    return f"""\
## System Under Analysis
{fitted["system_description"]}

## Components ({len(state.get('components', []))} total)
{fitted["components"]}

## Trust Boundaries
{fitted["trust_boundaries"]}

## Data Flows
{fitted["data_flows"]}

## Architecture Review Briefing
{fitted["threat_surface_summary"]}

## Analyst Findings ({total_raw} raw threats total across all methodologies)
{fitted["methodology"]}

## Red Team vs Blue Team Debate
{fitted["debate"] if fitted["debate"].strip() else "No debate occurred."}

## Previous Threat Model Context (RAG)
{fitted["raw_input"]}

Synthesize all of the above into the final threat model. Use RAG tools to
cross-reference with previous threat models for consistency. Blend your own synthesis
expertise with RAG findings for a comprehensive result. Return ONLY valid JSON — no other text.
"""


def run_threat_synthesizer(
    state: ThreatModelState,
    llm: BaseChatModel,
    config: AgenticTMConfig | None = None,
) -> dict:
    """LangGraph node: Threat Synthesizer (Deep Thinker).

    HYBRID STRATEGY:
    1. Always extract the BASELINE of ALL raw threats from analyst reports.
    2. Try LLM synthesis for enrichment/deduplication.
    3. If LLM produces enough threats (>= MIN_THRESHOLD), use LLM output.
    4. Otherwise, use baseline threats (all analyst raw threats), which
       guarantees we NEVER lose threats.
    5. Apply category-based IDs (WEB-01, INF-02, etc.) to ALL threats.

    Lee: methodology_reports, debate_history, components, trust_boundaries
    Escribe: threats_final
    """
    logger.info("[Synthesizer] Combining analysis from all methodologies...")

    # ── Step 1: Build the baseline (ALL raw threats from all analysts) ──
    baseline_threats = _extract_threats_from_reports(state)
    baseline_count = len(baseline_threats)
    logger.info(
        "[Synthesizer] BASELINE: %d threats extracted from analyst reports",
        baseline_count,
    )

    _self_reflect = False
    if config and config.pipeline.self_reflection_enabled and config.pipeline.self_reflection_rounds > 0:
        _self_reflect = True
        logger.info("[Synthesizer] Self-reflection ENABLED (%d rounds)", config.pipeline.self_reflection_rounds)

    _target = config.pipeline.target_threats if config else 20
    _min_t = config.pipeline.min_threats if config else 8
    _max_t = config.pipeline.max_threats if config else 40
    coverage_plan = _estimate_expected_threat_count(state, config)
    expected_threat_count = int(coverage_plan["expected_count"])
    coverage_dimensions = coverage_plan["dimensions"]
    logger.info(
        "[Synthesizer] Complexity-based coverage target: ~%d threats (%s) | baseline=%d | configured_target=%d",
        expected_threat_count,
        ", ".join(str(part) for part in coverage_dimensions),
        baseline_count,
        _target,
    )

    effective_system_prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        "Coverage guidance for this run:\n"
        f"- Estimated complete coverage for this system: about {expected_threat_count} threats.\n"
        f"- Complexity signals: {', '.join(str(part) for part in coverage_dimensions)}.\n"
        "- This is guidance, not a hard minimum. Prefer attack-surface completeness over hitting a fixed count.\n"
    )

    _output_lang = config.pipeline.output_language if config else "en"

    human_prompt = _build_human_prompt(state)
    logger.info(
        "[Synthesizer] Prompt sizes: system=%d chars | human=%.1f KB | target=%d threats",
        len(effective_system_prompt), len(human_prompt) / 1024, _target,
    )
    t0 = time.perf_counter()

    # ── Step 2: Try LLM synthesis ──
    SYNTH_TIMEOUT = 900  # 15 minutes hard cap

    def _invoke_synth():
        return invoke_agent(
            llm, effective_system_prompt, human_prompt,
            tools=ALL_RAG_TOOLS,
            max_tool_rounds=3,
            agent_name="Synthesizer",
            enable_self_reflection=_self_reflect,
            pre_invoke_tools=True,
        )

    llm_threats: list[dict] = []
    executive_summary = ""
    raw_response = ""

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(with_logging_context(_invoke_synth))
            response = future.result(timeout=SYNTH_TIMEOUT)
            raw_response = response
    except concurrent.futures.TimeoutError:
        elapsed = time.perf_counter() - t0
        logger.error(
            "[Synthesizer] TIMEOUT after %.0fs (limit=%ds). Using baseline threats.",
            elapsed, SYNTH_TIMEOUT,
        )
        response = ""
    except Exception as exc:
        logger.error("[Synthesizer] LLM invocation failed: %s. Using baseline threats.", exc)
        response = ""

    elapsed_llm = time.perf_counter() - t0
    if response:
        logger.info("[Synthesizer] LLM invoke completed in %.1fs | response=%d chars", elapsed_llm, len(response))
    else:
        logger.warning("[Synthesizer] No LLM response, will use baseline threats.")

    # ── Step 3: Parse LLM response ──
    if response:
        parsed = extract_json_from_response(response)

        threat_items: list[dict] = []
        if isinstance(parsed, dict):
            executive_summary = parsed.get("executive_summary", "")
            threat_items = _find_threats_array(parsed)
        elif isinstance(parsed, list):
            logger.info(
                "[Synthesizer] Got list instead of dict from JSON parse "
                "(likely truncated output). Treating as threats array (%d items).",
                len(parsed),
            )
            threat_items = [t for t in parsed if isinstance(t, dict)]
        elif parsed is None:
            logger.warning(
                "[Synthesizer] extract_json_from_response returned None. "
                "Response first 500 chars: %s",
                response[:500],
            )

        if threat_items:
            logger.info("[Synthesizer] Found %d threat items from LLM JSON", len(threat_items))
        else:
            logger.warning(
                "[Synthesizer] 0 threat items after JSON parse. "
                "parsed type=%s, keys=%s",
                type(parsed).__name__,
                list(parsed.keys())[:20] if isinstance(parsed, dict) else "N/A",
            )

        for t in threat_items:
            desc = _to_str(
                t.get("description") or t.get("title") or t.get("threat")
                or t.get("descripcion") or t.get("vulnerability")
                or t.get("scenario") or t.get("attack_scenario") or ""
            )
            if not desc:
                continue

            try:
                d = _clamp_dread(int(t.get("damage", 5) or 5))
                r = _clamp_dread(int(t.get("reproducibility", 5) or 5))
                e = _clamp_dread(int(t.get("exploitability", 5) or 5))
                a = _clamp_dread(int(t.get("affected_users", 5) or 5))
                disc = _clamp_dread(int(t.get("discoverability", 5) or 5))
            except (TypeError, ValueError):
                d = r = e = a = disc = 5

            if d + r + e + a + disc == 0:
                stride_cat_inferred = _normalize_stride_category(_to_str(t.get("stride_category", ""))) or _infer_stride_category(t)
                scores = _asymmetric_dread(5, stride_cat_inferred, desc)
                d, r, e, a, disc = scores["damage"], scores["reproducibility"], scores["exploitability"], scores["affected_users"], scores["discoverability"]

            if len({d, r, e, a, disc}) == 1 and d > 3:
                stride_for_fix = _normalize_stride_category(_to_str(t.get("stride_category", ""))) or _infer_stride_category(t)
                scores = _asymmetric_dread(d, stride_for_fix, desc)
                d = scores["damage"]
                r = scores["reproducibility"]
                e = scores["exploitability"]
                a = scores["affected_users"]
                disc = scores["discoverability"]
                logger.info(
                    "[Synthesizer] Corrected uniform DREAD %d -> %d/%d/%d/%d/%d for '%s'",
                    d, d, r, e, a, disc, _to_str(t.get("component", ""))[:40],
                )

            computed_total = d + r + e + a + disc
            reported_total = t.get("dread_total", computed_total)
            try:
                final_total = computed_total if computed_total > 0 else int(reported_total or 0)
            except (TypeError, ValueError):
                final_total = 25

            priority = _compute_priority(final_total)

            llm_threats.append({
                "id": _to_str(t.get("id", "")),
                "component": _to_str(t.get("component") or t.get("componente") or ""),
                "description": desc,
                "methodology": ", ".join(t.get("methodology_sources", [])) if isinstance(t.get("methodology_sources"), list) else _to_str(t.get("methodology", "")),
                "stride_category": _normalize_stride_category(_to_str(t.get("stride_category", ""))) or _infer_stride_category(t),
                "attack_path": _to_str(t.get("attack_path") or t.get("ruta_ataque") or ""),
                "damage": d,
                "reproducibility": r,
                "exploitability": e,
                "affected_users": a,
                "discoverability": disc,
                "dread_total": final_total,
                "priority": priority,
                "mitigation": _to_str(t.get("mitigation") or t.get("mitigacion") or "") or _DEFAULT_MITIGATIONS.get(_infer_stride_category(t), ""),
                "control_reference": _to_str(t.get("control_reference") or t.get("referencia_control") or "") or _DEFAULT_CONTROLS.get(_infer_stride_category(t), ""),
                "effort": _to_str(t.get("effort", "Medium")),
                "observations": _to_str(t.get("observations") or t.get("observaciones") or ""),
                "status": _to_str(t.get("status", "Open")),
                "evidence_sources": t.get("evidence_sources", []),
                "confidence_score": float(t.get("confidence_score", 0.5) or 0.5),
                "justification": None,
            })

        if not llm_threats:
            logger.warning(
                "[Synthesizer] JSON extraction yielded 0 threats. "
                "Trying markdown extraction. Response first 1000 chars: %s",
                response[:1000],
            )
            llm_threats = extract_threats_from_markdown(response, "Synthesizer")

    # ── Step 3b: Retry with condensed prompt if too few threats ──
    if len(llm_threats) < expected_threat_count and baseline_count > 0:
        remaining_budget = SYNTH_TIMEOUT - (time.perf_counter() - t0)
        if remaining_budget > 120:
            logger.warning(
                "[Synthesizer] Coverage looks thin: %d threats vs complexity target ~%d. Retrying with condensed prompt (%.0fs budget left).",
                len(llm_threats), expected_threat_count, remaining_budget,
            )
            condensed_threats = sorted(
                baseline_threats, key=lambda t: t.get("dread_total", 0), reverse=True,
            )[:20]
            condensed_prompt = (
                f"System: {state.get('system_description', '')[:3000]}\n\n"
                f"Top {len(condensed_threats)} baseline threats (consolidate and expand):\n"
                + json.dumps(condensed_threats, indent=1, ensure_ascii=False)[:12000]
            )
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    retry_future = executor.submit(
                        with_logging_context(lambda: invoke_agent(
                            llm, effective_system_prompt, condensed_prompt,
                            agent_name="Synthesizer-Retry",
                        ))
                    )
                    retry_resp = retry_future.result(timeout=int(remaining_budget * 0.8))
                retry_parsed = extract_json_from_response(retry_resp)
                retry_items: list[dict] = []
                if isinstance(retry_parsed, dict):
                    retry_items = _find_threats_array(retry_parsed)
                    executive_summary = retry_parsed.get("executive_summary", "") or executive_summary
                elif isinstance(retry_parsed, list):
                    retry_items = [t for t in retry_parsed if isinstance(t, dict)]
                if retry_items:
                    logger.info("[Synthesizer-Retry] Got %d threats from retry", len(retry_items))
                    for t in retry_items:
                        desc = _to_str(t.get("description") or t.get("title") or "")
                        if not desc:
                            continue
                        try:
                            d = _clamp_dread(int(t.get("damage", 5) or 5))
                            r = _clamp_dread(int(t.get("reproducibility", 5) or 5))
                            e = _clamp_dread(int(t.get("exploitability", 5) or 5))
                            a = _clamp_dread(int(t.get("affected_users", 5) or 5))
                            disc = _clamp_dread(int(t.get("discoverability", 5) or 5))
                        except (TypeError, ValueError):
                            d = r = e = a = disc = 5
                        if len({d, r, e, a, disc}) == 1 and d > 3:
                            _s = _normalize_stride_category(_to_str(t.get("stride_category", ""))) or _infer_stride_category(t)
                            _sc = _asymmetric_dread(d, _s, desc)
                            d, r, e, a, disc = _sc["damage"], _sc["reproducibility"], _sc["exploitability"], _sc["affected_users"], _sc["discoverability"]
                        total = d + r + e + a + disc
                        llm_threats.append({
                            "id": _to_str(t.get("id", "")),
                            "component": _to_str(t.get("component") or t.get("componente") or ""),
                            "description": desc,
                            "methodology": _to_str(t.get("methodology", "Synthesizer-Retry")),
                            "stride_category": _normalize_stride_category(_to_str(t.get("stride_category", ""))) or _infer_stride_category(t),
                            "attack_path": _to_str(t.get("attack_path", "")),
                            "damage": d, "reproducibility": r, "exploitability": e,
                            "affected_users": a, "discoverability": disc,
                            "dread_total": total, "priority": _compute_priority(total),
                            "mitigation": _to_str(t.get("mitigation", "")),
                            "control_reference": _to_str(t.get("control_reference", "")),
                            "effort": _to_str(t.get("effort", "Medium")),
                            "observations": "", "status": "Open",
                            "evidence_sources": [], "confidence_score": 0.6,
                            "justification": None,
                        })
                    logger.info(
                        "[Synthesizer-Retry] Total threats after retry: %d",
                        len(llm_threats),
                    )
            except Exception as retry_exc:
                logger.warning("[Synthesizer-Retry] Retry failed: %s", retry_exc)

    llm_coverage_ratio = (len(llm_threats) / expected_threat_count) if expected_threat_count > 0 else 1.0
    logger.info(
        "[Synthesizer] LLM produced %d threats (~%.0f%% of complexity target %d, baseline=%d)",
        len(llm_threats), llm_coverage_ratio * 100, expected_threat_count, baseline_count,
    )

    # ── Step 4: Decide which threats to use (hybrid merge) ──
    _used_baseline = False
    if llm_threats:
        threats_final = llm_threats
        logger.info(
            "[Synthesizer] Using LLM output: %d threats",
            len(threats_final),
        )
        recovered = _recover_unmatched_baseline(baseline_threats, llm_threats)
        if recovered:
            threats_final.extend(recovered)
            logger.info(
                "[Synthesizer] After reconciliation: %d threats (%d LLM + %d recovered)",
                len(threats_final), len(llm_threats), len(recovered),
            )
    else:
        _used_baseline = True
        threats_final = list(baseline_threats)
        logger.warning(
            "[Synthesizer] LLM produced 0 threats. Using ALL %d baseline threats.",
            len(threats_final),
        )

    # ── Step 5: Quality gates (filter, deduplicate, fill gaps, cap count) ──
    _max_t = config.pipeline.max_threats if config else 30
    _known_comps = [
        c.get("name", "") if isinstance(c, dict) else str(c)
        for c in state.get("components", [])
    ]
    threats_final = _filter_irrelevant_threats(threats_final, state)
    threats_final = _deduplicate_threats(threats_final)
    threats_final = _apply_quality_gates(threats_final, max_threats=_max_t, known_components=_known_comps)

    # ── Step 5b: Mandatory coverage audit ──
    _mandatory = state.get("mandatory_threat_patterns", [])
    if _mandatory:
        _stubs = _audit_mandatory_coverage(threats_final, _mandatory)
        if _stubs:
            threats_final.extend(_stubs)
            threats_final = _deduplicate_threats(threats_final)

    # ── Step 5c: Enrich weak threats (expand short descriptions, fill mitigations) ──
    _enrich_llm = llm
    try:
        from agentictm.llm import create_llm
        if config:
            _enrich_llm = create_llm(config.quick_thinker, format_override="json")
            logger.info("[Synthesizer] Using quick_json model (%s) for enrichment", config.quick_thinker.model)
    except Exception as _e:
        logger.debug("[Synthesizer] Could not create quick_json for enrichment: %s", _e)
    _sys_desc = state.get("system_description", "")
    threats_final = _enrich_weak_threats(threats_final, _enrich_llm, system_description=_sys_desc, known_components=_known_comps)

    # ── Step 6: Assign category-based IDs (WEB-01, INF-02, etc.) ──
    threats_final.sort(key=lambda t: t.get("dread_total", 0), reverse=True)
    threats_final = _assign_category_ids(threats_final)

    final_coverage_ratio = (len(threats_final) / expected_threat_count) if expected_threat_count > 0 else 1.0
    coverage_warning = final_coverage_ratio < 0.75
    validation_result = {
        "coverage_expected": expected_threat_count,
        "coverage_actual": len(threats_final),
        "coverage_ratio": round(final_coverage_ratio, 2),
        "coverage_warning": coverage_warning,
        "complexity_dimensions": coverage_dimensions,
        "used_baseline_fallback": _used_baseline,
    }
    if coverage_warning:
        warning_text = (
            f"Quality warning: final threat coverage looks low for this system's complexity "
            f"({len(threats_final)} threats vs about {expected_threat_count} expected from "
            f"{', '.join(str(part) for part in coverage_dimensions)})."
        )
        logger.warning("[Synthesizer] %s", warning_text)
        executive_summary = f"{executive_summary}\n\n{warning_text}".strip() if executive_summary else warning_text

    total_elapsed = time.perf_counter() - t0
    logger.info(
        "[Synthesizer] COMPLETED in %.1fs (LLM=%.1fs): %d final prioritized threats "
        "(baseline=%d, llm_raw=%d)",
        total_elapsed, elapsed_llm, len(threats_final),
        baseline_count, len(llm_threats),
    )

    for t in threats_final[:30]:
        logger.info(
            "  -> %s [%s] %s | DREAD=%s | %s",
            t.get("id", "?"), t.get("stride_category", "?"),
            (t.get("component", "") or "?")[:40],
            t.get("dread_total", 0),
            t.get("priority", "?"),
        )

    return {
        "threats_final": threats_final,
        "executive_summary": executive_summary or
            "Threat model synthesized from multiple methodology analyses.",
        "report_output": raw_response,
        "validation_result": validation_result,
    }
