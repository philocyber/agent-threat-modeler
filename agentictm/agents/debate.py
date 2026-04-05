"""Agentes: Red Team + Blue Team Debaters — Fase III: Debate Adversarial Estructurado.

"Analysis-First Structured Debate":
  Round 1: Each team builds an independent threat assessment grounded in ALL
           prior methodology findings (STRIDE, PASTA, Attack Trees, MAESTRO,
           AI Threat Analysis, raw user input, architecture model).
  Round 2+: Focused rebuttal — each team responds to the other's specific
           per-threat verdicts with evidence-grounded arguments.

Both teams produce:
  - Prose argument (for the human-readable report)
  - Structured threat_assessments[] (for machine-readable downstream consumption
    by the Threat Synthesizer and DREAD Validator)
"""

from __future__ import annotations

import json
import logging
import time

from agentictm.rag.tools import DEBATE_TOOLS
from typing import TYPE_CHECKING

from agentictm.agents.base import invoke_agent, extract_json_from_response
from agentictm.state import ThreatModelState, DebateEntry

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

_THREAT_LIST_KEYS = [
    "threat_assessments",
    "identified_threats",
    "threats",
    "threat_analysis",
    "threat_model",
    "assessments",
    "findings",
    "red_team_assessment",
    "blue_team_assessment",
    "analysis",
    "results",
    "vulnerabilities",
]


def _extract_debate_threats(response: str, team: str, round_num: int) -> list:
    """Extract threat assessments from debate response with flexible key matching."""
    parsed = extract_json_from_response(response)
    if parsed is None:
        logger.info("[%s] Round %d: no JSON parsed from response", team, round_num)
        return []

    if isinstance(parsed, list):
        valid = [item for item in parsed if isinstance(item, dict)]
        if valid:
            logger.info("[%s] Round %d: %d structured assessments extracted (top-level list)", team, round_num, len(valid))
            return valid
        logger.info("[%s] Round %d: parsed list has no dict items", team, round_num)
        return []

    _THREAT_ITEM_KEYS = {"id", "title", "description", "threat", "severity",
                         "likelihood", "impact", "mitigation", "action", "verdict"}

    def _looks_like_threats(lst):
        """Heuristic: a list of threat dicts should have threat-like keys."""
        if not lst or not isinstance(lst[0], dict):
            return False
        sample_keys = set(lst[0].keys())
        return bool(sample_keys & _THREAT_ITEM_KEYS)

    def _find_threat_list(obj, depth=0, path=""):
        """Recursively search for a list of threat dicts up to 4 levels deep."""
        if depth > 4:
            return None, ""
        if isinstance(obj, list) and obj and isinstance(obj[0], dict) and _looks_like_threats(obj):
            return obj, path
        if isinstance(obj, dict):
            for key in _THREAT_LIST_KEYS:
                val = obj.get(key)
                if val is not None:
                    result, rpath = _find_threat_list(val, depth + 1, f"{path}.{key}" if path else key)
                    if result is not None:
                        return result, rpath
            for key, val in obj.items():
                if key not in _THREAT_LIST_KEYS and isinstance(val, (dict, list)):
                    result, rpath = _find_threat_list(val, depth + 1, f"{path}.{key}" if path else key)
                    if result is not None:
                        return result, rpath
        return None, ""

    if isinstance(parsed, dict):
        found, keypath = _find_threat_list(parsed)
        if found:
            logger.info("[%s] Round %d: %d structured assessments extracted (path='%s')", team, round_num, len(found), keypath)
            return found

    logger.info("[%s] Round %d: 0 structured assessments extracted (no matching key found in: %s)",
                team, round_num, list(parsed.keys()) if isinstance(parsed, dict) else type(parsed).__name__)
    return []


# ────────────────────────────────────────────────────────────────────
# Shared context builder -- gives BOTH teams full pipeline state
# ────────────────────────────────────────────────────────────────────

def _build_full_context(state: ThreatModelState) -> str:
    """Build the shared context block that both Red and Blue teams receive.

    Includes: user input, parsed architecture, ALL methodology reports with
    their raw threats, and the attack tree.
    """
    # ── 1. User input ──
    raw_input = state.get("raw_input", "")
    system_desc = state.get("system_description", "Not available")

    # ── 2. Architecture ──
    components = state.get("components", [])
    data_flows = state.get("data_flows", [])
    trust_boundaries = state.get("trust_boundaries", [])

    comp_text = ""
    for c in components:
        if isinstance(c, dict):
            comp_text += f"  - {c.get('name', '?')} [{c.get('type', '')}]"
            desc = c.get("description", "")
            if desc:
                comp_text += f": {desc}"
            comp_text += "\n"
        else:
            comp_text += f"  - {c}\n"

    flow_text = ""
    for f in data_flows[:60]:
        if isinstance(f, dict):
            flow_text += f"  - {f.get('source', '?')} -> {f.get('destination', '?')}"
            proto = f.get("protocol", "")
            if proto:
                flow_text += f" [{proto}]"
            data = f.get("data", "")
            if data:
                flow_text += f": {data}"
            flow_text += "\n"
        else:
            flow_text += f"  - {f}\n"

    boundary_text = ""
    for b in trust_boundaries:
        if isinstance(b, dict):
            boundary_text += f"  - {b.get('name', '?')}"
            desc = b.get("description", "")
            if desc:
                boundary_text += f": {desc}"
            inside = b.get("inside", [])
            if inside:
                boundary_text += f" [contains: {', '.join(str(i) for i in inside)}]"
            boundary_text += "\n"
        else:
            boundary_text += f"  - {b}\n"

    # ── 3. All methodology reports with their specific threats ──
    methodology_reports = state.get("methodology_reports", [])
    reports_block = ""
    attack_tree_block = ""
    for r in methodology_reports:
        methodology = r.get("methodology", "Unknown")
        agent_name = r.get("agent", "")
        report = r.get("report", "")
        threats_raw = r.get("threats_raw", [])

        # Separate attack trees into their own section
        if "ATTACK_TREE" in methodology.upper():
            attack_tree_block += f"\n### {methodology}\n{report[:8000]}\n"
            if threats_raw:
                attack_tree_block += f"\n**Attack tree threats ({len(threats_raw)}):**\n"
                for tr in threats_raw[:25]:
                    at_id = tr.get("id", "")
                    at_comp = tr.get("component", "")
                    at_desc = tr.get("description", "")
                    at_stride = tr.get("stride_category", "")
                    attack_tree_block += f"  - {at_id} [{at_stride}] {at_comp}: {at_desc}\n"
            continue

        # Regular methodology report
        reports_block += f"\n---\n### {methodology} (agent: {agent_name})\n"
        if len(report) > 8000:
            report = report[:8000] + "\n... [truncated]"
        reports_block += f"{report}\n"

        if threats_raw:
            reports_block += f"\n**Specific threats identified ({len(threats_raw)}):**\n"
            for tr in threats_raw[:25]:
                t_id = tr.get("id", "")
                t_comp = tr.get("component", "")
                t_stride = tr.get("stride_category", "")
                t_desc = tr.get("description", "")
                t_prio = tr.get("priority", "")
                t_attack = tr.get("attack_path", "")
                line = f"  - **{t_id}** [{t_stride}] {t_comp}: {t_desc}"
                if t_prio:
                    line += f" (priority: {t_prio})"
                if t_attack:
                    line += f"\n    Attack path: {t_attack[:600]}"
                reports_block += line + "\n"

    from agentictm.agents.prompt_budget import PromptBudget
    pb = PromptBudget(system_prompt_chars=2000)

    fitted = pb.fit(
        sections={
            "system_description": system_desc,
            "components": comp_text or "  (none)",
            "data_flows": flow_text or "  (none)",
            "trust_boundaries": boundary_text or "  (none)",
            "methodology": reports_block or "(no methodology reports)",
            "attack_trees": attack_tree_block or "(no attack trees)",
            "raw_input": raw_input or "(no raw input)",
        },
        priorities=[
            "system_description", "components", "data_flows",
            "trust_boundaries", "methodology", "attack_trees", "raw_input",
        ],
    )

    return f"""\
## 1. User's Original Input
{fitted["raw_input"]}

## 2. Parsed System Description
{fitted["system_description"]}

## 3. Architecture

### Components ({len(components)})
{fitted["components"]}

### Data Flows ({len(data_flows)})
{fitted["data_flows"]}

### Trust Boundaries ({len(trust_boundaries)})
{fitted["trust_boundaries"]}

## 4. Methodology Analysis Reports
{fitted["methodology"]}

## 5. Attack Trees
{fitted["attack_trees"]}
"""


def _build_debate_history_text(state: ThreatModelState) -> str:
    """Build the debate history text including structured assessments."""
    debate_history = state.get("debate_history", [])
    if not debate_history:
        return ""

    history_text = ""
    for entry in debate_history:
        side = entry.get("side", "?") if isinstance(entry, dict) else getattr(entry, "side", "?")
        rnd = entry.get("round", "?") if isinstance(entry, dict) else getattr(entry, "round", "?")
        arg = entry.get("argument", "") if isinstance(entry, dict) else getattr(entry, "argument", "")
        assessments = entry.get("threat_assessments", []) if isinstance(entry, dict) else getattr(entry, "threat_assessments", [])

        tag = "[RED TEAM]" if side == "red" else "[BLUE TEAM]"
        history_text += f"\n{tag} (Round {rnd}):\n{arg[:8000]}\n"

        if assessments:
            history_text += f"\n**Structured Assessments ({len(assessments)}):**\n"
            for ta in assessments[:30]:
                if not isinstance(ta, dict):
                    history_text += f"  - {str(ta)[:200]}\n"
                    continue
                threat_id = ta.get("threat_id", "?")
                if side == "red":
                    action = ta.get("action", "?")
                    reasoning = ta.get("reasoning", "")[:400]
                    history_text += f"  - {threat_id}: {action} -- {reasoning}\n"
                else:
                    verdict = ta.get("verdict", "?")
                    reasoning = ta.get("reasoning", ta.get("mitigation", ""))[:400]
                    history_text += f"  - {threat_id}: {verdict} -- {reasoning}\n"

    return history_text


# ────────────────────────────────────────────────────────────────────
# RED TEAM
# ────────────────────────────────────────────────────────────────────

RED_TEAM_SYSTEM_PROMPT = """\
You are an experienced Red Teamer / Penetration Tester / Adversary Simulator.

CRITICAL: You MUST write your ENTIRE response in English. Never use Hebrew, Arabic,
Chinese, or any non-Latin script. All prose, analysis, and JSON must be in English.

Your mission: analyze the SPECIFIC system under review and argue that its threats
are SEVERE, that assumed defenses are INSUFFICIENT, and that undiscovered attack
vectors exist.

## How you operate:
1. **Study every methodology report** — STRIDE, PASTA, Attack Tree, MAESTRO, AI Threat.
   You have access to each report AND the specific threats they identified (with IDs).
2. **Reference threats by ID** (e.g. TM-003, TM-014). This grounds your arguments.
3. **Combine findings across methodologies** into multi-step attack chains.
4. **Challenge security assumptions** — "Is TLS configured with mutual auth?",
   "Who validates the JWT signing key?", "Is the S3 bucket public?"
5. **Propose APT scenarios** that chain 2+ threats into a realistic kill chain.
6. **Identify single points of failure** that would cause cascading damage.

## IMPORTANT RULES:
- Do NOT invent unsupported threats. Ground arguments in analyst evidence.
- Always reference specific threat IDs when discussing existing threats.
- When proposing NEW threats not covered by any methodology, explain the attack chain
  step-by-step and mark them as "NEW-Rx" (e.g. NEW-R1, NEW-R2).

## OUTPUT FORMAT:
Write your prose argument first, then include a MANDATORY JSON block at the end
enclosed in triple backticks:

```json
{
  "threat_assessments": [
    {
      "threat_id": "TM-003",
      "action": "ESCALATE",
      "reasoning": "SQL injection combined with privilege escalation via...",
      "proposed_dread_total": 38,
      "attack_chain": "Step 1: exploit TM-003 → Step 2: lateral movement via..."
    },
    {
      "threat_id": "NEW-R1",
      "action": "NEW_THREAT",
      "description": "Cross-service SSRF chain through API Gateway...",
      "attack_chain": "Attacker sends crafted request to...",
      "proposed_dread_total": 35
    }
  ]
}
```

Valid actions: ESCALATE (raise severity), CONFIRM (agree with current severity), NEW_THREAT

## CONVERGENCE SIGNAL (MANDATORY — place as the very LAST line of your response,
AFTER the JSON block):
- If you found NEW attack vectors not discussed in previous rounds: `[NUEVOS VECTORES]`
- If all major vectors have been covered and you have nothing substantially new: `[CONVERGENCIA]`
"""


def _build_red_prompt(state: ThreatModelState) -> str:
    """Build the Red Team human prompt with full pipeline context."""
    current_round = state.get("debate_round", 1)
    context = _build_full_context(state)
    history = _build_debate_history_text(state)

    if current_round == 1:
        instruction = """\
This is Round 1 — your INITIAL assessment. You have NOT seen Blue Team arguments yet.

Study ALL methodology reports and their specific threats (with IDs). Then:
1. Identify the 8-12 most critical threats and argue why they are severe
2. Propose 2-4 NEW multi-methodology attack chains not already identified
3. Challenge specific security assumptions in the architecture
4. Produce your structured threat_assessments JSON block"""
    else:
        instruction = f"""\
This is Round {current_round}. Review Blue Team's verdicts and respond:
1. For threats Blue Team CONCEDED: acknowledge and propose additional severity
2. For DISPUTED threats: counter with specific evidence, CVEs, or attack paths
3. For MODERATED threats: argue why partial mitigation is insufficient
4. Propose any NEW attack chains discovered while reviewing Blue's arguments
5. Update your structured threat_assessments JSON block"""

    return f"""\
{context}

## Debate History
{history if history else "This is the first round — no history yet."}

---

## YOUR TASK (Red Team, Round {current_round})
{instruction}
"""


def run_red_team(
    state: ThreatModelState,
    llm: BaseChatModel,
) -> dict:
    """Nodo de LangGraph: Red Team Debater (structured assessment)."""
    current_round = state.get("debate_round", 1)
    logger.info("[Red Team] Round %d starting...", current_round)

    human_prompt = _build_red_prompt(state)
    t0 = time.perf_counter()
    response = invoke_agent(llm, RED_TEAM_SYSTEM_PROMPT, human_prompt, tools=DEBATE_TOOLS, agent_name="Red Team")
    elapsed = time.perf_counter() - t0

    logger.info("[Red Team] Round %d LLM response (%d chars):\n%s", current_round, len(response), response)

    threat_assessments = _extract_debate_threats(response, "Red Team", current_round)

    entry = DebateEntry(
        round=current_round,
        side="red",
        argument=response,
        threat_assessments=threat_assessments,
    )
    logger.info("[Red Team] Round %d completed in %.1fs | response=%d chars", current_round, elapsed, len(response))
    return {
        "debate_history": [entry],
    }


# ────────────────────────────────────────────────────────────────────
# BLUE TEAM
# ────────────────────────────────────────────────────────────────────

BLUE_TEAM_SYSTEM_PROMPT = """\
You are a senior Blue Teamer / Security Architect / Incident Response Lead.

CRITICAL: You MUST write your ENTIRE response in English. Never use Hebrew, Arabic,
Chinese, or any non-Latin script. All prose, analysis, and JSON must be in English.

Your mission: critically evaluate Red Team arguments against the SPECIFIC system
and provide HONEST, technically grounded verdicts on each threat.

## How you operate:
1. **Study the same methodology reports and architecture** the Red Team saw.
2. **Review Red Team's structured threat_assessments** — respond to EACH by ID.
3. For each Red Team threat, issue a verdict:
   - **CONCEDE** — valid threat, propose specific mitigation + control reference
   - **DISPUTE** — exaggerated or theoretical, explain why with evidence
   - **MODERATE** — partially valid, explain what mitigating factors exist and
     what additional controls are needed
4. **Identify existing controls** in the architecture that Red Team missed
   (e.g. WAF in front of API, VPC isolation, IAM policies).

## IMPORTANT RULES:
- Do NOT minimize everything. A good Blue Team acknowledges real weaknesses.
- When you CONCEDE, propose a CONCRETE mitigation (not "implement security best practices").
- Reference specific threat IDs from Red Team's assessments.
- If Red Team proposed NEW threats (NEW-R1, etc.), evaluate those too.

## OUTPUT FORMAT:
Write your prose rebuttal first, then include a MANDATORY JSON block at the end
enclosed in triple backticks:

```json
{
  "threat_assessments": [
    {
      "threat_id": "TM-003",
      "verdict": "CONCEDE",
      "reasoning": "Red Team correctly identified that the API lacks rate limiting...",
      "existing_controls": "API Gateway has basic auth but no rate limiting",
      "mitigation": "Implement API rate limiting at 100 req/min per client IP + WAF rules",
      "control_reference": "NIST AC-6, CIS Control 13.1"
    },
    {
      "threat_id": "NEW-R1",
      "verdict": "DISPUTE",
      "reasoning": "The SSRF scenario requires internal network access which is blocked by...",
      "existing_controls": "VPC security groups restrict internal traffic to port 443 only"
    },
    {
      "threat_id": "TM-007",
      "verdict": "MODERATE",
      "reasoning": "While XSS is possible, the CSP header limits impact...",
      "existing_controls": "Content-Security-Policy strict-dynamic",
      "mitigation": "Add nonce-based CSP + sanitize all user input at rendering",
      "control_reference": "OWASP ASVS V5.3"
    }
  ]
}
```

Valid verdicts: CONCEDE, DISPUTE, MODERATE
"""


def _build_blue_prompt(state: ThreatModelState) -> str:
    """Build the Blue Team human prompt with full pipeline context."""
    current_round = state.get("debate_round", 1)
    context = _build_full_context(state)
    history = _build_debate_history_text(state)

    if current_round == 1:
        instruction = """\
This is Round 1. Red Team has presented their initial assessment.

For EACH threat Red Team identified (referenced by ID):
1. Issue a verdict: CONCEDE / DISPUTE / MODERATE
2. Identify existing security controls in the architecture
3. For CONCEDE/MODERATE: propose specific, concrete mitigations with control references
4. For DISPUTE: explain technically why the threat is exaggerated
5. Produce your structured threat_assessments JSON block"""
    else:
        instruction = f"""\
This is Round {current_round}. Review Red Team's latest arguments and counter-arguments.

1. Address any NEW threats Red Team proposed this round
2. Update verdicts if Red Team provided compelling evidence
3. Highlight controls or mitigations Red Team continues to ignore
4. Update your structured threat_assessments JSON block"""

    return f"""\
{context}

## Debate History
{history}

---

## YOUR TASK (Blue Team, Round {current_round})
{instruction}
"""


def run_blue_team(
    state: ThreatModelState,
    llm: BaseChatModel,
) -> dict:
    """Nodo de LangGraph: Blue Team Debater (structured verdicts)."""
    current_round = state.get("debate_round", 1)
    logger.info("[Blue Team] Round %d starting...", current_round)

    human_prompt = _build_blue_prompt(state)
    t0 = time.perf_counter()
    response = invoke_agent(llm, BLUE_TEAM_SYSTEM_PROMPT, human_prompt, tools=DEBATE_TOOLS, agent_name="Blue Team")
    elapsed = time.perf_counter() - t0

    logger.info("[Blue Team] Round %d LLM response (%d chars):\n%s", current_round, len(response), response)

    threat_assessments = _extract_debate_threats(response, "Blue Team", current_round)

    entry = DebateEntry(
        round=current_round,
        side="blue",
        argument=response,
        threat_assessments=threat_assessments,
    )
    logger.info("[Blue Team] Round %d completed in %.1fs | response=%d chars", current_round, elapsed, len(response))
    return {
        "debate_history": [entry],
        "debate_round": current_round + 1,
    }
