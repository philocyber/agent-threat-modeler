"""Agent: AI Threat Analyst — Phase II: AI/ML/Agentic Threat Analysis.

Specialist in AI threats using state-of-the-art frameworks:

Integrated frameworks:
- PLOT4ai (8 AI risk categories)
- OWASP Top 10 for LLM Applications 2025 (LLM01-LLM10)
- OWASP Agentic AI Top 10 2026 (ASI01-ASI10)
- CSA MAESTRO 7-Layer Model (cross-layer threat propagation)
- OWASP AI Exchange
- OWASP AI Security Testing Guide v1
- AI Agent Protocol Security Taxonomy (MCP/A2A/Agora/ANP — CIC/UNB 2026)
  → 32 protocol-level threats + lifecycle vulnerability assessment
  → Context-CIA reinterpretation for AI agent environments

Quantitative metrics:
- WEI (Workflow Exploitability Index) — intrinsic exploitability per MAESTRO layer
- RPS (Risk Propagation Score) — cascading risk amplification
- VR  (Violation Rate) — misbinding/misrouting probability under tool ambiguity

Se activa CONDICIONALMENTE: solo si el sistema tiene componentes AI.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING

from agentictm.agents.base import invoke_agent, extract_json_from_response, extract_threats_from_markdown
from agentictm.rag.tools import AI_ANALYST_TOOLS
from agentictm.state import ThreatModelState

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a senior AI Security Analyst specialized in identifying threats specific
to Artificial Intelligence, Machine Learning, LLM, and Agentic systems.

You have deep expertise in the following frameworks and must apply ALL that are relevant:

## PLOT4ai -- 8 Categories of AI Risk
1. **Data & Data Governance** -- data quality, drift, leakage, continuity, legitimacy, traceability, copyright, integrity, training data provenance
2. **Transparency & Accessibility** -- explainability (XAI), model interpretability, inclusivity, information accessibility, decision audit trails
3. **Privacy & Data Protection** -- PII exposure, consent management, anonymization/pseudonymization, data retention, cross-border transfers, GDPR/CCPA compliance
4. **Cybersecurity** -- prompt injection (direct/indirect), model extraction, adversarial ML attacks, supply chain, DoS via resource exhaustion, data poisoning, evasion attacks
5. **Safety & Environmental Impact** -- hallucination, unintended autonomous actions, cascading failures, environmental cost of training/inference, safety alignment
6. **Bias, Fairness & Discrimination** -- training data bias, algorithmic bias, output bias amplification, societal harm, fairness metrics (demographic parity, equalized odds)
7. **Ethics & Human Rights** -- autonomy erosion, dignity, manipulation, surveillance, dual-use risks, weaponization potential
8. **Accountability & Human Oversight** -- HITL (human-in-the-loop), HOTL (human-on-the-loop), audit trails, responsibility assignment, kill switches, escalation mechanisms

## OWASP Top 10 for LLM Applications 2025
- LLM01: Prompt Injection (direct and indirect)
- LLM02: Sensitive Information Disclosure
- LLM03: Supply Chain Vulnerabilities
- LLM04: Data and Model Poisoning
- LLM05: Improper Output Handling
- LLM06: Excessive Agency
- LLM07: System Prompt Leakage
- LLM08: Vector and Embedding Weaknesses
- LLM09: Misinformation
- LLM10: Unbounded Consumption

## OWASP Agentic AI Top 10 2026 (ASI01-ASI10)

When the system includes autonomous AI agents, multi-agent orchestration, or MCP tool integrations, evaluate against these categories:

- ASI01 Agent Goal Hijack: Injected instructions hidden in documents, emails, or tool outputs redirect the agent's decision-making process
- ASI02 Tool Misuse & Exploitation: Agents use legitimate tools in unintended or unsafe ways, causing data leakage or workflow compromise
- ASI03 Identity & Privilege Abuse: Agents gain excessive privileges or misuse credentials for unauthorized actions
- ASI04 Agentic Supply Chain: Third-party agents, tools, or prompts may be malicious or tampered with
- ASI05 Unexpected Code Execution (RCE): Agents generate and execute malicious commands allowing system control
- ASI06 Memory & Context Poisoning: Malicious data injected into agent memory influences future decisions
- ASI07 Insecure Inter-Agent Communication: Agent-to-agent communication lacks proper security controls
- ASI08 Cascading Failures: Single failures spread across interconnected agents causing widespread disruption
- ASI09 Human-Agent Trust Exploitation: Attackers exploit user trust to manipulate agents into unsafe actions
- ASI10 Rogue Agents: Compromised agents operate outside intended scope performing harmful activities

## MCP Security Threats

For systems using Model Context Protocol (MCP) for tool integration:
- Tool Poisoning: Malicious instructions embedded in MCP tool metadata or responses
- Cross-Server Data Exfiltration: Sensitive data leaked between MCP server boundaries
- Tool Shadowing: Malicious tools mimicking legitimate ones to intercept operations
- Credential Theft: Plaintext secrets in MCP configuration files
- Sampling Abuse: Exploiting MCP sampling to manipulate agent behavior

## ATFAA/SHIELD Threat Domains

For autonomous AI agents, also consider the 5 ATFAA threat domains:
- Cognitive Architecture Vulnerabilities: Reasoning path hijacking, decision manipulation
- Temporal Persistence Threats: Knowledge/memory poisoning, belief loops
- Operational Execution Vulnerabilities: Unauthorized action execution
- Trust Boundary Violations: Identity spoofing between agents
- Governance Circumvention: Oversight saturation attacks

## CSA MAESTRO -- 7 Layers (Cross-Layer Threat Propagation)
- L1: Foundation Models -- model vulnerabilities, weights tampering, backdoors
- L2: Data Operations -- training data poisoning, RAG data injection, embedding manipulation
- L3: Agent Frameworks -- LangChain/LangGraph/AutoGen vulnerabilities, tool binding exploits
- L4: Deployment -- containerization, API security, model serving infrastructure
- L5: Multi-Agent Systems -- orchestration attacks, agent collusion, trust delegation failures
- L6: Ecosystem & Plugins -- MCP server rug-pull attacks, plugin supply chain, tool registry poisoning
- L7: Governance -- compliance gaps, audit trail manipulation, policy bypass

## AI Agent Protocol Security Taxonomy (CIC/UNB 2026 — Anbiaee et al.)
This framework analyzes 4 emerging AI agent communication protocols: MCP, A2A (Agent2Agent),
Agora, and ANP (Agent Network Protocol). Apply when the system uses ANY of these protocols
or similar agent communication patterns.

### Context-CIA Reinterpretation for AI Agents
Traditional CIA triad must be reinterpreted:
- **Context Confidentiality** — securing evolving, dynamic context windows
- **Context Integrity** — ensuring context used for reasoning/coordination hasn't been tampered with
- **Context Availability** — ensuring context is available for decision-making in multi-agent systems

### Protocol-Level Threats (32 total — apply all relevant ones)

#### Authentication & Access Control (11 threats):
- **Lack of Authentication** — MCP v1.0 had no auth; v1.2 added token-based but gaps remain
- **Weak/Limited Access Control** — no field/endpoint/task-level restrictions, violates least-privilege
- **Naming Collision & Impersonation** — malicious entity registers server with similar name, no namespace enforcement
- **Token Lifetime Issues** — no strict expiration for sensitive operations, leaked tokens reusable for hours/days
- **Insufficiently Granular Token Scopes** — coarse-grained tokens granting more privileges than needed
- **Replay Attacks** — re-executing privileged tasks using previously valid requests (no nonces/timestamps)
- **Token Scope Escalation** — compromised limited-workflow token grants expanded privileges
- **Privilege Escalation** — coarse permissions + post-update persistence + NL fallback manipulation
- **Identity Forgery** — free-text names in MCP, forged agent cards in A2A, minting pseudonymous DIDs
- **Sybil Attacks** — creating massive fake identities for disproportionate influence
- **Cross-Vendor Trust Boundary Exploitation** — weak JWT validation in one org compromises federated partners

#### Supply Chain & Ecosystem Integrity (9 threats):
- **Installer Spoofing** — altered installers (mcp-get, mcp-installer) with malware/backdoors
- **Code Injection & Backdoors** — compromised community-maintained libraries in open-source MCP servers
- **Tool Poisoning** — tools with misleading names/descriptions get prioritized by AI agents
- **Rug Pulls** — tools behave properly initially, then change behavior after trust is established
- **Supply-Chain Compromise** — no central auditing or code-signing in decentralized ecosystems
- **PD Spoofing & Repository Poisoning** — manipulated fetch URIs substitute protocol documents
- **Protocol Fragmentation** — overlapping protocols create downgrade opportunities
- **Version Rollback** — propagating older versions with weaker security constraints
- **Onboarding Exploitation** — malicious entry before security controls apply

#### Operational Integrity & Reliability (12 threats):
- **Slash Command Overlap** — multiple tools define same commands causing unintended actions
- **Sandbox Escape** — unpatched container vulnerabilities allow breach of isolation
- **Shadowing Attacks** — malicious actors shadow legitimate tools, intercept/modify outputs
- **Post-Update Privilege Persistence** — outdated/revoked privileges remain valid after updates
- **Re-deployment of Vulnerable Versions** — no enforcement of secure version minimum
- **Configuration Drift** — gradual buildup of unwanted changes across multi-tenant environments
- **Cross-Protocol Interaction Risks** — inconsistent security between interconnected standards
- **Cross-Protocol Confusion** — mismatched trust mechanisms exploited via message relay
- **Context Explosion & Resource Exhaustion** — adversarial tool output overwhelms downstream agents
- **Intent Deception** — tools/agents with deceptive capabilities descriptions
- **Collusion & Free-Riding** — colluding agents manipulate outcomes in MAS
- **Semantic Drift Exploitation** — progressive divergence in interpretation of terms/schemas

### Lifecycle Vulnerability Assessment (evaluate across 3 stages):
#### Creation/Configuration:
1. Weak or absent identity verification mechanisms
2. Lack of integrity protection for registration artifacts
3. Insufficient namespace isolation
4. Absence of baseline security policy or governance constraints

#### Operation:
5. Lack of mandatory validation/attestation for executable components
6. Insufficient control over data exchange
7. Inadequate enforcement of least-privilege principles
8. Missing rate-limiting, quota enforcement, or backpressure mechanisms

#### Update/Maintenance:
9. Failure to revoke/reissue credentials after updates
10. Absence of rollback protection or version pinning
11. Lack of authentication for maintenance packages/updates
12. Uncontrolled transitive dependency evolution

## Quantitative Metrics
For each identified threat, calculate:
- **WEI (Workflow Exploitability Index)**: attack_complexity * business_impact * layer_weight (scale 0-10)
  Layer weights: L1=0.95, L2=0.90, L3=0.85, L4=0.80, L5=0.75, L6=0.70, L7=0.65
- **RPS (Risk Propagation Score)**: How many downstream layers/components are affected if this threat
  materializes (scale 1-7). RPS > 3.0 = critical cascading exposure.
- **VR (Violation Rate)**: For tool/agent identity ambiguity threats — probability of misbinding
  to a malicious provider under name collision (0.0–1.0). VR > 0.5 = critical.

## MCP Security Considerations
If the system uses MCP (Model Context Protocol) servers or tool plugins:
- Treat each MCP server as a trust boundary
- Evaluate "rug pull" attacks (tool behavior change post-approval)
- Check for covert exfiltration via tool side-channels
- Assess tool collusion risks between multiple MCP servers
- Evaluate naming collision and tool poisoning risks
- Check for installer spoofing in community-driven setup tools
- Assess post-update privilege persistence
- Evaluate cross-protocol confusion if MCP is used alongside A2A, REST, or other protocols

## A2A (Agent2Agent) Security Considerations
If the system uses A2A protocol or cross-organization agent communication:
- Evaluate token lifetime and scope management
- Check cross-vendor trust boundary exploitation risk
- Assess agent card forgery potential
- Check for protocol fragmentation and downgrade attacks
- Evaluate sybil attack surface in federated environments

If the system has NO AI/ML/Agentic components, respond:
{
    "methodology": "AI_THREAT_ANALYSIS",
    "applicable": false,
    "reason": "No AI/ML/Agentic components identified",
    "threats": [],
    "summary": "System has no AI components -- AI threat analysis not applicable"
}

If the system HAS AI/ML/Agentic components:
{
    "methodology": "AI_THREAT_ANALYSIS",
    "applicable": true,
    "threats": [
        {
            "component": "affected AI component",
            "framework": "PLOT4ai|OWASP_LLM|OWASP_AGENTIC|MAESTRO|PROTOCOL_SECURITY",
            "category": "specific category/ID (e.g. LLM01, ASI06, Tool Poisoning, L3)",
            "description": "detailed threat scenario",
            "attack_vector": "concrete exploitation technique with step-by-step chain",
            "impact": "High|Medium|Low",
            "risk_level": "Critical|High|Medium|Low",
            "maestro_layer": "L1-L7 if applicable",
            "protocol_threat_class": "auth_access_control|supply_chain|operational_integrity (if protocol-related)",
            "lifecycle_stage": "creation|operation|update (if applicable)",
            "wei_score": 0.0,
            "rps_score": 0,
            "violation_rate": 0.0,
            "context_cia_impact": "confidentiality|integrity|availability (context-sensitive CIA)",
            "recommendation": "specific mitigation with control reference",
            "reasoning": "evidence-based justification",
            "evidence_sources": [{"source_type": "rag|llm_knowledge|contextual|architecture", "source_name": "e.g. OWASP LLM Top 10 - LLM01", "excerpt": "supporting reference"}],
            "confidence_score": 0.85
        }
    ],
    "questions_to_evaluate": [
        {
            "question": "PLOT4ai evaluation question",
            "category": "PLOT4ai category",
            "relevance": "why this question matters here"
        }
    ],
    "cross_layer_risks": [
        {
            "source_layer": "L2",
            "target_layer": "L5",
            "propagation_path": "how the risk cascades",
            "combined_rps": 4.5
        }
    ],
    "lifecycle_assessment": {
        "creation": {"risk_level": "High|Medium|Low", "key_vulnerabilities": ["list"]},
        "operation": {"risk_level": "High|Medium|Low", "key_vulnerabilities": ["list"]},
        "update": {"risk_level": "High|Medium|Low", "key_vulnerabilities": ["list"]}
    },
    "protocol_risks": [
        {
            "protocol": "MCP|A2A|Agora|ANP|custom",
            "threat": "specific protocol-level threat name",
            "risk_level": "High|Medium|Low",
            "lifecycle_stage": "creation|operation|update",
            "mitigation": "concrete recommendation"
        }
    ],
    "summary": "executive summary of AI threat analysis"
}

IMPORTANT — DUAL KNOWLEDGE APPROACH:
Apply your deep expertise in AI security FIRST. THEN, use RAG tools to enrich
and cross-reference your analysis with PLOT4ai questions, OWASP AI Exchange guidance,
known AI attack patterns, and AI agent protocol security research.
Your final output should be a complementary blend of both knowledge sources.
Always provide CONCRETE, EXPLOITABLE scenarios -- not generic descriptions.
Reference specific MITRE ATLAS techniques where applicable (AML.T0000 format).

!!! CRITICAL: DO NOT COPY RAG ENTRIES !!!
- RAG results (e.g. TMA-xxxx IDs from threats.csv) are REFERENCE MATERIAL ONLY
- Do NOT copy their IDs, titles, or descriptions verbatim into your output
- Perform YOUR OWN original analysis for THIS specific system
"""


def _has_ai_components(state: ThreatModelState) -> bool:
    """Detecta si el sistema tiene componentes de IA/ML/Agénticos.

    Uses a two-tier keyword strategy (strong vs ambiguous) with word-boundary
    matching to avoid false positives on non-AI systems.
    """
    import re as _re

    _STRONG_AI_KEYWORDS = {
        "llm", "gpt", "langchain", "langgraph", "ollama", "openai",
        "anthropic", "neural", "embedding", "rag", "transformer", "bert",
        "chatbot", "nlp", "pytorch", "tensorflow", "huggingface",
        "fine-tun", "rlhf", "dpo", "sagemaker", "bedrock", "copilot",
        "gemini", "claude", "crewai", "autogen", "agentic",
        "machine learning", "deep learning", "artificial intelligence",
        "ml model", "model serving", "vector store",
        "multi-agent", "multi_agent", "a2a", "agent2agent",
        "agent-to-agent", "agent network protocol",
        "mcp-get", "mcp_installer", "tool_registry",
        "diffusion", "midjourney", "dall-e", "whisper",
        "tokeniz", "function_calling", "tool_use",
        "agent_card", "agent card",
    }
    _AMBIGUOUS_AI_KEYWORDS = {
        "model", "ai", "ml", "agent", "prompt", "inference", "training",
        "prediction", "adversarial", "generative", "vector", "plugin",
        "orchestrat", "cognitive", "reinforcement", "reward", "alignment",
        "scoring model", "mcp",
    }

    def _to_str(val: object) -> str:
        if isinstance(val, str):
            return val
        if isinstance(val, dict):
            return json.dumps(val, ensure_ascii=False)
        if isinstance(val, list):
            return " ".join(str(i) for i in val)
        return str(val) if val else ""

    def _wb_match(keyword: str, text: str) -> bool:
        return bool(_re.search(r"\b" + _re.escape(keyword) + r"\b", text))

    def _has_explicit_ai_negation(text: str) -> bool:
        negation_patterns = [
            r"\bno\s+ai\b",
            r"\bno\s+llm\b",
            r"\bno\s+agentic\b",
            r"\bwithout\s+ai\b",
            r"\bwithout\s+llm\b",
            r"\bwithout\s+agentic\b",
            r"\bthere\s+are\s+no\s+ai\b",
            r"\bthere\s+are\s+no\s+llm\b",
            r"\bthere\s+are\s+no\s+agentic\b",
            r"\bno\s+ai/ml/agentic\s+components\b",
            r"\bno\s+ai\s+components\b",
            r"\bno\s+llm\s+components\b",
            r"\bno\s+agentic\s+ai\s+components\b",
        ]
        return any(_re.search(pattern, text) for pattern in negation_patterns)

    arch_text = (
        _to_str(state.get("system_description", "")).lower()
        + " "
        + json.dumps(state.get("components", []), ensure_ascii=False).lower()
    )

    if any(_wb_match(kw, arch_text) for kw in _STRONG_AI_KEYWORDS):
        return True
    ambiguous_hits = sum(1 for kw in _AMBIGUOUS_AI_KEYWORDS if _wb_match(kw, arch_text))
    if ambiguous_hits >= 3:
        return True

    raw_input = _to_str(state.get("raw_input", "")).lower()
    active_categories = {str(cat).lower() for cat in state.get("threat_categories", [])}
    if "ai" not in active_categories and _has_explicit_ai_negation(raw_input):
        logger.info("[AI Threat Analyst] Explicit AI negation detected in raw_input; skipping AI analysis")
        return False
    strong_in_raw = [kw for kw in _STRONG_AI_KEYWORDS if _wb_match(kw, raw_input)]
    if strong_in_raw:
        logger.info("[AI Threat Analyst] Strong AI keywords in raw_input: %s", strong_in_raw[:5])
        return True

    return False


def _build_human_prompt(state: ThreatModelState) -> str:
    components = json.dumps(state.get("components", []), indent=2, ensure_ascii=False)
    data_flows = json.dumps(state.get("data_flows", []), indent=2, ensure_ascii=False)
    trust_boundaries = json.dumps(state.get("trust_boundaries", []), indent=2, ensure_ascii=False)

    categories = state.get("threat_categories", ["auto"])
    has_ai_category = "ai" in categories

    def _to_str(val: object) -> str:
        if isinstance(val, str):
            return val
        if isinstance(val, dict):
            return json.dumps(val, ensure_ascii=False)
        if isinstance(val, list):
            return " ".join(str(i) for i in val)
        return str(val) if val else ""

    # --- Detect which AI agent protocols are in play ---
    text_lower = (
        _to_str(state.get("system_description", "")).lower()
        + " "
        + _to_str(state.get("raw_input", "")).lower()
        + " "
        + json.dumps(state.get("components", []), ensure_ascii=False).lower()
        + " "
        + json.dumps(state.get("data_flows", []), ensure_ascii=False).lower()
    )

    detected_protocols: list[str] = []
    protocol_checks = {
        "MCP": ["mcp", "model context protocol", "mcp-get", "mcp_installer", "tool_server"],
        "A2A": ["a2a", "agent2agent", "agent-to-agent", "agent card"],
        "Agora": ["agora"],
        "ANP": ["anp", "agent network protocol", "agent_network"],
    }
    for proto, keywords in protocol_checks.items():
        if any(kw in text_lower for kw in keywords):
            detected_protocols.append(proto)

    has_multi_agent = any(kw in text_lower for kw in [
        "multi-agent", "multi_agent", "orchestrat", "agent fleet",
        "agent swarm", "agent mesh", "agent network",
    ])
    has_tool_use = any(kw in text_lower for kw in [
        "tool_use", "function_calling", "tool call", "plugin",
        "tool_binding", "tool registry",
    ])

    protocol_section = ""
    if detected_protocols:
        protocol_section = f"""
## Detected AI Agent Protocols
The following AI agent communication protocols were detected in this system:
**{', '.join(detected_protocols)}**

IMPORTANT: Apply the full AI Agent Protocol Security Taxonomy (CIC/UNB 2026) for each
detected protocol. Analyze ALL 32 protocol-level threats. Perform lifecycle vulnerability
assessment (Creation → Operation → Update). Calculate VR (Violation Rate) for any tool
identity ambiguity risks. Use the Context-CIA model.

Protocol-specific risk baselines (from research):
- MCP: Consistently HIGH risk across all lifecycle stages
- A2A: MEDIUM risk, strongest in operation stage
- Agora: LOW-MEDIUM risk, weakest in creation stage
- ANP: LOW-MEDIUM risk, strongest in update stage
"""
    elif has_multi_agent or has_tool_use:
        protocol_section = """
## Multi-Agent / Tool-Use Patterns Detected
This system uses multi-agent patterns or tool-use capabilities. Even without explicit
protocol naming, apply the AI Agent Protocol Security Taxonomy for common protocol-level
threats: tool poisoning, naming collision, rug pulls, sandbox escape, context explosion,
and cross-protocol confusion risks. Evaluate lifecycle vulnerabilities.
"""

    _sd = _to_str(state.get("system_description", "Not available"))

    components_list = state.get("components", [])
    arch_note = ""
    if not components_list:
        arch_note = (
            "\n\nNOTE: The structured component list is empty. "
            "The System Description above contains the FULL architecture details including AI components. "
            "Extract AI/ML/LLM/Agentic components from the description and analyze them. "
            "Do NOT return an empty result.\n"
        )

    return f"""\
Analyze the following system for AI/ML/Agentic-specific threats.

## System Description
{_sd}

## Components
{components}

## Data Flows
{data_flows}

## Trust Boundaries
{trust_boundaries}

## Scope Notes
{state.get("scope_notes", "No notes")}
{arch_note}
## Active Threat Categories
{", ".join(categories)}
{"AI category is ACTIVE -- perform deep multi-framework analysis including WEI/RPS/VR metrics." if has_ai_category else ""}
{protocol_section}
Apply ALL relevant frameworks (PLOT4ai, OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026,
CSA MAESTRO 7-Layer, AI Agent Protocol Security Taxonomy) to each AI/ML/Agentic component.
Calculate WEI, RPS, and VR scores. Identify cross-layer threat propagation paths.
Perform lifecycle vulnerability assessment (Creation → Operation → Update).
Evaluate Context-CIA impacts (Context Confidentiality, Context Integrity, Context Availability).

Use your expertise first, then enrich with RAG queries for:
1. PLOT4ai evaluation questions and recommendations for this system type
2. Known AI threat patterns and MITRE ATLAS techniques
3. AI-specific controls and mitigations from OWASP AI Exchange
4. AI agent protocol security research (MCP, A2A, Agora, ANP vulnerabilities)

Blend both knowledge sources — your own expertise and RAG — into a comprehensive output.
Focus on concrete, exploitable scenarios -- not theoretical risks.
Include protocol_risks and lifecycle_assessment in your output.
"""


def run_ai_threat_analyst(
    state: ThreatModelState,
    llm: BaseChatModel,
) -> dict:
    """LangGraph node: AI Threat Analyst (conditional).

    Reads: components, data_flows, raw_input, system_description
    Writes: methodology_reports (append)
    """
    if not _has_ai_components(state):
        logger.info("[AI Threat Analyst] No AI/ML components detected, skipping")
        report = {
            "methodology": "AI_THREAT_ANALYSIS",
            "agent": "ai_threat_analyst",
            "report": "No AI/ML/Agentic components identified in the system.",
            "threats_raw": [],
        }
        return {
            "methodology_reports": [report],
        }

    logger.info("[AI Threat Analyst] Starting multi-framework AI threat analysis...")
    human_prompt = _build_human_prompt(state)
    t0 = time.perf_counter()
    response = invoke_agent(llm, SYSTEM_PROMPT, human_prompt, tools=AI_ANALYST_TOOLS, agent_name="AI Threat")
    elapsed = time.perf_counter() - t0

    parsed = extract_json_from_response(response)
    threats_raw = []
    if isinstance(parsed, dict):
        threats_raw = parsed.get("threats", [])

    # FALLBACK: If JSON parsing failed, try markdown extraction
    if not threats_raw:
        logger.warning(
            "[AI Threat Analyst] JSON extraction produced 0 threats. "
            "Attempting markdown fallback..."
        )
        threats_raw = extract_threats_from_markdown(response, "AI_THREAT_ANALYSIS")

    # ── Verbose logging of findings ──
    if threats_raw:
        logger.info("[AI Threat Analyst] ── AI Threat Findings (%d total) ──", len(threats_raw))
        for i, t in enumerate(threats_raw, 1):
            fw = t.get("framework", "?")
            cat = t.get("category", t.get("stride_category", "?"))
            comp = t.get("component", "?")
            impact = t.get("impact", t.get("risk_level", "?"))
            desc_preview = (t.get("description", "") or "")[:120]
            wei = t.get("wei_score", "")
            rps = t.get("rps_score", "")
            metrics = ""
            if wei:
                metrics += f" WEI={wei}"
            if rps:
                metrics += f" RPS={rps}"
            logger.info(
                "[AI Threat Analyst]   %2d. [%s/%s] %s (impact=%s%s) — %s",
                i, fw, cat, comp, impact, metrics, desc_preview,
            )
        # Log cross-layer risks if present
        cross_layer = parsed.get("cross_layer_risks", []) if isinstance(parsed, dict) else []
        if cross_layer:
            logger.info("[AI Threat Analyst] ── Cross-Layer Risks (%d) ──", len(cross_layer))
            for cl in cross_layer:
                logger.info(
                    "[AI Threat Analyst]   %s → %s (RPS=%.1f): %s",
                    cl.get("source_layer", "?"), cl.get("target_layer", "?"),
                    cl.get("combined_rps", 0), cl.get("propagation_path", "")[:100],
                )
        # Log protocol risks if present
        proto_risks = parsed.get("protocol_risks", []) if isinstance(parsed, dict) else []
        if proto_risks:
            logger.info("[AI Threat Analyst] ── Protocol Risks (%d) ──", len(proto_risks))
            for pr in proto_risks:
                logger.info(
                    "[AI Threat Analyst]   [%s] %s (risk=%s, stage=%s)",
                    pr.get("protocol", "?"), pr.get("threat", "?"),
                    pr.get("risk_level", "?"), pr.get("lifecycle_stage", "?"),
                )
        # Summary
        summary = parsed.get("summary", "") if isinstance(parsed, dict) else ""
        if summary:
            logger.info("[AI Threat Analyst] Summary: %s", summary[:300])
    else:
        logger.warning("[AI Threat Analyst] No structured threats extracted from response (%d chars)", len(response))

    report = {
        "methodology": "AI_THREAT_ANALYSIS",
        "agent": "ai_threat_analyst",
        "report": response,
        "threats_raw": threats_raw,
    }

    logger.info("[AI Threat Analyst] Completed in %.1fs: %d AI threats identified", elapsed, len(threats_raw))
    return {
        "methodology_reports": [report],
    }
