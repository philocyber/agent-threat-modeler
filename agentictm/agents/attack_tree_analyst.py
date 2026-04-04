"""Agente: Attack Tree Analyst -- Fase II + Fase II.5.

Dual Attack Tree approach:
  1. attack_tree_initial: First pass from user input + architecture model only
  2. attack_tree_enriched: Second pass incorporating ALL prior agent outputs
     (STRIDE, PASTA, MAESTRO, AI Threats, Red/Blue debate) for a richer,
     more comprehensive attack tree with cross-methodology attack vectors.

The enriched version is the one shown to users -- it has more context,
more attack paths, and considers vectors identified by other methodologies.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING

import re as _re

from agentictm.agents.base import invoke_agent, extract_json_from_response, extract_threats_from_markdown
from agentictm.rag.tools import ANALYST_TOOLS
from agentictm.state import ThreatModelState

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mermaid leaf-node extraction fallback
# ---------------------------------------------------------------------------

def _extract_leaf_threats_from_mermaid(response: str) -> list[dict]:
    """Parse Mermaid attack tree diagrams from the LLM response and extract leaf nodes as threats.

    A leaf node is any node that appears as a target but never as a source in edges.
    This is the critical fallback when JSON parsing fails (truncation, etc.).

    Returns a list of threat dicts compatible with threats_raw format.
    """
    threats: list[dict] = []

    # Find all mermaid diagram blocks (```mermaid or graph TD/LR patterns)
    mermaid_blocks: list[str] = []

    # Pattern 1: ```mermaid ... ``` code blocks
    for m in _re.finditer(r'```(?:mermaid)?\s*\n(.*?)```', response, _re.DOTALL):
        block = m.group(1).strip()
        if 'graph' in block.lower() or '-->' in block:
            mermaid_blocks.append(block)

    # Pattern 2: Inline mermaid in JSON tree_mermaid fields (even if unclosed)
    for m in _re.finditer(r'"tree_mermaid"\s*:\s*"([^"]+)', response, _re.DOTALL):
        block = m.group(1).replace('\\n', '\n').strip()
        if '-->' in block:
            mermaid_blocks.append(block)

    # Pattern 2b: Raw graph tokens inside a generic JSON string
    if not mermaid_blocks:
        for m in _re.finditer(r'(?:graph|flowchart)\s+(?:TD|LR|TB|RL|BT).*?(?="|\Z)', response, _re.IGNORECASE | _re.DOTALL):
            block = m.group(0).replace('\\n', '\n').strip()
            if '-->' in block:
                mermaid_blocks.append(block)

    # Pattern 3: Raw graph TD sections outside code blocks
    if not mermaid_blocks:
        for m in _re.finditer(r'(graph\s+(?:TD|LR|TB|BT)\b.*?)(?=\n\n|\Z)', response, _re.DOTALL):
            block = m.group(1).strip()
            if '-->' in block:
                mermaid_blocks.append(block)

    if not mermaid_blocks:
        return threats

    seen_labels: set[str] = set()  # deduplicate across trees

    for tree_idx, block in enumerate(mermaid_blocks):
        # Extract node definitions: ID[label], ID([label]), ID((label)), etc.
        node_labels: dict[str, str] = {}
        for m in _re.finditer(r'(\w+)\s*[\[\(\{]+([^}\]\)]+)[\]\)\}]+', block):
            node_id = m.group(1).strip()
            label = m.group(2).strip()
            node_labels[node_id] = label

        # Extract edges: source --> target, source -->|label| target
        sources: set[str] = set()
        targets: set[str] = set()
        for m in _re.finditer(r'(\w+)\s*(?:-->|-.->|==>)', block):
            sources.add(m.group(1).strip())
        for m in _re.finditer(r'(?:-->|-.->|==>)\s*(?:\|[^|]*\|)?\s*(\w+)', block):
            targets.add(m.group(1).strip())

        # Leaf nodes: appear as targets but NOT as sources (terminal nodes)
        leaf_ids = targets - sources
        # Also include nodes that never appear in any edge (orphaned but defined)
        all_edge_nodes = sources | targets
        for nid in node_labels:
            if nid not in all_edge_nodes and nid not in leaf_ids:
                # Skip the root node (first defined node)
                continue

        # Try to find root goal from first node
        root_goal = ""
        for m in _re.finditer(r'(\w+)\s*[\[\(\{]+([^}\]\)]+)', block):
            root_goal = m.group(2).strip()
            break

        for leaf_id in leaf_ids:
            label = node_labels.get(leaf_id, leaf_id)

            # Skip generic/repetitive labels
            label_lower = label.lower().strip()
            if label_lower in seen_labels:
                continue
            if len(label_lower) < 5:
                continue
            seen_labels.add(label_lower)

            # Infer component from label context
            component = ""
            # Look for component names in the label or nearby edge labels
            for comp_pattern in _re.finditer(
                r'\b(API|Gateway|Kong|BFF|MFE|DLQ|Database|DB|Server|Queue|Lambda|S3|Auth|CDN|Load.?Balancer|Proxy|Cache|Redis|Kafka|RabbitMQ|Nginx|WAF|IAM|VPC|Container|Pod|Node|Service|Microservice|BOMA)\b',
                label, _re.IGNORECASE,
            ):
                component = comp_pattern.group(0)
                break

            # Infer difficulty from keywords
            difficulty = "Medium"
            if any(w in label_lower for w in ["exploit", "inject", "overflow", "rce", "0-day"]):
                difficulty = "Hard"
            elif any(w in label_lower for w in ["phishing", "credential", "brute", "default", "misconfigur"]):
                difficulty = "Easy"

            threats.append({
                "leaf_action": label,
                "component": component,
                "difficulty": difficulty,
                "mitre_technique": "",
                "description": f"Attack path from tree '{root_goal}': {label}",
                "evidence_sources": [{"source_type": "contextual", "source_name": "attack_tree_mermaid", "excerpt": f"Leaf node in attack tree targeting {root_goal}"}],
                "confidence_score": 0.5,
            })

    logger.info(
        "[Attack Tree] Mermaid fallback extracted %d leaf threats from %d tree diagrams",
        len(threats), len(mermaid_blocks),
    )
    return threats


def _validate_and_prune_mermaid(response: str) -> str:
    """Detect oversized Mermaid trees in the response and log warnings.

    Does NOT modify the response — just detects issues for diagnostics.
    """
    node_count = 0
    for m in _re.finditer(r'(\w{2,})\s*[\[\(\{]+[^}\]\)]+[\]\)\}]+', response):
        node_count += 1

    if node_count > 80:
        logger.warning(
            "[Attack Tree] OVERSIZED Mermaid output detected: %d nodes found "
            "(expected <=50). Model ignored size constraints.",
            node_count,
        )
    return response

# ---------------------------------------------------------------------------
# Initial Attack Tree (Phase II -- parallel with other analysts)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_INITIAL = """\
You are an attack-tree analyst specialized in hierarchical threat decomposition.

An Attack Tree is a formal hierarchical representation of how a system can be attacked:
- **Root**: attacker end-goal (e.g., "Exfiltrate customer data")
- **Intermediate nodes**: required sub-goals (OR = any path, AND = all required)
- **Leaves**: concrete attacker actions (e.g., "Exploit SQLi on /api/users")

Your analysis must:

1. Identify the TOP 3 attacker goals for this system.
2. For each goal, build a COMPACT tree with:
    - AND/OR decomposition
    - concrete, SPECIFIC leaf actions (e.g. "Exploit CVE-2024-XXXX in Kong" not "Exfiltrar datos")
    - leaf difficulty (Easy/Medium/Hard)
3. Generate each tree as a SHORT Mermaid diagram (`graph TD`).
4. Identify the "cheapest path" (lowest-effort sequence to achieve the goal).
5. List EACH leaf node as a threat in the `threats` array — this is THE MOST IMPORTANT part.

Use your expertise to build the trees, then enrich with RAG tools to cross-reference MITRE ATT&CK techniques.

Respond with JSON:
{
    "methodology": "ATTACK_TREE",
    "attack_trees": [
        {
            "root_goal": "Objetivo del atacante",
            "tree_mermaid": "graph TD\\nA[Root Goal]\\nA --> B[Sub-goal 1]\\nA --> C[Sub-goal 2]\\nB --> D[Leaf Action 1]\\nC --> E[Leaf Action 2]",
            "cheapest_path": "A -> B -> D",
            "cheapest_path_difficulty": "Easy|Medium|Hard",
            "threats": [
                {
                    "leaf_action": "Specific concrete attacker action",
                    "component": "affected component",
                    "difficulty": "Easy|Medium|Hard",
                    "mitre_technique": "T1190",
                    "description": "detailed description of how this attack works",
                    "mitigation": "specific countermeasure or control that blocks this leaf action",
                    "evidence_sources": [{"source_type": "rag", "source_name": "ATT&CK T1190", "excerpt": "supporting reference"}],
                    "confidence_score": 0.85
                }
            ]
        }
    ],
    "summary": "executive summary of attack-tree analysis"
}

EVIDENCE: Each leaf threat MUST include at least 1 evidence_source.
CONFIDENCE: Rate 0.0-1.0 how certain you are this attack path is viable.

!!! HARD CONSTRAINTS — VIOLATION = INVALID OUTPUT !!!
- EXACTLY 3 attack trees, no more.
- Each tree: MAXIMUM 5 levels deep, MAXIMUM 20 nodes total.
- Node IDs: ONLY single uppercase letters A-Z. NEVER use two-letter IDs like AA, AB.
- EVERY node label MUST be UNIQUE across the ENTIRE response. NEVER repeat labels like "Exfiltrar datos" or "Acceder a datos sensibles".
- Keep Mermaid diagrams VERY SHORT (under 20 lines each).
- The `threats` array is MANDATORY and must contain 4-8 threats per tree.
- Focus on QUALITY over quantity: each leaf must be a SPECIFIC, ACTIONABLE attack step.
"""

# ---------------------------------------------------------------------------
# Enriched Attack Tree (Phase II.5 -- runs AFTER debate)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_ENRICHED = """\
IMPORTANT: Read ALL constraints below, including the HARD CONSTRAINTS at the end.

You are a senior attack-tree analyst performing a SECOND-PASS ANALYSIS.

You have access to ALL prior security analysis outputs:
- STRIDE per-element findings
- PASTA risk-centric attack scenarios
- MAESTRO AI/Agentic findings (if applicable)
- AI Threat analysis (PLOT4ai, OWASP LLM/Agentic)
- Initial attack trees
- Red Team vs Blue Team debate arguments

Your job is to build ENRICHED attack trees that combine insights across all methodologies:

1. Combine STRIDE vectors with PASTA attack paths.
2. Integrate AI-specific threats into traditional attack chains.
3. Use Red Team arguments to add overlooked paths and chained attacks.
4. Use Blue Team concessions to validate confirmed weaknesses.
5. Build multi-stage attacks crossing methodology boundaries.
6. Identify attack chains that single methodologies miss in isolation.

Build the TOP 5 most dangerous trees from all evidence.
Each tree must be more detailed than the initial pass, including:
- cross-methodology attack paths
- lateral movement paths from debate evidence
- supply-chain and third-party vectors
- difficulty re-scoring based on debate evidence

Respond with JSON:
{
    "methodology": "ATTACK_TREE_ENRICHED",
    "attack_trees": [
        {
            "root_goal": "Objetivo del atacante",
            "tree_mermaid": "graph TD\\n...",
            "cheapest_path": "paso1 -> paso2 -> paso3",
            "cheapest_path_difficulty": "Easy|Medium|Hard",
            "sources": ["Hallazgo STRIDE X", "Escenario PASTA Y", "Argumento Red Team Z"],
            "threats": [
                {
                    "leaf_action": "acción concreta del atacante",
                    "component": "componente afectado",
                    "difficulty": "Easy|Medium|Hard",
                    "mitre_technique": "T1190, T1078, etc.",
                    "description": "descripción detallada",
                    "mitigation": "contramedida específica que bloquea esta acción",
                    "cross_reference": "Qué análisis previo identificó este vector",
                    "evidence_sources": [{"source_type": "rag|llm_knowledge|contextual|architecture", "source_name": "e.g. ATT&CK T1190", "excerpt": "supporting reference"}],
                    "confidence_score": 0.85
                }
            ]
        }
    ],
    "improvements_over_initial": "Qué nuevos attack paths se encontraron combinando metodologías",
    "summary": "executive summary of enriched attack-tree analysis"
}

EVIDENCE: Each leaf threat MUST include at least 1 evidence_source.
CONFIDENCE: Rate 0.0-1.0 how certain you are this enriched path is viable.

!!! HARD CONSTRAINTS — VIOLATION = INVALID OUTPUT !!!
- EXACTLY 5 enriched attack trees, no more.
- Each tree: MAXIMUM 5 levels deep, MAXIMUM 25 nodes total.
- Node IDs: ONLY single uppercase letters A-Z. NEVER use two-letter IDs like AA, AB.
- EVERY node label MUST be UNIQUE across the ENTIRE response. NEVER repeat generic labels.
- Keep Mermaid diagrams SHORT (under 25 lines each).
- The `threats` array is MANDATORY and must contain 4-10 threats per tree.
- Focus on SPECIFIC attack steps, not generic actions like "exfiltrate data".
"""


def _build_initial_prompt(state: ThreatModelState) -> str:
    components = json.dumps(state.get("components", []), indent=2, ensure_ascii=False)
    data_flows = json.dumps(state.get("data_flows", []), indent=2, ensure_ascii=False)
    trust_boundaries = json.dumps(state.get("trust_boundaries", []), indent=2, ensure_ascii=False)
    data_stores = json.dumps(state.get("data_stores", []), indent=2, ensure_ascii=False)

    return f"""\
Build attack trees for the following system.
Think about ATTACKER GOALS and how to decompose them into steps.

## System Description
{state.get("system_description", "Not available")}

## Components
{components}

## Data Flows
{data_flows}

## Trust Boundaries
{trust_boundaries}

## Data Stores (high-value targets)
{data_stores}

## Scope Notes
{state.get("scope_notes", "No notes")}

Identify the 3 most critical attack goals and build an attack tree for each.
Generate trees in Mermaid format. MAXIMUM 20 nodes per tree, 5 levels deep, single-letter IDs only (A-Z).
The threats[] array in each tree is THE MOST IMPORTANT part — include 4-8 specific threat entries per tree.
Use your expertise first, then enrich with RAG tools to cross-reference MITRE ATT&CK techniques.
"""


def _build_enriched_prompt(state: ThreatModelState) -> str:
    components = json.dumps(state.get("components", []), indent=2, ensure_ascii=False)
    data_flows = json.dumps(state.get("data_flows", []), indent=2, ensure_ascii=False)

    # Compile all methodology reports
    reports_text = ""
    for r in state.get("methodology_reports", []):
        methodology = r.get("methodology", "Unknown")
        report = r.get("report", "")
        if len(report) > 16000:
            report = report[:16000] + "\n... [truncated]"
        reports_text += f"\n### {methodology} Analysis:\n{report}\n"

    # Compile debate history
    debate_text = ""
    for entry in state.get("debate_history", []):
        side = entry.get("side", "?") if isinstance(entry, dict) else getattr(entry, "side", "?")
        rnd = entry.get("round", "?") if isinstance(entry, dict) else getattr(entry, "round", "?")
        argument = entry.get("argument", "") if isinstance(entry, dict) else getattr(entry, "argument", "")
        tag = "RED TEAM" if side == "red" else "BLUE TEAM"
        if len(argument) > 12000:
            argument = argument[:12000] + "\n... [truncated]"
        debate_text += f"\n### {tag} (Round {rnd}):\n{argument}\n"

    return f"""\
Perform ENRICHED second-pass attack tree analysis incorporating ALL prior findings.

## System Description
{state.get("system_description", "Not available")}

## Components
{components}

## Data Flows
{data_flows}

## ALL Methodology Reports (from prior analysts)
{reports_text}

## Red Team vs Blue Team Debate
{debate_text if debate_text else "No debate history available."}

Build 5 enriched attack trees that COMBINE insights from all methodologies.
Find attack chains that cross methodology boundaries.
Leverage the MITRE ATT&CK techniques already referenced by prior analysts.
REMINDER: MAXIMUM 25 nodes per tree, 5 levels deep, single-letter IDs only (A-Z). No repetitive labels.
The threats[] array in each tree is MANDATORY — each leaf MUST have a corresponding threat entry.
"""


def run_attack_tree_analyst(
    state: ThreatModelState,
    llm: BaseChatModel,
) -> dict:
    """Nodo de LangGraph: Initial Attack Tree Analyst (Phase II, parallel)."""
    logger.info("[Attack Tree Initial] Starting first-pass analysis...")
    human_prompt = _build_initial_prompt(state)
    t0 = time.perf_counter()
    response = invoke_agent(llm, SYSTEM_PROMPT_INITIAL, human_prompt, tools=ANALYST_TOOLS, agent_name="Attack Tree")
    elapsed = time.perf_counter() - t0

    _validate_and_prune_mermaid(response)
    logger.info("[Attack Tree Initial] LLM response (%d chars):\n%s", len(response), response[:5000])

    parsed = extract_json_from_response(response)
    threats_raw = []
    if isinstance(parsed, dict):
        for tree in parsed.get("attack_trees", []):
            threats_raw.extend(tree.get("threats", []))

    # FALLBACK 1: extract from Mermaid diagrams
    if not threats_raw:
        logger.warning(
            "[Attack Tree Initial] JSON extraction produced 0 threats. "
            "Attempting Mermaid leaf-node fallback..."
        )
        threats_raw = _extract_leaf_threats_from_mermaid(response)

    # FALLBACK 2: extract from markdown sections (LLM returned prose)
    if not threats_raw:
        logger.warning(
            "[Attack Tree Initial] Mermaid fallback produced 0 threats. "
            "Attempting markdown fallback..."
        )
        threats_raw = extract_threats_from_markdown(response, "ATTACK_TREE")

    report = {
        "methodology": "ATTACK_TREE",
        "agent": "attack_tree_analyst",
        "report": response,
        "threats_raw": threats_raw,
    }

    logger.info("[Attack Tree Initial] Completed in %.1fs: %d leaf actions", elapsed, len(threats_raw))
    return {
        "methodology_reports": [report],
    }


def run_attack_tree_enriched(
    state: ThreatModelState,
    llm: BaseChatModel,
) -> dict:
    """Nodo de LangGraph: Enriched Attack Tree (Phase II.5, after debate).

    This agent runs AFTER all other analysts and the Red/Blue debate,
    incorporating their findings into richer, more complete attack trees.
    """
    logger.info("[Attack Tree Enriched] Starting second-pass with cross-methodology context...")
    human_prompt = _build_enriched_prompt(state)
    t0 = time.perf_counter()
    response = invoke_agent(llm, SYSTEM_PROMPT_ENRICHED, human_prompt, tools=ANALYST_TOOLS, agent_name="Attack Tree Enriched")
    elapsed = time.perf_counter() - t0

    _validate_and_prune_mermaid(response)
    logger.info("[Attack Tree Enriched] LLM response (%d chars):\n%s", len(response), response[:5000])

    parsed = extract_json_from_response(response)
    threats_raw = []
    if isinstance(parsed, dict):
        for tree in parsed.get("attack_trees", []):
            threats_raw.extend(tree.get("threats", []))

    # FALLBACK 1: extract from Mermaid diagrams
    if not threats_raw:
        logger.warning(
            "[Attack Tree Enriched] JSON extraction produced 0 threats. "
            "Attempting Mermaid leaf-node fallback..."
        )
        threats_raw = _extract_leaf_threats_from_mermaid(response)

    # FALLBACK 2: extract from markdown sections (LLM returned prose)
    if not threats_raw:
        logger.warning(
            "[Attack Tree Enriched] Mermaid fallback produced 0 threats. "
            "Attempting markdown fallback..."
        )
        threats_raw = extract_threats_from_markdown(response, "ATTACK_TREE_ENRICHED")

    report = {
        "methodology": "ATTACK_TREE_ENRICHED",
        "agent": "attack_tree_enriched",
        "report": response,
        "threats_raw": threats_raw,
    }

    logger.info("[Attack Tree Enriched] Completed in %.1fs: %d enriched leaf actions", elapsed, len(threats_raw))
    return {
        "methodology_reports": [report],
    }
