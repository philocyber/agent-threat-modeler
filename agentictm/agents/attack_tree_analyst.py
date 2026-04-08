"""Agent: Attack Tree Analyst -- Phase II + Phase II.5.

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

from agentictm.agents.base import (
    invoke_agent, extract_json_from_response, extract_threats_from_markdown,
    find_threats_in_json, _extract_individual_json_objects,
)
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
!!! OUTPUT FORMAT: You MUST respond with a SINGLE JSON object. NO markdown, NO narrative, NO headings outside JSON. !!!

You are an attack-tree analyst. Build hierarchical threat decompositions INTERNALLY,
then OUTPUT ONLY the JSON structure below.

Your response must be EXACTLY this JSON:
{"methodology":"ATTACK_TREE","attack_trees":[<3 tree objects>],"summary":"<1 paragraph>"}

Each tree object:
{
  "root_goal": "attacker end-goal",
  "tree_mermaid": "graph TD\\nA[Root]\\nA --> B[Sub-goal]\\nB --> C[Leaf Action]",
  "cheapest_path": "A -> B -> C",
  "cheapest_path_difficulty": "Easy|Medium|Hard",
  "threats": [
    {
      "leaf_action": "specific concrete attacker action (e.g. 'Exploit SQLi on /api/users')",
      "component": "exact affected component name",
      "difficulty": "Easy|Medium|Hard",
      "mitre_technique": "T1190",
      "description": "3-5 sentences: how this attack works against THIS system, naming specific components",
      "mitigation": "specific countermeasure that blocks this action",
      "evidence_sources": [{"source_type": "rag", "source_name": "ATT&CK T1190", "excerpt": "quote"}],
      "confidence_score": 0.85
    }
  ]
}

HARD CONSTRAINTS:
- EXACTLY 3 attack trees
- Each tree: MAX 5 levels, MAX 20 nodes, single-letter IDs (A-Z)
- The threats[] array is MANDATORY: 4-8 specific threats per tree
- Each leaf must be a SPECIFIC, ACTIONABLE attack step (not "exfiltrate data")
- Output ONLY JSON -- no markdown narrative, no stage descriptions, no conclusions

!!! CRITICAL: DO NOT COPY RAG ENTRIES !!!
- RAG results (e.g. TMA-xxxx IDs from threats.csv) are REFERENCE MATERIAL ONLY
- Do NOT copy their IDs, titles, or descriptions into your output
- Build YOUR OWN attack trees from the specific system architecture
- Use RAG only to find MITRE ATT&CK technique IDs for YOUR attack paths
"""

# ---------------------------------------------------------------------------
# Enriched Attack Tree (Phase II.5 -- runs AFTER debate)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_ENRICHED = """\
!!! OUTPUT FORMAT: You MUST respond with a SINGLE JSON object. NO markdown, NO narrative outside JSON. !!!

You are a senior attack-tree analyst performing a SECOND-PASS ENRICHED analysis.
You have ALL prior analysis (STRIDE, PASTA, MAESTRO, AI Threats, initial trees, Red/Blue debate).

Combine cross-methodology insights INTERNALLY, then OUTPUT ONLY this JSON:
{"methodology":"ATTACK_TREE_ENRICHED","attack_trees":[<5 tree objects>],"summary":"<1 paragraph>"}

Each tree object:
{
  "root_goal": "attacker end-goal",
  "tree_mermaid": "graph TD\\nA[Root]\\nA --> B[Sub-goal]\\nB --> C[Leaf]",
  "cheapest_path": "step1 -> step2 -> step3",
  "cheapest_path_difficulty": "Easy|Medium|Hard",
  "sources": ["STRIDE finding X", "PASTA scenario Y", "Red Team argument Z"],
  "threats": [
    {
      "leaf_action": "specific attacker action",
      "component": "affected component",
      "difficulty": "Easy|Medium|Hard",
      "mitre_technique": "T1190, T1078",
      "description": "3-5 sentences: how this multi-stage attack works, naming components",
      "mitigation": "specific countermeasure",
      "cross_reference": "which prior analysis identified this vector",
      "evidence_sources": [{"source_type": "rag", "source_name": "source", "excerpt": "quote"}],
      "confidence_score": 0.85
    }
  ]
}

HARD CONSTRAINTS:
- EXACTLY 5 enriched attack trees
- Each tree: MAX 5 levels, MAX 25 nodes, single-letter IDs (A-Z)
- threats[] is MANDATORY: 4-10 specific threats per tree
- Cross-reference findings from multiple prior methodologies
- Output ONLY JSON -- no markdown, no conclusions, no evidence sections outside JSON
- Do NOT copy RAG entries (TMA-xxxx IDs) -- build original attack paths from prior findings
"""


def _build_initial_prompt(state: ThreatModelState) -> str:
    components = json.dumps(state.get("components", []), indent=2, ensure_ascii=False)
    data_flows = json.dumps(state.get("data_flows", []), indent=2, ensure_ascii=False)
    trust_boundaries = json.dumps(state.get("trust_boundaries", []), indent=2, ensure_ascii=False)
    data_stores = json.dumps(state.get("data_stores", []), indent=2, ensure_ascii=False)

    components_list = state.get("components", [])
    arch_note = ""
    if not components_list:
        arch_note = (
            "\n\nNOTE: The structured component list is empty. "
            "The System Description above contains the FULL architecture details. "
            "Extract components and data flows from the description and build attack trees from them. "
            "Do NOT return an empty result.\n"
        )

    return f"""\
Build attack trees for the following system.

IMPORTANT: Respond with the JSON object ONLY. Do NOT write markdown or narrative text.

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
{arch_note}
Identify the 3 most critical attacker goals and build a compact attack tree for each.
The threats[] array in each tree is THE MOST IMPORTANT part -- include 4-8 specific threat entries per tree.
Use your expertise first, then enrich with RAG tools to cross-reference MITRE ATT&CK techniques.

REMINDER: Output a single JSON object with "methodology", "attack_trees" array, and "summary". No markdown.
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

IMPORTANT: Respond with the JSON object ONLY. Do NOT write markdown or narrative text.

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
The threats[] array in each tree is MANDATORY -- each leaf MUST have a corresponding threat entry.

REMINDER: Output a single JSON object with "methodology", "attack_trees" array, and "summary". No markdown.
"""


def run_attack_tree_analyst(
    state: ThreatModelState,
    llm: BaseChatModel,
) -> dict:
    """LangGraph node: Initial Attack Tree Analyst (Phase II, parallel)."""
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
        if not threats_raw:
            threats_raw = find_threats_in_json(parsed)

    # FALLBACK 1: individual object extraction from malformed JSON
    if not threats_raw:
        logger.warning("[Attack Tree Initial] JSON extraction produced 0 threats. Trying individual object extraction...")
        threats_raw = _extract_individual_json_objects(response)

    # FALLBACK 2: extract from Mermaid diagrams
    if not threats_raw:
        logger.warning("[Attack Tree Initial] Trying Mermaid leaf-node fallback...")
        threats_raw = _extract_leaf_threats_from_mermaid(response)

    # FALLBACK 3: extract from markdown sections
    if not threats_raw:
        logger.warning("[Attack Tree Initial] Trying markdown fallback...")
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
    """LangGraph node: Enriched Attack Tree (Phase II.5, after debate).

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
        if not threats_raw:
            threats_raw = find_threats_in_json(parsed)

    # FALLBACK 1: individual object extraction from malformed JSON
    if not threats_raw:
        logger.warning("[Attack Tree Enriched] JSON extraction produced 0 threats. Trying individual object extraction...")
        threats_raw = _extract_individual_json_objects(response)

    # FALLBACK 2: extract from Mermaid diagrams
    if not threats_raw:
        logger.warning("[Attack Tree Enriched] Trying Mermaid leaf-node fallback...")
        threats_raw = _extract_leaf_threats_from_mermaid(response)

    # FALLBACK 3: extract from markdown sections
    if not threats_raw:
        logger.warning("[Attack Tree Enriched] Trying markdown fallback...")
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
