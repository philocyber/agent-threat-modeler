"""Graph builder for AgenticTM.

Pipeline (6 phases):
  I.     Architecture Parser (ingestion + VLM for images)
  II.    Methodology Analysts — execution governed by pipeline.analyst_execution_mode:
           "hybrid"   (default) Parallel fan-out throttled to max_parallel_analysts=2
                      simultaneous LLM slots via threading.Semaphore. Best quality/VRAM
                      tradeoff: diverse independent reasoning + bounded GPU pressure.
           "parallel" Same topology but semaphore limit may be set higher (up to 5).
           "cascade"  Sequential STRIDE→PASTA→AttackTree→MAESTRO→AI edges. Each
                      analyst sees accumulated prior state (context inheritance).
                      Lowest peak VRAM; some bias-drag risk.
  III.   Debate Red/Blue (N rounds)
  II.5   Enriched Attack Tree (post-debate, uses ALL prior outputs)
  IV.    Threat Synthesizer (Deep Thinker)
  IV.5   DREAD Validator (Deep Thinker — validates/corrects severity scores)
  V.     Output Localizer -> Report Generator -> END
"""

from __future__ import annotations

import gc
import logging
import threading
import traceback
from typing import TYPE_CHECKING, Literal

from langgraph.graph import END, StateGraph

from agentictm.state import ThreatModelState

if TYPE_CHECKING:
    from agentictm.config import AgenticTMConfig
    from agentictm.llm import LLMFactory

logger = logging.getLogger(__name__)


def _summarize_state(state: dict) -> dict:
    """Create a compact summary of state keys for logging."""
    summary = {}
    for k, v in state.items():
        if isinstance(v, list):
            summary[k] = f"list[{len(v)}]"
        elif isinstance(v, dict):
            summary[k] = f"dict[{len(v)} keys]"
        elif isinstance(v, str):
            summary[k] = f"str[{len(v)}]"
        else:
            summary[k] = type(v).__name__
    return summary


def _safe_node(node_fn, node_name: str):
    """Wrap a node function with try/except for graceful error handling.

    If the wrapped function raises, logs the full traceback and returns
    a dict with an ``_errors`` key so downstream nodes can still run.
    Critical nodes (architecture_parser, threat_synthesizer) re-raise
    because the pipeline cannot meaningfully continue without them.

    Logs structured node start/end/failure data through the standard
    logging system (captured by PipelineFileHandler when active).
    """
    import time as _time
    CRITICAL_NODES = {"architecture_parser", "threat_synthesizer"}

    def wrapper(state: ThreatModelState) -> dict:
        from agentictm.logging import set_agent_name

        set_agent_name(node_name)
        t0 = _time.monotonic()
        logger.info(
            "[%s] Node starting | input_keys=%d",
            node_name, len(state),
            extra={"node_name": node_name, "input_keys": list(state.keys())},
        )
        try:
            result = node_fn(state)

            elapsed_ms = (_time.monotonic() - t0) * 1000
            output_summary = _summarize_state(result) if isinstance(result, dict) else {}
            logger.info(
                "[%s] Node completed in %.1fms | output_keys=%s",
                node_name, elapsed_ms, list(output_summary.keys()),
                extra={
                    "node_name": node_name,
                    "duration_ms": round(elapsed_ms, 1),
                    "output_keys": output_summary,
                },
            )
            return result
        except Exception as exc:
            elapsed_ms = (_time.monotonic() - t0) * 1000
            logger.error(
                "[%s] Node FAILED after %.1fms: %s\n%s",
                node_name, elapsed_ms, exc, traceback.format_exc(),
                extra={
                    "node_name": node_name,
                    "duration_ms": round(elapsed_ms, 1),
                    "error": str(exc),
                },
            )
            if node_name in CRITICAL_NODES:
                raise
            return {"_errors": [{
                "node": node_name,
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }]}
        finally:
            collected = gc.collect()
            if collected:
                logger.debug("[%s] gc.collect() freed %d objects", node_name, collected)
            set_agent_name("")

    wrapper.__name__ = f"safe_{node_name}"
    return wrapper


def build_graph(
    config: AgenticTMConfig,
    llm_factory: LLMFactory,
) -> StateGraph:
    """Build the complete AgenticTM StateGraph.

    Flow:
        architecture_parser (VLM-enabled)
            -> [stride, pasta, attack_tree, maestro, ai_threat] (parallel fan-out)
            -> barrier
            -> red_team -> blue_team -> (loop N rounds)
            -> attack_tree_enriched (second pass with ALL context)
            -> threat_synthesizer (Deep Thinker)
            -> report_generator
            -> END
    """

    # -- Import agent functions --
    from agentictm.agents.architecture_parser import run_architecture_parser
    from agentictm.agents.arch_clarifier import run_arch_clarifier
    from agentictm.agents.stride_analyst import run_stride_analyst
    from agentictm.agents.pasta_analyst import run_pasta_analyst
    from agentictm.agents.attack_tree_analyst import (
        run_attack_tree_analyst,
        run_attack_tree_enriched,
    )
    from agentictm.agents.maestro_analyst import run_maestro_analyst
    from agentictm.agents.ai_threat_analyst import run_ai_threat_analyst
    from agentictm.agents.debate import run_red_team, run_blue_team
    from agentictm.agents.threat_synthesizer import run_threat_synthesizer
    from agentictm.agents.dread_validator import run_dread_validator
    from agentictm.agents.output_localizer import run_output_localizer
    from agentictm.agents.report_generator import run_report_generator

    # -- LLM instances --
    quick = llm_factory.quick
    quick_json = llm_factory.quick_json
    deep = llm_factory.deep
    deep_json = llm_factory.deep_json
    stride = llm_factory.stride
    stride_json = llm_factory.stride_json
    vlm = llm_factory.vlm
    vlm_image_timeout = config.vlm.vlm_image_timeout

    # -- Pipeline skip flags (fast-mode optimizations) --
    _enabled_analysts = set(config.pipeline.enabled_analysts)
    _skip_debate = config.pipeline.skip_debate
    _skip_enriched = config.pipeline.skip_enriched_attack_tree
    _skip_dread = config.pipeline.skip_dread_validator
    _skip_localizer = config.pipeline.skip_output_localizer

    # -- Node wrappers (wrapped with _safe_node for graceful error handling) --

    def _node_architecture_parser(state: ThreatModelState) -> dict:
        return run_architecture_parser(state, stride_json, vlm=vlm, vlm_image_timeout=vlm_image_timeout)

    def _node_arch_clarifier(state: ThreatModelState) -> dict:
        return run_arch_clarifier(state, quick)

    def _node_stride(state: ThreatModelState) -> dict:
        if "stride" not in _enabled_analysts:
            logger.info("[STRIDE] Skipped (not in enabled_analysts)")
            return {}
        return run_stride_analyst(state, stride_json)

    def _node_pasta(state: ThreatModelState) -> dict:
        if "pasta" not in _enabled_analysts:
            logger.info("[PASTA] Skipped (not in enabled_analysts)")
            return {}
        return run_pasta_analyst(state, quick_json)

    def _node_attack_tree(state: ThreatModelState) -> dict:
        if "attack_tree" not in _enabled_analysts:
            logger.info("[Attack Tree] Skipped (not in enabled_analysts)")
            return {}
        return run_attack_tree_analyst(state, quick_json)

    def _node_maestro(state: ThreatModelState) -> dict:
        if "maestro" not in _enabled_analysts:
            logger.info("[MAESTRO] Skipped (not in enabled_analysts)")
            return {}
        return run_maestro_analyst(state, quick_json)

    def _node_ai_threat(state: ThreatModelState) -> dict:
        if "ai_threat" not in _enabled_analysts:
            logger.info("[AI Threat] Skipped (not in enabled_analysts)")
            return {}
        return run_ai_threat_analyst(state, quick_json)

    def _node_red_team(state: ThreatModelState) -> dict:
        if _skip_debate:
            logger.info("[Red Team] Skipped (skip_debate=True)")
            return {}
        return run_red_team(state, stride)

    def _node_blue_team(state: ThreatModelState) -> dict:
        if _skip_debate:
            logger.info("[Blue Team] Skipped (skip_debate=True)")
            return {}
        return run_blue_team(state, stride)

    def _node_attack_tree_enriched(state: ThreatModelState) -> dict:
        if _skip_enriched:
            logger.info("[Attack Tree Enriched] Skipped (skip_enriched_attack_tree=True)")
            return {}
        return run_attack_tree_enriched(state, quick_json)

    def _node_synthesizer(state: ThreatModelState) -> dict:
        return run_threat_synthesizer(state, deep_json, config=config)

    def _node_dread_validator(state: ThreatModelState) -> dict:
        if _skip_dread:
            logger.info("[DREAD Validator] Skipped (skip_dread_validator=True)")
            return {}
        return run_dread_validator(state, quick_json, config=config)

    def _node_output_localizer(state: ThreatModelState) -> dict:
        if _skip_localizer:
            logger.info("[Output Localizer] Skipped (skip_output_localizer=True)")
            return {}
        return run_output_localizer(state, quick_json, config=config)

    def _node_report(state: ThreatModelState) -> dict:
        return run_report_generator(state)

    # ── Analyst concurrency throttle (hybrid / parallel modes) ──────────────
    # In LangGraph parallel fan-out, nodes execute in a ThreadPoolExecutor.
    # A threading.Semaphore shared by all 5 analyst wrappers ensures at most
    # max_parallel_analysts LLM calls run simultaneously, keeping GPU/VRAM
    # pressure bounded without changing the graph topology.
    execution_mode = config.pipeline.analyst_execution_mode
    max_concurrent = config.pipeline.max_parallel_analysts

    if execution_mode in ("parallel", "hybrid"):
        _analyst_sem = threading.Semaphore(max_concurrent)
        logger.info(
            "[Graph] Analyst execution mode=%s  max_concurrent=%d",
            execution_mode, max_concurrent,
        )
    else:  # cascade — semaphore not needed (single sequential path)
        _analyst_sem = None
        logger.info("[Graph] Analyst execution mode=cascade (sequential chain)")

    def _throttled(fn, name: str):
        """Wrap an analyst node with semaphore acquisition when throttling is active."""
        if _analyst_sem is None:
            return fn

        def _wrapper(state: ThreatModelState) -> dict:
            logger.info(
                "[%s] Waiting for analyst slot (active_slots≤%d)...",
                name, max_concurrent,
            )
            _analyst_sem.acquire()
            try:
                logger.info("[%s] Analyst slot acquired — starting", name)
                return fn(state)
            finally:
                _analyst_sem.release()
                logger.info("[%s] Analyst slot released", name)

        _wrapper.__name__ = fn.__name__
        return _wrapper

    # Apply throttle wrappers BEFORE _safe_node so semaphore is always released
    # (even if _safe_node swallows the exception after release in finally block).
    _node_stride      = _throttled(_node_stride,      "stride_analyst")
    _node_pasta       = _throttled(_node_pasta,       "pasta_analyst")
    _node_attack_tree = _throttled(_node_attack_tree, "attack_tree_analyst")
    _node_maestro     = _throttled(_node_maestro,     "maestro_analyst")
    _node_ai_threat   = _throttled(_node_ai_threat,   "ai_threat_analyst")

    # Apply _safe_node to all wrappers
    node_architecture_parser = _safe_node(_node_architecture_parser, "architecture_parser")
    node_arch_clarifier      = _safe_node(_node_arch_clarifier,      "arch_clarifier")
    node_stride              = _safe_node(_node_stride, "stride_analyst")
    node_pasta               = _safe_node(_node_pasta, "pasta_analyst")
    node_attack_tree         = _safe_node(_node_attack_tree, "attack_tree_analyst")
    node_maestro             = _safe_node(_node_maestro, "maestro_analyst")
    node_ai_threat           = _safe_node(_node_ai_threat, "ai_threat_analyst")
    node_red_team            = _safe_node(_node_red_team, "red_team")
    node_blue_team           = _safe_node(_node_blue_team, "blue_team")
    node_attack_tree_enriched = _safe_node(_node_attack_tree_enriched, "attack_tree_enriched")
    node_synthesizer         = _safe_node(_node_synthesizer, "threat_synthesizer")
    node_dread_validator     = _safe_node(_node_dread_validator, "dread_validator")
    node_output_localizer    = _safe_node(_node_output_localizer, "output_localizer")
    node_report              = _safe_node(_node_report, "report_generator")

    # -- Conditional edges --
    max_rounds = config.pipeline.max_debate_rounds

    def should_continue_debate(state: ThreatModelState) -> Literal["red_team", "attack_tree_enriched"]:
        """Decide whether to continue the debate or proceed to enriched attack tree.

        Stops early if Red Team signals [CONVERGENCIA] (no new attack vectors found).
        Per-request cap via state["max_debate_rounds"]; falls back to config default.
        """
        current_round = state.get("debate_round", 1)
        effective_max = state.get("max_debate_rounds", max_rounds)
        debate_history = state.get("debate_history", [])

        logger.debug(
            "[Debate] Decision: round=%d, max=%d, history_len=%d",
            current_round, effective_max, len(debate_history),
        )

        # ── Safety valve: detect failed/skipped debate nodes ──
        # After blue_team runs we expect at least 2 entries (1 red + 1 blue).
        # An empty history means both nodes returned nothing — exit immediately
        # to prevent an infinite loop where debate_round never increments.
        if not debate_history:
            logger.warning(
                "[Debate] debate_history is empty — debate nodes failed or were skipped. "
                "Exiting debate loop."
            )
            return "attack_tree_enriched"

        # ── Safety valve: detect stalled rounds ──
        # Each completed round adds 2 entries (red + blue). If the history is
        # far shorter than expected, nodes are silently failing.
        expected_entries = current_round * 2
        if len(debate_history) < expected_entries - 2:
            logger.warning(
                "[Debate] debate_history has %d entries but expected ~%d for round %d "
                "— debate nodes are failing. Exiting.",
                len(debate_history), expected_entries, current_round,
            )
            return "attack_tree_enriched"

        if current_round > effective_max:
            logger.info("[Debate] Cap reached at round %d (max=%d), moving on", current_round - 1, effective_max)
            return "attack_tree_enriched"

        # ── Minimum-round guard ──
        # Never allow convergence before completing at least 2 full exchanges
        # (round 1 = initial positions, round 2 = first real rebuttal).
        MIN_DEBATE_ROUNDS = 2
        if current_round <= MIN_DEBATE_ROUNDS:
            return "red_team"

        # Convergence check: look for [CONVERGENCIA] in the last Red Team argument
        last_red = next(
            (e for e in reversed(debate_history)
             if (e.get("side") if isinstance(e, dict) else getattr(e, "side", "")) == "red"),
            None,
        )
        if last_red is not None:
            last_arg = last_red.get("argument", "") if isinstance(last_red, dict) else getattr(last_red, "argument", "")
            if "[CONVERGENCIA]" in last_arg or "[CONVERGED]" in last_arg:
                logger.info(
                    "[Debate] Convergence signal detected by Red Team after round %d, stopping early",
                    current_round - 1,
                )
                return "attack_tree_enriched"

        return "red_team"

    # -- Build the graph --
    graph = StateGraph(ThreatModelState)

    # Phase I: Ingestion
    graph.add_node("architecture_parser", node_architecture_parser)
    graph.add_node("arch_clarifier", node_arch_clarifier)

    # Phase II: Methodology Analysts (parallel fan-out)
    graph.add_node("stride_analyst", node_stride)
    graph.add_node("pasta_analyst", node_pasta)
    graph.add_node("attack_tree_analyst", node_attack_tree)
    graph.add_node("maestro_analyst", node_maestro)
    graph.add_node("ai_threat_analyst", node_ai_threat)

    # Phase III: Debate (only added when debate is enabled)
    if not _skip_debate:
        graph.add_node("red_team", node_red_team)
        graph.add_node("blue_team", node_blue_team)

    # Phase II.5: Enriched Attack Tree (post-debate)
    graph.add_node("attack_tree_enriched", node_attack_tree_enriched)

    # Phase IV: Synthesis + Validation + Output
    graph.add_node("threat_synthesizer", node_synthesizer)
    graph.add_node("dread_validator", node_dread_validator)
    graph.add_node("output_localizer", node_output_localizer)
    graph.add_node("report_generator", node_report)

    # -- Edges --

    # Entry point
    graph.set_entry_point("architecture_parser")

    def should_clarify(state: ThreatModelState) -> Literal["arch_clarifier", "stride_analyst", "branch"]:
        """Decide if we need more info or can move to analysts."""
        if state.get("clarification_needed") and not state.get("user_answers"):
            return "arch_clarifier"
        
        # Determine the next node based on execution_mode
        if execution_mode == "cascade":
            return "stride_analyst"
        return "branch"

    # Branch helper for parallel mode
    def branch_analysts(state: ThreatModelState) :
        return ["stride_analyst", "pasta_analyst", "attack_tree_analyst", "maestro_analyst", "ai_threat_analyst"]

    def _make_activation_gate(target_node: str):
        """Create a uniquely named branch predicate for parallel analyst fan-out."""
        def _gate(state: ThreatModelState) -> Literal["active", "skip"]:
            if not state.get("clarification_needed") or state.get("user_answers"):
                return "active"
            return "skip"

        _gate.__name__ = f"activate_{target_node}"
        return _gate

    # Phase I -> Phase II (with optional clarification)
    graph.add_conditional_edges(
        "architecture_parser",
        should_clarify,
        {
            "arch_clarifier": "arch_clarifier",
            "stride_analyst": "stride_analyst", # cascade mode
            "branch": "stride_analyst"         # parallel start point (LangGraph handles multiple edges)
        }
    )

    # After clarification, we ALWAYS interrupt (implicitly by ending at a node or having no next edge)
    # But we want to return the flow to analysts once resumed.
    # The API will resume by calling the graph with user_answers set.
    graph.add_edge("arch_clarifier", END) # Stop and wait for user

    # The node analysts fan into — either debate (red_team) or directly to
    # attack_tree_enriched when debate is skipped.
    _fan_in_target = "attack_tree_enriched" if _skip_debate else "red_team"

    # Phase I -> Phase II — topology depends on analyst_execution_mode
    if execution_mode == "cascade":
        # Sequential chain: each analyst feeds into the next
        graph.add_edge("stride_analyst",      "pasta_analyst")
        graph.add_edge("pasta_analyst",       "attack_tree_analyst")
        graph.add_edge("attack_tree_analyst", "maestro_analyst")
        graph.add_edge("maestro_analyst",     "ai_threat_analyst")
        graph.add_edge("ai_threat_analyst",   _fan_in_target)
        logger.info("[Graph] Cascade edges: stride→pasta→attack_tree→maestro→ai→%s", _fan_in_target)
    else:
        # Parallel: fan-out from architecture_parser to all analysts
        graph.add_conditional_edges(
            "architecture_parser",
            _make_activation_gate("pasta_analyst"),
            {
                "active": "pasta_analyst",
                "skip": END 
            }
        )
        graph.add_conditional_edges(
            "architecture_parser",
            _make_activation_gate("attack_tree_analyst"),
            {
                "active": "attack_tree_analyst",
                "skip": END
            }
        )
        graph.add_conditional_edges(
            "architecture_parser",
            _make_activation_gate("maestro_analyst"),
            {
                "active": "maestro_analyst",
                "skip": END
            }
        )
        graph.add_conditional_edges(
            "architecture_parser",
            _make_activation_gate("ai_threat_analyst"),
            {
                "active": "ai_threat_analyst",
                "skip": END
            }
        )

        # Fan-in barrier: all 5 analysts complete before next phase
        graph.add_edge("stride_analyst",      _fan_in_target)
        graph.add_edge("pasta_analyst",        _fan_in_target)
        graph.add_edge("attack_tree_analyst",  _fan_in_target)
        graph.add_edge("maestro_analyst",      _fan_in_target)
        graph.add_edge("ai_threat_analyst",    _fan_in_target)

    if not _skip_debate:
        # Debate loop: red -> blue -> conditional(continue debate or enriched tree)
        graph.add_edge("red_team", "blue_team")
        graph.add_conditional_edges(
            "blue_team",
            should_continue_debate,
            {
                "red_team": "red_team",
                "attack_tree_enriched": "attack_tree_enriched",
            },
        )
    else:
        logger.info("[Graph] Debate loop skipped (skip_debate=True)")

    # Phase II.5 -> Phase IV
    graph.add_edge("attack_tree_enriched", "threat_synthesizer")

    # Phase IV -> Validation -> Output -> END
    graph.add_edge("threat_synthesizer", "dread_validator")
    graph.add_edge("dread_validator", "output_localizer")
    graph.add_edge("output_localizer", "report_generator")
    graph.add_edge("report_generator", END)

    logger.info("[Graph] AgenticTM graph built -- %d nodes", len(graph.nodes))
    return graph


def compile_graph(
    config: AgenticTMConfig,
    llm_factory: LLMFactory,
):
    """Build and compile the graph, ready to execute."""
    graph = build_graph(config, llm_factory)
    return graph.compile()
