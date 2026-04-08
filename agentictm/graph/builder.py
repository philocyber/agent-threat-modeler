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
            -> architecture_reviewer
            -> [clarification or analysts]
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
    from agentictm.agents.architecture_reviewer import run_architecture_reviewer
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
    from agentictm.agents.quality_judge import run_quality_judge, should_retry_synthesis
    from agentictm.agents.dread_validator import run_dread_validator
    from agentictm.agents.hallucination_detector import run_hallucination_detection
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
    _skip_review = config.pipeline.skip_architecture_review

    # -- Node wrappers (wrapped with _safe_node for graceful error handling) --

    def _node_architecture_parser(state: ThreatModelState) -> dict:
        return run_architecture_parser(state, stride_json, vlm=vlm, vlm_image_timeout=vlm_image_timeout)

    def _node_arch_clarifier(state: ThreatModelState) -> dict:
        return run_arch_clarifier(state, quick)

    def _node_architecture_reviewer(state: ThreatModelState) -> dict:
        if _skip_review:
            logger.info("[ArchitectureReviewer] Skipped (skip_architecture_review=True)")
            return {}
        return run_architecture_reviewer(state, llm=quick, config=config)

    def _node_stride(state: ThreatModelState) -> dict:
        if "stride" not in _enabled_analysts:
            logger.info("[STRIDE] Skipped (not in enabled_analysts)")
            return {}
        return run_stride_analyst(state, stride_json)

    def _node_pasta(state: ThreatModelState) -> dict:
        if "pasta" not in _enabled_analysts:
            logger.info("[PASTA] Skipped (not in enabled_analysts)")
            return {}
        return run_pasta_analyst(state, stride_json)

    def _node_attack_tree(state: ThreatModelState) -> dict:
        if "attack_tree" not in _enabled_analysts:
            logger.info("[Attack Tree] Skipped (not in enabled_analysts)")
            return {}
        return run_attack_tree_analyst(state, stride_json)

    def _node_maestro(state: ThreatModelState) -> dict:
        if "maestro" not in _enabled_analysts:
            logger.info("[MAESTRO] Skipped (not in enabled_analysts)")
            return {}
        return run_maestro_analyst(state, stride_json)

    def _node_ai_threat(state: ThreatModelState) -> dict:
        if "ai_threat" not in _enabled_analysts:
            logger.info("[AI Threat] Skipped (not in enabled_analysts)")
            return {}
        return run_ai_threat_analyst(state, stride_json)

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
        return run_attack_tree_enriched(state, stride_json)

    def _node_synthesizer(state: ThreatModelState) -> dict:
        return run_threat_synthesizer(state, deep_json, config=config)

    def _node_quality_judge(state: ThreatModelState) -> dict:
        return run_quality_judge(state, deep_json, config=config)

    def _node_dread_validator(state: ThreatModelState) -> dict:
        if _skip_dread:
            logger.info("[DREAD Validator] Skipped (skip_dread_validator=True)")
            return {}
        return run_dread_validator(state, stride_json, config=config)

    def _node_hallucination_detector(state: ThreatModelState) -> dict:
        return run_hallucination_detection(state)

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
                "[%s] Waiting for analyst slot (active_slots<=%d)...",
                name, max_concurrent,
            )
            _analyst_sem.acquire()
            try:
                logger.info("[%s] Analyst slot acquired -- starting", name)
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
    node_architecture_parser  = _safe_node(_node_architecture_parser, "architecture_parser")
    node_arch_clarifier      = _safe_node(_node_arch_clarifier,      "arch_clarifier")
    node_architecture_review = _safe_node(_node_architecture_reviewer, "architecture_reviewer")
    node_stride              = _safe_node(_node_stride, "stride_analyst")
    node_pasta               = _safe_node(_node_pasta, "pasta_analyst")
    node_attack_tree         = _safe_node(_node_attack_tree, "attack_tree_analyst")
    node_maestro             = _safe_node(_node_maestro, "maestro_analyst")
    node_ai_threat           = _safe_node(_node_ai_threat, "ai_threat_analyst")
    node_red_team            = _safe_node(_node_red_team, "red_team")
    node_blue_team           = _safe_node(_node_blue_team, "blue_team")
    node_attack_tree_enriched = _safe_node(_node_attack_tree_enriched, "attack_tree_enriched")
    node_synthesizer         = _safe_node(_node_synthesizer, "threat_synthesizer")
    node_quality_judge       = _safe_node(_node_quality_judge, "quality_judge")
    node_dread_validator     = _safe_node(_node_dread_validator, "dread_validator")
    node_hallucination_det   = _safe_node(_node_hallucination_detector, "hallucination_detector")
    node_output_localizer    = _safe_node(_node_output_localizer, "output_localizer")
    node_report              = _safe_node(_node_report, "report_generator")

    # -- Conditional edges --
    max_rounds = config.pipeline.max_debate_rounds

    def _debate_novelty_score(debate_history: list, current_round: int) -> float:
        """Score how much novelty the latest round added (0.0 = fully repetitive, 1.0 = entirely new).

        Compares the latest red+blue arguments against all previous ones
        using word-level Jaccard overlap as a lightweight semantic proxy.
        """
        if len(debate_history) < 4:
            return 1.0  # Too early to judge repetition

        def _extract_text(entry) -> str:
            if isinstance(entry, dict):
                return (entry.get("argument") or "").lower()
            return (getattr(entry, "argument", "") or "").lower()

        def _word_set(text: str) -> set:
            return set(text.split()) - {"the", "a", "an", "is", "are", "of", "in", "to", "and", "or", "for"}

        # Latest round = last 2 entries; previous rounds = everything before
        latest = " ".join(_extract_text(e) for e in debate_history[-2:])
        previous = " ".join(_extract_text(e) for e in debate_history[:-2])

        latest_words = _word_set(latest)
        prev_words = _word_set(previous)

        if not latest_words:
            return 0.0

        overlap = latest_words & prev_words
        jaccard = len(overlap) / len(latest_words | prev_words) if (latest_words | prev_words) else 1.0

        novelty = 1.0 - jaccard
        return round(novelty, 3)

    def _debate_coverage_score(state: ThreatModelState, debate_history: list) -> float:
        """Score whether the debate is covering STRIDE categories that analysts missed.

        Returns 0.0-1.0 where higher means the debate is filling gaps.
        """
        stride_chars = set("STRIDEA")
        covered_in_reports = set()
        for report in state.get("methodology_reports", []):
            text = (report.get("report") if isinstance(report, dict) else str(report)).upper()
            for c in stride_chars:
                if c in text:
                    covered_in_reports.add(c)

        covered_in_debate = set()
        for entry in debate_history:
            text = (_extract_argument(entry)).upper()
            for c in stride_chars:
                if c in text:
                    covered_in_debate.add(c)

        new_coverage = covered_in_debate - covered_in_reports
        return min(len(new_coverage) / 3.0, 1.0)

    def _extract_argument(entry) -> str:
        if isinstance(entry, dict):
            return entry.get("argument", "")
        return getattr(entry, "argument", "")

    # Track consecutive low-novelty rounds for termination
    _low_novelty_consecutive = [0]
    _NOVELTY_THRESHOLD = 0.15

    def should_continue_debate(state: ThreatModelState) -> Literal["red_team", "attack_tree_enriched"]:
        """Debate judge: decide whether to continue based on novelty and coverage scoring.

        Replaces keyword-based [CONVERGENCIA] with quantitative analysis of:
        - Novelty: how many new concepts the latest round introduced
        - Coverage: whether the debate is filling STRIDE category gaps
        - Repetition: consecutive low-novelty rounds trigger termination
        """
        current_round = state.get("debate_round", 1)
        effective_max = state.get("max_debate_rounds", max_rounds)
        debate_history = state.get("debate_history", [])

        logger.debug(
            "[DebateJudge] Evaluating: round=%d, max=%d, history_len=%d",
            current_round, effective_max, len(debate_history),
        )

        # ── Safety valve: empty or stalled history ──
        if not debate_history:
            logger.warning("[DebateJudge] debate_history is empty, exiting debate loop")
            return "attack_tree_enriched"

        expected_entries = current_round * 2
        if len(debate_history) < expected_entries - 2:
            logger.warning(
                "[DebateJudge] debate_history has %d entries but expected ~%d for round %d, exiting",
                len(debate_history), expected_entries, current_round,
            )
            return "attack_tree_enriched"

        if current_round > effective_max:
            logger.info("[DebateJudge] Cap reached at round %d (max=%d), stopping", current_round - 1, effective_max)
            return "attack_tree_enriched"

        # ── Minimum-round guard (at least 2 full exchanges) ──
        MIN_DEBATE_ROUNDS = 2
        if current_round <= MIN_DEBATE_ROUNDS:
            return "red_team"

        # ── Score the latest round ──
        novelty = _debate_novelty_score(debate_history, current_round)
        coverage = _debate_coverage_score(state, debate_history)

        # Legacy convergence signal still honored as hard stop
        last_red = next(
            (e for e in reversed(debate_history)
             if (e.get("side") if isinstance(e, dict) else getattr(e, "side", "")) == "red"),
            None,
        )
        if last_red is not None:
            last_arg = _extract_argument(last_red)
            if "[CONVERGENCIA]" in last_arg or "[CONVERGED]" in last_arg:
                logger.info("[DebateJudge] Explicit convergence signal at round %d", current_round - 1)
                return "attack_tree_enriched"

        # ── Dynamic termination: 2 consecutive low-novelty rounds ──
        if novelty < _NOVELTY_THRESHOLD:
            _low_novelty_consecutive[0] += 1
        else:
            _low_novelty_consecutive[0] = 0

        logger.info(
            "[DebateJudge] round=%d novelty=%.3f coverage=%.3f consecutive_low=%d",
            current_round - 1, novelty, coverage, _low_novelty_consecutive[0],
        )

        if _low_novelty_consecutive[0] >= 2:
            logger.info(
                "[DebateJudge] 2 consecutive low-novelty rounds (%.3f < %.3f), stopping debate",
                novelty, _NOVELTY_THRESHOLD,
            )
            _low_novelty_consecutive[0] = 0  # Reset for next analysis
            return "attack_tree_enriched"

        return "red_team"

    # -- Build the graph --
    graph = StateGraph(ThreatModelState)

    # Phase I: Ingestion
    graph.add_node("architecture_parser", node_architecture_parser)
    graph.add_node("arch_clarifier", node_arch_clarifier)

    # Phase I.5: Architecture Review (pre-analysis intelligence)
    graph.add_node("architecture_reviewer", node_architecture_review)

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

    # Phase IV: Synthesis + Quality Judge + Validation + Hallucination Detection + Output
    graph.add_node("threat_synthesizer", node_synthesizer)
    graph.add_node("quality_judge", node_quality_judge)
    graph.add_node("dread_validator", node_dread_validator)
    graph.add_node("hallucination_detector", node_hallucination_det)
    graph.add_node("output_localizer", node_output_localizer)
    graph.add_node("report_generator", node_report)

    # -- Edges --

    # Entry point
    graph.set_entry_point("architecture_parser")

    def should_clarify(state: ThreatModelState) -> Literal["arch_clarifier", "analysts"]:
        """Decide if the reviewer needs clarification before analyst execution."""
        if state.get("clarification_needed") and not state.get("user_answers"):
            return "arch_clarifier"
        return "analysts"

    def _make_activation_gate(target_node: str):
        """Create a uniquely named branch predicate for parallel analyst fan-out."""
        def _gate(state: ThreatModelState) -> Literal["active", "skip"]:
            if not state.get("clarification_needed") or state.get("user_answers"):
                return "active"
            return "skip"

        _gate.__name__ = f"activate_{target_node}"
        return _gate

    # Phase I -> Phase I.5
    graph.add_edge("architecture_parser", "architecture_reviewer")

    # After reviewer, either pause for clarification or continue to analysts
    graph.add_conditional_edges(
        "architecture_reviewer",
        should_clarify,
        {
            "arch_clarifier": "arch_clarifier",
            "analysts": "stride_analyst",
        },
    )

    # After clarification, stop and wait for user
    graph.add_edge("arch_clarifier", END)

    # The node analysts fan into — either debate (red_team) or directly to
    # attack_tree_enriched when debate is skipped.
    _fan_in_target = "attack_tree_enriched" if _skip_debate else "red_team"

    # Phase I.5 -> Phase II — architecture_reviewer fans out to analysts
    if execution_mode == "cascade":
        # Sequential chain starting after the reviewer gate
        graph.add_edge("stride_analyst",        "pasta_analyst")
        graph.add_edge("pasta_analyst",         "attack_tree_analyst")
        graph.add_edge("attack_tree_analyst",   "maestro_analyst")
        graph.add_edge("maestro_analyst",       "ai_threat_analyst")
        graph.add_edge("ai_threat_analyst",     _fan_in_target)
        logger.info("[Graph] Cascade edges: reviewer->stride->pasta->attack_tree->maestro->ai->%s", _fan_in_target)
    else:
        # Parallel: fan-out starts after the reviewer/clarification gate

        graph.add_conditional_edges(
            "architecture_reviewer",
            _make_activation_gate("pasta_analyst"),
            {
                "active": "pasta_analyst",
                "skip": END
            }
        )
        graph.add_conditional_edges(
            "architecture_reviewer",
            _make_activation_gate("attack_tree_analyst"),
            {
                "active": "attack_tree_analyst",
                "skip": END
            }
        )
        graph.add_conditional_edges(
            "architecture_reviewer",
            _make_activation_gate("maestro_analyst"),
            {
                "active": "maestro_analyst",
                "skip": END
            }
        )
        graph.add_conditional_edges(
            "architecture_reviewer",
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

    # Phase IV -> Quality Judge (MAR) -> conditional retry or DREAD Validator
    _max_validation = config.pipeline.max_validation_iterations

    graph.add_edge("threat_synthesizer", "quality_judge")

    def _should_retry(state: ThreatModelState) -> Literal["threat_synthesizer", "dread_validator"]:
        return should_retry_synthesis(state, max_iterations=_max_validation)

    graph.add_conditional_edges(
        "quality_judge",
        _should_retry,
        {
            "threat_synthesizer": "threat_synthesizer",
            "dread_validator": "dread_validator",
        },
    )

    # DREAD Validator -> Hallucination Detector -> Output -> END
    graph.add_edge("dread_validator", "hallucination_detector")
    graph.add_edge("hallucination_detector", "output_localizer")
    graph.add_edge("output_localizer", "report_generator")
    graph.add_edge("report_generator", END)

    logger.info("[Graph] AgenticTM graph built -- %d nodes", len(graph.nodes))
    return graph


def compile_graph(
    config: AgenticTMConfig,
    llm_factory: LLMFactory,
    checkpointer=None,
):
    """Build and compile the graph, ready to execute.

    Args:
        config: AgenticTM configuration.
        llm_factory: LLM factory instance.
        checkpointer: Optional LangGraph checkpointer for pipeline resume.
            When provided, enables resume-after-failure and HITL interrupt.
            Use ``langgraph.checkpoint.sqlite.SqliteSaver`` for development
            or ``langgraph.checkpoint.postgres.PostgresSaver`` for production.
    """
    graph = build_graph(config, llm_factory)
    if checkpointer is None:
        checkpointer = _default_checkpointer(config)
    return graph.compile(checkpointer=checkpointer)


def _default_checkpointer(config: AgenticTMConfig):
    """Create a default SQLite checkpointer if the memory system is enabled."""
    if not config.memory.enabled:
        return None
    try:
        from langgraph.checkpoint.sqlite import SqliteSaver
        import sqlite3
        db_dir = config.memory.db_path.parent
        db_dir.mkdir(parents=True, exist_ok=True)
        checkpoint_path = db_dir / "checkpoints.db"
        conn = sqlite3.connect(str(checkpoint_path), check_same_thread=False)
        saver = SqliteSaver(conn)
        logger.info("[Graph] SQLite checkpointer enabled: %s", checkpoint_path)
        return saver
    except ImportError:
        logger.debug("[Graph] langgraph.checkpoint.sqlite not available, running without checkpointing")
        return None
    except Exception as exc:
        logger.warning("[Graph] Checkpointer init failed (non-fatal): %s", exc)
        return None
