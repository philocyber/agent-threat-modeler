"""Threat Synthesizer subpackage — Phase III: Final synthesis.

Re-exports the main entry point and key constants used by other modules.
"""

from agentictm.agents.synthesis.orchestrator import run_threat_synthesizer
from agentictm.agents.synthesis.classification import _STRIDE_TO_CATEGORY

__all__ = ["run_threat_synthesizer", "_STRIDE_TO_CATEGORY"]
