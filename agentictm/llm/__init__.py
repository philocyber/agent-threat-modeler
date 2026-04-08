"""LLM client factory — Ollama-first with optional cloud fallback."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from langchain_ollama import ChatOllama

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel
    from agentictm.config import LLMConfig


def create_llm(cfg: LLMConfig, *, format_override: str | None = None) -> BaseChatModel:
    """Create an LLM client based on the configured provider.

    Supported providers:
      - "ollama"     → ChatOllama (local, default)
      - "anthropic"  → ChatAnthropic (requires langchain-anthropic)
      - "google"     → ChatGoogleGenerativeAI (requires langchain-google-genai)
      - "openai"     → ChatOpenAI (requires langchain-openai)
      - "azure"      → AzureChatOpenAI (requires langchain-openai)

    Args:
        format_override: Override the config format (e.g. "json" for structured output).
    """
    fmt = format_override or cfg.format
    if cfg.provider == "ollama":
        kwargs: dict = dict(
            model=cfg.model,
            temperature=cfg.temperature,
            base_url=cfg.base_url,
        )
        if fmt:
            kwargs["format"] = fmt
        # Pass timeout through client_kwargs (ChatOllama doesn't accept timeout directly)
        client_kw: dict = {}
        if cfg.timeout:
            client_kw["timeout"] = float(cfg.timeout)
        if client_kw:
            kwargs["client_kwargs"] = client_kw
        # GPU layer control (None = Ollama auto, -1 = all GPU, 0 = all CPU)
        if cfg.num_gpu is not None:
            kwargs["num_gpu"] = cfg.num_gpu
        # Context window control — reduce KV cache memory on constrained hardware
        if cfg.num_ctx is not None:
            kwargs["num_ctx"] = cfg.num_ctx
        # Max generation tokens — prevents runaway output
        if cfg.num_predict is not None:
            kwargs["num_predict"] = cfg.num_predict
        # Thinking mode control for qwen3/deepseek-r1 (config "think" -> ChatOllama "reasoning")
        if cfg.think is not None:
            kwargs["reasoning"] = cfg.think
        return ChatOllama(**kwargs)

    if cfg.provider == "anthropic":
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError as exc:
            python_bin = sys.executable
            raise ImportError(
                "Missing dependency for provider 'anthropic': langchain-anthropic.\n"
                f"Install it in the same interpreter used by the backend:\n"
                f"  {python_bin} -m pip install langchain-anthropic"
            ) from exc
        return ChatAnthropic(
            model=cfg.model,
            temperature=cfg.temperature,
            api_key=cfg.api_key,
            timeout=float(cfg.timeout),
            max_retries=cfg.max_retries,
        )

    if cfg.provider == "google":
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
        except ImportError as exc:
            raise ImportError(
                "pip install langchain-google-genai  to use provider 'google'"
            ) from exc
        return ChatGoogleGenerativeAI(
            model=cfg.model,
            temperature=cfg.temperature,
            google_api_key=cfg.api_key,
            max_retries=cfg.max_retries,
        )

    if cfg.provider == "openai":
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as exc:
            raise ImportError(
                "pip install langchain-openai  to use provider 'openai'"
            ) from exc
        kw: dict = dict(
            model=cfg.model,
            temperature=cfg.temperature,
            api_key=cfg.api_key,
            timeout=float(cfg.timeout),
            max_retries=cfg.max_retries,
        )
        if fmt == "json":
            kw["model_kwargs"] = {"response_format": {"type": "json_object"}}
        return ChatOpenAI(**kw)

    if cfg.provider == "azure":
        try:
            from langchain_openai import AzureChatOpenAI
        except ImportError as exc:
            raise ImportError(
                "pip install langchain-openai  to use provider 'azure'"
            ) from exc
        return AzureChatOpenAI(
            azure_deployment=cfg.model,
            temperature=cfg.temperature,
            api_key=cfg.api_key,
            azure_endpoint=cfg.base_url,
            api_version="2024-06-01",
            timeout=float(cfg.timeout),
            max_retries=cfg.max_retries,
        )

    raise ValueError(f"Unsupported LLM provider: {cfg.provider}")


class LLMFactory:
    """Factory that caches LLM instances by config hash."""

    def __init__(self, quick_cfg: LLMConfig | object, deep_cfg: LLMConfig | None = None,
                 vlm_cfg: LLMConfig | None = None, stride_cfg: LLMConfig | None = None):
        # Backward-compatible constructor: allow passing AgenticTMConfig directly.
        if deep_cfg is None and vlm_cfg is None and hasattr(quick_cfg, "quick_thinker"):
            config = quick_cfg
            quick_cfg = getattr(config, "quick_thinker")
            deep_cfg = getattr(config, "deep_thinker")
            vlm_cfg = getattr(config, "vlm")
            stride_cfg = getattr(config, "stride_thinker", None)

        if deep_cfg is None or vlm_cfg is None:
            raise TypeError("LLMFactory requires quick, deep, and vlm configs")

        self._quick_cfg = quick_cfg
        self._deep_cfg = deep_cfg
        self._vlm_cfg = vlm_cfg
        self._stride_cfg = stride_cfg or deep_cfg  # fallback to deep if not configured
        self._cache: dict[str, BaseChatModel] = {}

    def _get_or_create(self, key: str, cfg: LLMConfig, *, format_override: str | None = None) -> BaseChatModel:
        if key not in self._cache:
            self._cache[key] = create_llm(cfg, format_override=format_override)
        return self._cache[key]

    @property
    def quick(self) -> BaseChatModel:
        """Fast LLM for analysts."""
        return self._get_or_create("quick", self._quick_cfg)

    @property
    def quick_json(self) -> BaseChatModel:
        """Fast LLM with format=json for agents producing structured JSON."""
        return self._get_or_create("quick_json", self._quick_cfg, format_override="json")

    @property
    def deep(self) -> BaseChatModel:
        """More capable LLM for Threat Synthesizer and validation."""
        return self._get_or_create("deep", self._deep_cfg)

    @property
    def deep_json(self) -> BaseChatModel:
        """Deep LLM with format=json for Synthesizer and DREAD Validator."""
        return self._get_or_create("deep_json", self._deep_cfg, format_override="json")

    @property
    def stride(self) -> BaseChatModel:
        """LLM for STRIDE analysis + debate (tool-capable model)."""
        return self._get_or_create("stride", self._stride_cfg)

    @property
    def stride_json(self) -> BaseChatModel:
        """LLM for STRIDE analysis with JSON output."""
        return self._get_or_create("stride_json", self._stride_cfg, format_override="json")

    @property
    def vlm(self) -> BaseChatModel:
        """Vision Language Model for image parsing."""
        return self._get_or_create("vlm", self._vlm_cfg)
