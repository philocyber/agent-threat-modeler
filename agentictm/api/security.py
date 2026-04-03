"""Security middleware — prompt injection detection & rate limiting.

Provides two FastAPI-compatible components:

1. ``check_prompt_injection(text)`` — scans user input for common prompt
   injection patterns and returns a sanitised version with warning metadata.

2. ``RateLimiter`` — simple in-memory sliding-window rate limiter keyed by
   API key or client IP.  Designed for single-instance deployments; swap
   for Redis-backed implementation for multi-instance.
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt Injection Detection
# ---------------------------------------------------------------------------

# Patterns that indicate prompt injection attempts.
# Each tuple is (compiled_regex, human_readable_label, severity).
_INJECTION_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Direct instruction override attempts
    (re.compile(r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|rules?)", re.I),
     "instruction_override", "high"),
    (re.compile(r"disregard\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?)", re.I),
     "instruction_override", "high"),
    (re.compile(r"forget\s+(everything|all|your)\s+(you|instructions?|rules?|above)", re.I),
     "instruction_override", "high"),

    # Role-play / persona hijacking
    (re.compile(r"you\s+are\s+now\s+(a|an|acting\s+as|pretending)", re.I),
     "persona_hijack", "high"),
    (re.compile(r"act\s+as\s+(if|though|a)\s+", re.I),
     "persona_hijack", "medium"),
    (re.compile(r"pretend\s+(you\s+are|to\s+be|that)", re.I),
     "persona_hijack", "medium"),

    # System prompt extraction
    (re.compile(r"(show|reveal|print|output|display|repeat)\s+(your|the|system)\s+(system\s+)?(prompt|instructions?|rules?)", re.I),
     "prompt_extraction", "high"),
    (re.compile(r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|rules?)", re.I),
     "prompt_extraction", "medium"),

    # Delimiter / encoding attacks
    (re.compile(r"```\s*(system|assistant|user)\s*\n", re.I),
     "delimiter_attack", "high"),
    (re.compile(r"\[SYSTEM\]|\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>", re.I),
     "chat_template_injection", "high"),
    (re.compile(r"<\|system\|>|<\|user\|>|<\|assistant\|>", re.I),
     "chat_template_injection", "high"),

    # Output manipulation
    (re.compile(r"(instead|rather)\s+of\s+(analyzing|doing|performing)\s+(the|a|an)?", re.I),
     "output_manipulation", "medium"),
    (re.compile(r"do\s+not\s+(analyze|perform|run|execute)\s+(the|a|an)?\s*(threat|security|analysis)", re.I),
     "output_manipulation", "high"),

    # Data exfiltration
    (re.compile(r"(send|post|fetch|curl|wget|http)\s+.*(api|endpoint|url|webhook)", re.I),
     "exfiltration_attempt", "high"),
]

# Strings to strip from input (sanitisation, not detection)
_SANITISE_PATTERNS: list[re.Pattern] = [
    # Strip chat template markers
    re.compile(r"<\|(?:im_start|im_end|system|user|assistant)\|>", re.I),
    re.compile(r"\[(?:SYSTEM|INST|/INST)\]", re.I),
    # Strip HTML script tags (potential XSS in reports)
    re.compile(r"<script[^>]*>.*?</script>", re.I | re.DOTALL),
]


@dataclass
class InjectionScanResult:
    """Result of scanning user input for prompt injection."""
    is_suspicious: bool = False
    detections: list[dict[str, str]] = field(default_factory=list)
    sanitised_text: str = ""
    risk_level: str = "none"  # none | low | medium | high


def check_prompt_injection(text: str) -> InjectionScanResult:
    """Scan user-provided text for prompt injection patterns.

    Returns an ``InjectionScanResult`` with:
    - ``is_suspicious``: whether any patterns matched
    - ``detections``: list of matched pattern labels and severities
    - ``sanitised_text``: input with dangerous markers stripped
    - ``risk_level``: highest severity found (none/low/medium/high)
    """
    result = InjectionScanResult(sanitised_text=text)
    severity_order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    max_severity = "none"

    for pattern, label, severity in _INJECTION_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            result.is_suspicious = True
            result.detections.append({
                "pattern": label,
                "severity": severity,
                "match_count": len(matches),
            })
            if severity_order.get(severity, 0) > severity_order.get(max_severity, 0):
                max_severity = severity

    result.risk_level = max_severity

    # Sanitise: strip dangerous markers regardless of whether injection was detected
    sanitised = text
    for pat in _SANITISE_PATTERNS:
        sanitised = pat.sub("", sanitised)
    result.sanitised_text = sanitised.strip()

    if result.is_suspicious:
        logger.warning(
            "[Security] Prompt injection detected — risk=%s patterns=%s input_length=%d",
            result.risk_level,
            [d["pattern"] for d in result.detections],
            len(text),
        )

    return result


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """In-memory sliding-window rate limiter.

    Args:
        max_requests: Maximum requests allowed in the window.
        window_seconds: Window duration in seconds.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    def _client_key(self, request: Request) -> str:
        """Extract rate-limit key: API key if present, else client IP."""
        api_key = request.headers.get("x-api-key")
        if api_key:
            return f"key:{api_key[:16]}"
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return f"ip:{forwarded.split(',')[0].strip()}"
        client = request.client
        return f"ip:{client.host}" if client else "ip:unknown"

    def _cleanup(self, key: str) -> None:
        """Remove timestamps outside the current window."""
        cutoff = time.time() - self.window_seconds
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]

    def check(self, request: Request) -> dict[str, Any]:
        """Check rate limit for the given request.

        Returns metadata dict with remaining quota.
        Raises HTTPException(429) if limit exceeded.
        """
        key = self._client_key(request)
        self._cleanup(key)

        timestamps = self._requests[key]

        if len(timestamps) >= self.max_requests:
            oldest = min(timestamps) if timestamps else time.time()
            retry_after = int(oldest + self.window_seconds - time.time()) + 1
            logger.warning(
                "[RateLimiter] Limit exceeded for %s (%d/%d in %ds)",
                key, len(timestamps), self.max_requests, self.window_seconds,
            )
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded. Max {self.max_requests} analyses per {self.window_seconds}s. Retry after {retry_after}s.",
                headers={"Retry-After": str(retry_after)},
            )

        timestamps.append(time.time())

        return {
            "remaining": self.max_requests - len(timestamps),
            "limit": self.max_requests,
            "window_seconds": self.window_seconds,
        }


# Singleton — configured via environment or defaults
# 10 analysis requests per hour per API key/IP
_analysis_limiter = RateLimiter(max_requests=10, window_seconds=3600)


def get_analysis_limiter() -> RateLimiter:
    """Get the global analysis rate limiter instance."""
    return _analysis_limiter
