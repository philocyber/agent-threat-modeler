"""Threat category mapping and filtering for RAG context.

Categorizes threats/controls from risks_mitigations store by technology
domain so the pipeline can filter relevant context based on the project
type (AWS, Azure, GCP, AI, Mobile, IoT, Web, etc.).

The 'base' category is ALWAYS included — it covers generic threats like
STRIDE, memory, auth, crypto, MITRE ATT&CK phases, etc.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Category keyword mappings — used both for classification AND auto-detection
# ---------------------------------------------------------------------------

CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "aws": [
        "aws", "amazon", "ec2", "s3", "lambda", "rds", "dynamodb",
        "cloudfront", "cloudwatch", "cloudtrail", "iam", "kms",
        "eks", "ecr", "elb", "api gateway", "bedrock", "sagemaker",
        "secretsmanager", "secrets manager", "waf",
    ],
    "azure": [
        "azure", "microsoft", "entra", "entra id", "aks",
        "app service", "keyvault", "sql server", "monitor",
        "defender", "function", "vmss", "virtual machine",
    ],
    "gcp": [
        "gcp", "google cloud", "compute engine", "cloud run",
        "cloud sql", "cloud logging", "gke", "iam",
        "secret manager", "cloud function",
    ],
    "ai": [
        "ai", "ml", "llm", "model", "gpt", "agent", "agentic",
        "rag", "vector", "embedding", "neural", "prompt",
        "inference", "training", "langchain", "langgraph",
        "ollama", "openai", "anthropic", "transformer", "chatbot",
        "nlp", "hallucination", "poisoning", "drift",
        "plot4ai", "maestro", "data quality", "bias", "fairness",
        "explainability", "generative",
    ],
    "mobile": [
        "mobile", "ios", "android", "apk", "ipa", "cordova",
        "react native", "flutter", "swift", "kotlin", "nfc",
        "biometric", "fingerprint", "face id",
    ],
    "web": [
        "web", "browser", "frontend", "react", "angular", "vue",
        "spa", "xss", "csrf", "cors", "cookie", "session",
        "javascript", "html", "css", "http", "https",
    ],
    "iot": [
        "iot", "sensor", "firmware", "embedded", "uart", "jtag",
        "mqtt", "coap", "zigbee", "bluetooth", "ble",
        "signal jamming", "physical",
    ],
    "privacy": [
        "privacy", "gdpr", "hipaa", "pii", "personal data",
        "data protection", "dpo", "retention", "anonymi",
        "pseudonymiz", "consent", "data subject",
    ],
    "supply_chain": [
        "supply chain", "third-party", "vendor", "dependency",
        "package", "npm", "pip", "typosquat", "sbom",
    ],
}

# ---------------------------------------------------------------------------
# Auto-detect categories from system description
# ---------------------------------------------------------------------------


def detect_categories(system_description: str) -> list[str]:
    """Auto-detect threat categories from the system description.

    Uses a weighted scoring system: each keyword match within a category
    earns 1 point.  A category is activated only when it reaches a
    minimum threshold of matches, preventing false positives from generic
    terms that appear across many domains.

    Always includes 'base'. Returns sorted unique list.
    """
    if isinstance(system_description, dict):
        import json as _json
        system_description = _json.dumps(system_description, ensure_ascii=False)
    text = str(system_description).lower()
    detected = {"base"}

    # Minimum keyword hits required per category
    # (categories with very distinctive keywords can use lower thresholds)
    _THRESHOLDS: dict[str, int] = {
        "aws": 2,     # "iam" alone is ambiguous
        "azure": 2,
        "gcp": 2,
        "ai": 2,      # "model" alone is too generic
        "mobile": 2,
        "web": 2,      # "http" alone is too generic
        "iot": 2,
        "privacy": 2,
        "supply_chain": 2,
    }

    for category, keywords in CATEGORY_KEYWORDS.items():
        hits = sum(1 for kw in keywords if kw in text)
        threshold = _THRESHOLDS.get(category, 2)
        if hits >= threshold:
            detected.add(category)

    logger.info(
        "🏷️  Categorías detectadas automáticamente: %s",
        ", ".join(sorted(detected)),
    )
    return sorted(detected)


def resolve_categories(
    configured: list[str],
    system_description: str = "",
) -> list[str]:
    """Resolve category list from config + optional auto-detection.

    If configured contains 'auto', auto-detects from system_description.
    Always includes 'base'.
    """
    if "auto" in configured:
        return detect_categories(system_description)

    result = set(configured) | {"base"}
    return sorted(result)


# ---------------------------------------------------------------------------
# Classify a threat/control ID into categories
# ---------------------------------------------------------------------------

# Compiled regex for ID-based classification
_AWS_ID_RE = re.compile(r"\bAWS\b", re.IGNORECASE)
_AZURE_ID_RE = re.compile(r"\bAzure|Microsoft|Entra\b", re.IGNORECASE)
_GCP_ID_RE = re.compile(r"\bGCP\b", re.IGNORECASE)


def classify_threat(title: str, description: str = "") -> set[str]:
    """Classify a threat/control into categories based on its text content.

    Returns set of categories. 'base' means it's generic/universal.
    """
    text = f"{title} {description}".lower()
    matched: set[str] = set()

    for category, keywords in CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                matched.add(category)
                break

    # If no specific category matched → it's base
    if not matched:
        matched.add("base")

    return matched


def filter_threats_by_categories(
    threats: list[dict],
    active_categories: list[str],
) -> list[dict]:
    """Filter a list of threat/control dicts to only those matching active categories.

    Each threat dict should have at minimum 'Title' and optionally 'Description'.
    """
    result = []
    active = set(active_categories) | {"base"}

    for t in threats:
        title = t.get("Title", t.get("title", t.get("label", "")))
        desc = t.get("Description", t.get("description", t.get("explanation", "")))
        categories = classify_threat(title, desc)

        if categories & active:
            result.append(t)

    return result
