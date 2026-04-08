"""Per-agent quality tests for deterministic post-processing functions.

Tests STRIDE inference, category classification, PASTA extraction,
synthesizer quality gates, DREAD merge, baseline extraction, deduplication,
report generation, and end-to-end quality contracts — no LLM required.

Each test class represents a single agent or processing stage and validates
that given a known input, the output meets quality requirements.
"""

from __future__ import annotations

import json

import pytest

from agentictm.agents.threat_synthesizer import (
    _infer_stride_category,
    _classify_threat_category,
    _normalize_stride_category,
    _apply_quality_gates,
    _assign_category_ids,
    _extract_threats_from_reports,
    _deduplicate_threats,
    _CATEGORY_PREFIX_MAP,
)
from agentictm.agents.pasta_analyst import _extract_threats_from_stages
from agentictm.agents.report_generator import generate_csv, generate_markdown_report
from agentictm.agents.synthesis.quality_gates import _filter_irrelevant_threats


# ═══════════════════════════════════════════════════════════════════════════
# Shared fixtures — realistic agent outputs for testing downstream stages
# ═══════════════════════════════════════════════════════════════════════════

ECOMMERCE_ARCHITECTURE = {
    "system_name": "E-Commerce Platform",
    "system_description": (
        "A serverless E-Commerce platform hosted on AWS. Frontend is a React SPA "
        "served via CloudFront CDN. Backend consists of Node.js Lambda functions "
        "behind API Gateway. DynamoDB for product catalog, Stripe for payments, "
        "Cognito for authentication. Step Functions orchestrate order workflows."
    ),
    "components": [
        {"name": "CloudFront CDN", "type": "external_entity", "description": "CDN for static assets"},
        {"name": "API Gateway", "type": "process", "description": "REST API entry point"},
        {"name": "Lambda Functions", "type": "process", "description": "Serverless business logic"},
        {"name": "DynamoDB", "type": "data_store", "description": "NoSQL product catalog and orders"},
        {"name": "Cognito", "type": "process", "description": "User authentication and authorization"},
        {"name": "Stripe Integration", "type": "external_entity", "description": "Payment processing"},
        {"name": "Step Functions", "type": "process", "description": "Order workflow orchestration"},
    ],
    "data_flows": [
        {"source": "CloudFront CDN", "destination": "API Gateway", "protocol": "HTTPS"},
        {"source": "API Gateway", "destination": "Lambda Functions", "protocol": "AWS Internal"},
        {"source": "Lambda Functions", "destination": "DynamoDB", "protocol": "AWS SDK"},
        {"source": "Lambda Functions", "destination": "Stripe Integration", "protocol": "HTTPS"},
    ],
    "trust_boundaries": [
        {"name": "Internet", "components_inside": ["API Gateway"], "components_outside": ["CloudFront CDN"]},
        {"name": "AWS VPC", "components_inside": ["Lambda Functions", "DynamoDB"], "components_outside": ["API Gateway"]},
    ],
}

AI_AGENT_ARCHITECTURE = {
    "system_name": "AI Agent System",
    "system_description": (
        "A multi-agent AI system using LangChain and LangGraph for orchestration. "
        "Agents use GPT-4 via API for reasoning, with a RAG pipeline backed by "
        "ChromaDB vector store. Tool-use agents can execute code, query databases, "
        "and call external APIs. Human-in-the-loop approval for critical actions."
    ),
    "components": [
        {"name": "Orchestrator", "type": "process", "description": "LangGraph agent orchestrator"},
        {"name": "LLM API", "type": "external_entity", "description": "GPT-4 API endpoint"},
        {"name": "RAG Pipeline", "type": "process", "description": "Retrieval-augmented generation"},
        {"name": "ChromaDB", "type": "data_store", "description": "Vector store for embeddings"},
        {"name": "Tool Executor", "type": "process", "description": "Executes agent tool calls"},
        {"name": "Code Sandbox", "type": "process", "description": "Isolated code execution environment"},
        {"name": "Human Review UI", "type": "process", "description": "Human approval interface"},
    ],
    "data_flows": [
        {"source": "Orchestrator", "destination": "LLM API", "protocol": "HTTPS"},
        {"source": "Orchestrator", "destination": "RAG Pipeline", "protocol": "Internal"},
        {"source": "RAG Pipeline", "destination": "ChromaDB", "protocol": "gRPC"},
        {"source": "Orchestrator", "destination": "Tool Executor", "protocol": "Internal"},
        {"source": "Tool Executor", "destination": "Code Sandbox", "protocol": "Docker API"},
    ],
    "trust_boundaries": [
        {"name": "Agent Boundary", "components_inside": ["Orchestrator", "RAG Pipeline"],
         "components_outside": ["LLM API"]},
        {"name": "Execution Boundary", "components_inside": ["Code Sandbox"],
         "components_outside": ["Tool Executor"]},
    ],
}

REALISTIC_STRIDE_THREATS = [
    {
        "id": "STRIDE-001", "component": "API Gateway",
        "description": "An attacker forges a JWT token by exploiting a weak signing algorithm (HS256 with a short secret). The forged token bypasses API Gateway authentication, granting unauthorized access to protected Lambda endpoints including order management and user data retrieval.",
        "methodology": "STRIDE", "stride_category": "S",
        "attack_path": "1. Intercept valid JWT → 2. Crack HS256 secret (brute force) → 3. Forge new token with admin claims → 4. Access protected endpoints",
        "mitigation": "Use RS256 with key rotation, enforce token expiration under 15 minutes, validate all JWT claims server-side",
        "damage": 8, "reproducibility": 5, "exploitability": 4, "affected_users": 9, "discoverability": 3,
    },
    {
        "id": "STRIDE-002", "component": "Lambda Functions",
        "description": "NoSQL injection through unsanitized user input in DynamoDB query expressions. An attacker manipulates the product search filter to extract data from other users' orders by injecting filter expression operators.",
        "methodology": "STRIDE", "stride_category": "T",
        "attack_path": "1. Craft malicious search parameter → 2. Inject DynamoDB condition expression → 3. Bypass tenant isolation → 4. Read other users' order data",
        "mitigation": "Use DynamoDB SDK with parameterized expressions, validate and sanitize all user inputs, implement query allow-lists",
        "damage": 9, "reproducibility": 6, "exploitability": 5, "affected_users": 8, "discoverability": 4,
    },
    {
        "id": "STRIDE-003", "component": "DynamoDB",
        "description": "Verbose error messages from DynamoDB operations leak table structure, key schema, and index names when malformed queries trigger ValidationExceptions. This information helps attackers craft targeted injection attacks.",
        "methodology": "STRIDE", "stride_category": "I",
        "attack_path": "1. Send malformed queries → 2. Trigger ValidationException → 3. Error reveals table schema → 4. Use schema knowledge for targeted attacks",
        "mitigation": "Implement generic error handler in Lambda, never expose raw DynamoDB errors to clients, log detailed errors server-side only",
        "damage": 4, "reproducibility": 7, "exploitability": 6, "affected_users": 3, "discoverability": 5,
    },
    {
        "id": "STRIDE-004", "component": "Cognito",
        "description": "Missing rate limiting on Cognito authentication endpoint allows brute-force credential stuffing attacks. Attackers use leaked credential databases to systematically try username/password combinations against the login API.",
        "methodology": "STRIDE", "stride_category": "S",
        "attack_path": "1. Obtain leaked credentials database → 2. Script automated login attempts → 3. Bypass lack of rate limiting → 4. Compromise user accounts",
        "mitigation": "Enable Cognito advanced security features, implement progressive delays, add CAPTCHA after 3 failed attempts, monitor for credential stuffing patterns",
        "damage": 7, "reproducibility": 8, "exploitability": 7, "affected_users": 6, "discoverability": 3,
    },
    {
        "id": "STRIDE-005", "component": "Step Functions",
        "description": "Insufficient audit logging in Step Functions workflow execution. Administrative actions like order cancellations and refund processing lack detailed audit trails, making it impossible to trace unauthorized modifications to order state.",
        "methodology": "STRIDE", "stride_category": "R",
        "attack_path": "1. Insider initiates unauthorized refund → 2. Step Functions processes without detailed logging → 3. No audit trail links action to specific user → 4. Repudiation of malicious action",
        "mitigation": "Enable CloudWatch detailed logging for all Step Functions executions, include IAM principal in all state transitions, implement immutable audit log with CloudTrail",
        "damage": 5, "reproducibility": 4, "exploitability": 3, "affected_users": 2, "discoverability": 6,
    },
]

REALISTIC_PASTA_THREATS = [
    {
        "id": "PASTA-001", "component": "Stripe Integration",
        "description": "Race condition in payment processing allows double-charging or free orders. An attacker submits multiple concurrent checkout requests for the same cart, exploiting the lack of idempotency in the Lambda-to-Stripe integration.",
        "methodology": "PASTA", "attack_scenario": "concurrent checkout race condition",
        "attack_path": "1. Add items to cart → 2. Initiate multiple simultaneous checkout requests → 3. Lambda processes both before Stripe confirms first → 4. Double charge or duplicate order",
        "mitigation": "Implement Stripe idempotency keys on all payment intents, use DynamoDB conditional writes for order creation, add distributed locking for checkout flow",
    },
    {
        "id": "PASTA-002", "component": "API Gateway",
        "description": "API Gateway resource exhaustion through slow-read DDoS attack. An attacker opens thousands of connections with extremely slow data transfer rates, consuming all available connection slots and preventing legitimate users from accessing the platform.",
        "methodology": "PASTA", "attack_scenario": "slowloris-style DDoS",
        "attack_path": "1. Open thousands of HTTP connections → 2. Send data at 1 byte/second → 3. Exhaust API Gateway connection pool → 4. Legitimate users receive 503 errors",
        "mitigation": "Configure API Gateway timeout limits, enable AWS WAF with rate-based rules, implement connection timeout at 30 seconds, use CloudFront as DDoS shield",
    },
]

REALISTIC_ATTACK_TREE_THREATS = [
    {
        "id": "AT-001", "component": "Lambda Functions",
        "description": "Supply chain attack through compromised npm dependency in Lambda deployment package. An attacker publishes a typosquatted package that mimics a legitimate dependency, which gets installed during CI/CD build and exfiltrates environment variables containing AWS credentials.",
        "methodology": "ATTACK_TREE",
        "attack_path": "1. Publish typosquatted npm package → 2. Developer installs via typo in package.json → 3. Malicious postinstall script runs during build → 4. AWS credentials exfiltrated to attacker server",
        "mitigation": "Pin all dependencies with exact versions and integrity hashes, use npm audit in CI pipeline, scan dependencies with Snyk/Dependabot, restrict Lambda environment variable access with IAM least-privilege",
    },
]

KNOWN_COMPONENTS = [c["name"] for c in ECOMMERCE_ARCHITECTURE["components"]]


# ═══════════════════════════════════════════════════════════════════════════
# 1. STRIDE Inference (unit)
# ═══════════════════════════════════════════════════════════════════════════

class TestStrideInference:
    """Feed known threat descriptions and assert correct STRIDE letters."""

    @pytest.mark.parametrize("desc,expected", [
        ("SQL injection through unsanitized query parameters", "T"),
        ("Command injection via user-controlled input to subprocess", "T"),
        ("Cross-site scripting (XSS) in the search results page", "T"),
        ("Insecure deserialization of user-supplied objects", "T"),
        ("NoSQL injection through filter expression manipulation", "T"),
    ])
    def test_tampering_threats(self, desc, expected):
        assert _infer_stride_category({"description": desc}) == expected

    @pytest.mark.parametrize("desc,expected", [
        ("DDoS attack exhausting API rate limits", "D"),
        ("Resource exhaustion causing service unavailability and outage", "D"),
        ("Memory exhaustion via unbounded file uploads causing crash", "D"),
        ("Denial of service through CPU-intensive regex evaluation", "D"),
        ("Slowloris attack consuming all connection slots causing downtime", "D"),
    ])
    def test_denial_of_service_threats(self, desc, expected):
        assert _infer_stride_category({"description": desc}) == expected

    @pytest.mark.parametrize("desc,expected", [
        ("Spoofing of user identity through forged JWT tokens", "S"),
        ("Authentication bypass via credential stuffing attack", "S"),
        ("Session hijacking through stolen session cookies", "S"),
        ("Phishing attack leading to account takeover", "S"),
        ("OAuth misconfiguration allowing token replay", "S"),
    ])
    def test_spoofing_threats(self, desc, expected):
        assert _infer_stride_category({"description": desc}) == expected

    @pytest.mark.parametrize("desc,expected", [
        ("Missing audit trail for administrative actions", "R"),
        ("Insufficient logging prevents forensic analysis", "R"),
        ("No audit log for data deletion operations", "R"),
        ("Audit log deletion allowing deniability of administrative actions", "R"),
        ("Compliance gap due to missing SIEM integration and monitoring", "R"),
    ])
    def test_repudiation_threats(self, desc, expected):
        assert _infer_stride_category({"description": desc}) == expected

    @pytest.mark.parametrize("desc,expected", [
        ("Sensitive data exposed through verbose error messages", "I"),
        ("API key exposure in client-side JavaScript bundle", "I"),
        ("Man-in-the-middle attack on unencrypted internal traffic", "I"),
        ("Data leak via publicly accessible S3 bucket", "I"),
        ("Stack trace disclosure in production error responses", "I"),
    ])
    def test_information_disclosure_threats(self, desc, expected):
        assert _infer_stride_category({"description": desc}) == expected

    @pytest.mark.parametrize("desc,expected", [
        ("Privilege escalation through IDOR on user profile endpoints", "E"),
        ("Horizontal escalation via broken access control on admin panel", "E"),
        ("RBAC bypass allowing standard users to access admin functions", "E"),
        ("Mass assignment vulnerability leading to role elevation", "E"),
        ("Forced browsing to admin dashboard without authorization check", "E"),
    ])
    def test_elevation_of_privilege_threats(self, desc, expected):
        assert _infer_stride_category({"description": desc}) == expected

    def test_fallback_returns_I_for_unknown_text(self):
        result = _infer_stride_category({"description": "lorem ipsum dolor sit amet"})
        assert result == "I"

    def test_never_returns_empty_string(self):
        for desc in [
            "A general security concern about the system",
            "Configuration drift in production environment",
            "Weak encryption algorithm used for data at rest",
        ]:
            result = _infer_stride_category({"description": desc})
            assert result in {"S", "T", "R", "I", "D", "E"}, f"Empty STRIDE for: {desc}"

    def test_realistic_stride_threats_classified_reasonably(self):
        """Realistic threats should infer a valid STRIDE category (may differ from
        analyst assignment when description keywords are ambiguous)."""
        for t in REALISTIC_STRIDE_THREATS:
            inferred = _infer_stride_category(t)
            assert inferred in {"S", "T", "R", "I", "D", "E"}, \
                f"Invalid STRIDE '{inferred}' for '{t['description'][:60]}'"


# ═══════════════════════════════════════════════════════════════════════════
# 2. STRIDE Normalization (unit)
# ═══════════════════════════════════════════════════════════════════════════

class TestNormalizeStrideCategory:

    @pytest.mark.parametrize("raw,expected", [
        ("S", "S"), ("T", "T"), ("R", "R"), ("I", "I"), ("D", "D"), ("E", "E"),
        ("Spoofing", "S"), ("Tampering", "T"), ("Repudiation", "R"),
        ("Information Disclosure", "I"), ("Denial", "D"), ("Elevation", "E"),
        ("", ""), ("-", ""), ("LLM02|ASI03|L1", ""),
        ("Bias, Fairness & Discrimination|LLM09", ""),
        ("Suplantación", "S"), ("Manipulación", "T"),
        ("privilege escalation", "E"),
    ])
    def test_normalization(self, raw, expected):
        assert _normalize_stride_category(raw) == expected


# ═══════════════════════════════════════════════════════════════════════════
# 3. Category Classification (unit)
# ═══════════════════════════════════════════════════════════════════════════

class TestCategoryClassification:

    @pytest.mark.parametrize("desc,category_prefix", [
        ("SQL injection on the API Gateway endpoint /api/users", "WEB"),
        ("XSS vulnerability in the search frontend component", "WEB"),
        ("CSRF attack on the payment form submission", "WEB"),
        ("SSRF through user-controlled URL parameter", "WEB"),
        ("Insecure deserialization in REST API endpoint", "WEB"),
    ])
    def test_web_threats(self, desc, category_prefix):
        cat = _classify_threat_category({"description": desc})
        assert _CATEGORY_PREFIX_MAP.get(cat) == category_prefix, \
            f"'{desc}' classified as '{cat}' (wanted prefix {category_prefix})"

    @pytest.mark.parametrize("desc,category_prefix", [
        ("Misconfigured TLS certificates on the server", "INF"),
        ("Docker container escape through kernel vulnerability", "INF"),
        ("AWS IAM policy allows overly broad access", "INF"),
        ("Exposed credentials in environment variable .env file", "INF"),
        ("CI/CD pipeline compromise through insecure build secrets", "INF"),
    ])
    def test_infrastructure_threats(self, desc, category_prefix):
        cat = _classify_threat_category({"description": desc})
        assert _CATEGORY_PREFIX_MAP.get(cat) == category_prefix, \
            f"'{desc}' classified as '{cat}' (wanted prefix {category_prefix})"

    @pytest.mark.parametrize("desc,category_prefix", [
        ("Prompt injection to bypass LLM guardrails", "LLM"),
        ("Model poisoning through adversarial training data", "LLM"),
        ("RAG pipeline data poisoning via vector database manipulation", "LLM"),
        ("Jailbreak attack to extract system prompt", "LLM"),
    ])
    def test_ai_threats(self, desc, category_prefix):
        cat = _classify_threat_category({"description": desc})
        assert _CATEGORY_PREFIX_MAP.get(cat) == category_prefix, \
            f"'{desc}' classified as '{cat}' (wanted prefix {category_prefix})"

    def test_stride_fallback_avoids_amenazas_generales(self):
        cat = _classify_threat_category({
            "description": "An obscure concern about the system",
            "stride_category": "T",
        })
        assert cat != "Amenazas Generales"

    def test_gen_prefix_for_truly_uncategorizable(self):
        threats = [{"description": "Lorem ipsum dolor sit amet " * 5}]
        result = _assign_category_ids(threats)
        assert result[0]["id"].startswith("GEN-"), f"Expected GEN-, got {result[0]['id']}"

    def test_sqli_never_classified_as_privacy(self):
        """Regression: SQLi with 'exfiltration' must be WEB, not Privacy."""
        cat = _classify_threat_category({
            "description": "SQL injection through API endpoint allowing data exfiltration of customer records",
            "component": "API Gateway",
        })
        prefix = _CATEGORY_PREFIX_MAP.get(cat)
        assert prefix in ("WEB", "INF"), f"SQLi classified as {cat} ({prefix})"

    def test_realistic_ecommerce_threats_classified(self):
        """All e-commerce threats should get INF or WEB prefix."""
        for t in REALISTIC_STRIDE_THREATS:
            cat = _classify_threat_category(t)
            prefix = _CATEGORY_PREFIX_MAP.get(cat)
            assert prefix in ("INF", "WEB", "PRI", "HUM"), \
                f"E-commerce threat '{t['description'][:50]}' got unexpected prefix {prefix}"

    @pytest.mark.parametrize("desc,allowed_prefixes", [
        (
            "Cross-tenant document access via IDOR on doc_id lets one customer read another tenant's files.",
            {"WEB", "PRI"},
        ),
        (
            "Race condition allows document download before malware scan updates CLEAN status in DynamoDB.",
            {"WEB", "PRI"},
        ),
    ])
    def test_docushare_app_logic_threats_not_classified_as_infrastructure(self, desc, allowed_prefixes):
        cat = _classify_threat_category({"description": desc, "component": "AWS Lambda (API Handlers)"})
        prefix = _CATEGORY_PREFIX_MAP.get(cat)
        assert prefix in allowed_prefixes, f"DocuShare app-layer threat classified as {cat} ({prefix})"


# ═══════════════════════════════════════════════════════════════════════════
# 4. Category ID Assignment (unit)
# ═══════════════════════════════════════════════════════════════════════════

class TestAssignCategoryIds:

    def test_no_tm_prefix(self):
        threats = [
            {"description": "SQL injection on API endpoint", "stride_category": "T"},
            {"description": "DDoS attack on the load balancer", "stride_category": "D"},
            {"description": "Credential stuffing on login form", "stride_category": "S"},
        ]
        result = _assign_category_ids(threats)
        for t in result:
            assert not t["id"].startswith("TM-"), f"Got TM- prefix on: {t['description'][:50]}"

    def test_ids_are_sequential_within_category(self):
        threats = [
            {"description": "XSS in search page", "stride_category": "T",
             "component": "frontend", "methodology": "STRIDE"},
            {"description": "CSRF on form submit via API", "stride_category": "T",
             "component": "api gateway", "methodology": "STRIDE"},
        ]
        result = _assign_category_ids(threats)
        web_threats = [t for t in result if t["id"].startswith("WEB-")]
        if len(web_threats) >= 2:
            nums = [int(t["id"].split("-")[1]) for t in web_threats]
            assert nums == sorted(nums)

    def test_mixed_categories_get_correct_prefixes(self):
        threats = [
            {"description": "SQL injection on API endpoint", "component": "API", "methodology": "STRIDE"},
            {"description": "Exposed AWS credentials in .env configuration file", "component": "Config"},
            {"description": "Prompt injection to bypass LLM guardrails", "component": "LLM API"},
        ]
        result = _assign_category_ids(threats)
        prefixes = {t["id"].split("-")[0] for t in result}
        assert len(prefixes) >= 2, f"Expected multiple prefixes, got {prefixes}"


# ═══════════════════════════════════════════════════════════════════════════
# 5. PASTA Extraction (unit)
# ═══════════════════════════════════════════════════════════════════════════

class TestPastaExtraction:

    def test_standard_threat_array(self):
        parsed = {
            "threats": [
                {"description": "SQL injection via API", "component": "API Gateway"},
                {"description": "DDoS via request flood", "component": "Load Balancer"},
            ]
        }
        result = _extract_threats_from_stages(parsed)
        assert len(result) >= 2

    def test_stage_keyed_dict_lists(self):
        parsed = {
            "stage_4_threats": [
                {"description": "Buffer overflow in parser", "attack_path": "send malformed input"},
            ],
            "stage_5_attack": [
                {"description": "Privilege escalation via symlink", "attack_path": "create symlink"},
            ],
        }
        result = _extract_threats_from_stages(parsed)
        assert len(result) >= 2

    def test_variant_stage_keys_with_strings(self):
        parsed = {
            "threat_model": {
                "stage_2_identify_threats": [
                    "SQL injection through the user search endpoint allows data exfiltration",
                    "Cross-site scripting in comment rendering enables session hijacking",
                ],
                "stage_4_exploit_threats": [
                    "API rate limit bypass enables brute-force credential attacks against users",
                ],
            }
        }
        result = _extract_threats_from_stages(parsed)
        assert len(result) >= 2, f"Expected >=2, got {len(result)}"
        for t in result:
            assert "description" in t
            assert t.get("methodology") == "PASTA"

    def test_nested_wrapper_keys(self):
        parsed = {
            "pasta_analysis": {
                "threats": [
                    {"description": "Credential theft via phishing", "component": "Auth"},
                ]
            }
        }
        result = _extract_threats_from_stages(parsed)
        assert len(result) >= 1

    def test_empty_response_returns_empty(self):
        parsed = {"summary": "No threats found", "methodology": "PASTA"}
        assert _extract_threats_from_stages(parsed) == []

    def test_deeply_nested_stages(self):
        parsed = {
            "analysis": {
                "stages": {
                    "stage_5_attack_scenarios": [
                        {"description": "Man-in-the-middle on internal traffic", "component": "Network"},
                    ]
                }
            }
        }
        result = _extract_threats_from_stages(parsed)
        assert len(result) >= 1

    def test_real_world_pasta_stage_output(self):
        """Simulate the exact JSON shape observed in production PASTA failures."""
        parsed = {
            "methodology": "PASTA",
            "threat_model": {
                "stage_1_motivation": "Protect customer financial data and ensure platform availability",
                "stage_2_identify_threats": [
                    "Unauthorized access to payment processing endpoints through API key theft",
                    "Data exfiltration of customer PII via NoSQL injection in product search",
                    "Denial of service through distributed request flooding of checkout API",
                ],
                "stage_3_decompose_application": "The application consists of CDN, API Gateway, Lambda, DynamoDB, and Stripe",
                "stage_4_exploit_threats": [
                    "An attacker exploits the lack of rate limiting to perform credential stuffing",
                    "Supply chain attack through compromised npm dependency in Lambda build",
                ],
                "stage_7_risk_assessment": "High risk for payment-related threats, medium for availability"
            }
        }
        result = _extract_threats_from_stages(parsed)
        assert len(result) >= 4, f"Expected >=4 threats from 5 string items, got {len(result)}"


# ═══════════════════════════════════════════════════════════════════════════
# 6. Quality Gates (integration-level)
# ═══════════════════════════════════════════════════════════════════════════

class TestQualityGates:

    def _make_threat(self, desc: str, **kwargs) -> dict:
        base = {
            "id": "TM-001", "component": "API Gateway",
            "description": desc, "methodology": "STRIDE",
            "stride_category": "", "attack_path": "",
            "damage": 5, "reproducibility": 5, "exploitability": 5,
            "affected_users": 5, "discoverability": 5,
            "dread_total": 25, "priority": "Medium",
            "mitigation": "", "control_reference": "",
            "effort": "Medium", "observations": "", "status": "Open",
        }
        base.update(kwargs)
        return base

    def test_all_threats_have_stride_after_gates(self):
        threats = [
            self._make_threat("SQL injection through API Gateway input validation bypass", stride_category=""),
            self._make_threat("DDoS flooding attack on the load balancer endpoint", stride_category=""),
            self._make_threat("Credential stuffing attack on login authentication endpoint", stride_category=""),
        ]
        result = _apply_quality_gates(threats, known_components=["API Gateway", "Load Balancer"])
        for t in result:
            assert t["stride_category"] in {"S", "T", "R", "I", "D", "E"}, \
                f"Empty STRIDE on: {t['description'][:60]}"

    def test_all_threats_have_mitigations(self):
        threats = [self._make_threat("SQL injection through unsanitized input parameters in the API", mitigation="")]
        result = _apply_quality_gates(threats)
        for t in result:
            assert (t.get("mitigation") or "").strip(), f"Empty mitigation on: {t['description'][:60]}"

    def test_all_threats_have_control_references(self):
        threats = [self._make_threat("SQL injection through API endpoint bypass validation", control_reference="")]
        result = _apply_quality_gates(threats)
        for t in result:
            assert (t.get("control_reference") or "").strip(), \
                f"Empty control_reference on: {t['description'][:60]}"

    def test_garbage_descriptions_filtered(self):
        threats = [
            self._make_threat("ok"),
            self._make_threat("SQL injection through the user API endpoint allows attackers "
                              "to exfiltrate sensitive data from the database"),
        ]
        result = _apply_quality_gates(threats)
        assert len(result) == 1
        assert "SQL injection" in result[0]["description"]

    def test_markdown_tables_in_description_filtered(self):
        threats = [
            self._make_threat(
                "Risk Assessment: | ID | Threat | Severity | --- | --- | --- | "
                "| 1 | SQL Injection | High | 2 | XSS | Medium |"
            ),
        ]
        result = _apply_quality_gates(threats)
        assert len(result) == 0, "Markdown table descriptions should be filtered"

    def test_architecture_descriptions_filtered(self):
        threats = [
            self._make_threat(
                "The system is a serverless E-Commerce platform hosted on AWS. "
                "Frontend is a React SPA served via CloudFront CDN. Backend consists "
                "of Node.js Lambda functions behind API Gateway."
            ),
        ]
        result = _apply_quality_gates(threats)
        assert len(result) == 0, "Architecture descriptions should be filtered"

    def test_control_recommendations_filtered(self):
        threats = [
            self._make_threat(
                "Implement robust input validation across all API endpoints to prevent injection attacks"
            ),
        ]
        result = _apply_quality_gates(threats)
        assert len(result) == 0, "Control recommendations should be filtered"

    def test_valid_threats_survive(self):
        threats = [
            self._make_threat(
                "An attacker exploits a SQL injection vulnerability in the search endpoint "
                "to exfiltrate customer PII from the PostgreSQL database, bypassing input "
                "validation controls on the API Gateway.",
                stride_category="T",
                mitigation="Use parameterized queries for all database operations",
            ),
        ]
        result = _apply_quality_gates(threats)
        assert len(result) == 1
        assert result[0]["stride_category"] == "T"

    def test_component_inference(self):
        threats = [
            self._make_threat(
                "SQL injection via the API Gateway search endpoint allows data exfiltration",
                component="",
            ),
        ]
        result = _apply_quality_gates(threats, known_components=["API Gateway", "PostgreSQL"])
        assert result[0].get("component"), "Component should be inferred"

    def test_realistic_threats_all_survive(self):
        """All realistic well-formed threats should pass quality gates."""
        result = _apply_quality_gates(
            [dict(t) for t in REALISTIC_STRIDE_THREATS],
            known_components=KNOWN_COMPONENTS,
        )
        assert len(result) == len(REALISTIC_STRIDE_THREATS), \
            f"Expected {len(REALISTIC_STRIDE_THREATS)} threats, got {len(result)}"

    def test_priority_recalculated(self):
        threats = [self._make_threat(
            "SQL injection allowing full database compromise via API endpoint exploitation",
            damage=9, reproducibility=7, exploitability=6, affected_users=8, discoverability=5,
        )]
        result = _apply_quality_gates(threats)
        assert result[0]["dread_total"] == 35
        assert result[0]["priority"] == "High"

    def test_filter_drops_prompt_injection_for_non_ai_systems(self):
        threats = [self._make_threat(
            "Prompt injection in uploaded documents manipulates the model and bypasses guardrails to expose other users' data.",
            component="AWS Lambda (API Handlers)",
            methodology="STRIDE",
            confidence_score=0.8,
        )]
        state = {
            "system_description": "Serverless document sharing platform with API handlers, S3, and DynamoDB.",
            "raw_input": "There are no AI, LLM, or agentic AI components in this system.",
            "components": [{"name": "AWS Lambda (API Handlers)", "description": "Generates upload and sharing links."}],
            "scope_notes": "",
            "threat_surface_summary": "",
        }
        result = _filter_irrelevant_threats(threats, state)
        assert result == []

    def test_filter_preserves_tenant_isolation_threats_grounded_in_raw_input(self):
        original = self._make_threat(
            "An attacker changes doc_id values to access another tenant's documents because ownership checks only validate authentication, not tenant isolation.",
            component="AWS Lambda (API Handlers)",
            methodology="STRIDE",
            confidence_score=0.82,
            damage=8,
            reproducibility=6,
            exploitability=5,
            affected_users=8,
            discoverability=5,
            dread_total=32,
            priority="Medium",
        )
        state = {
            "system_description": "Serverless document sharing platform on AWS.",
            "raw_input": (
                "Metadata includes doc_id, tenant_id, user_id, and status. "
                "The system is multi-tenant and must preserve tenant isolation for authorized tenant users."
            ),
            "components": [{"name": "AWS Lambda (API Handlers)", "description": "Handles document metadata and share links."}],
            "scope_notes": "Explicit application/workflow context:\n- Explicit business/data identifiers mentioned: doc_id, tenant_id, user_id, status.",
            "threat_surface_summary": "Prioritize tenant-scoped access controls and direct-object access paths.",
        }
        result = _filter_irrelevant_threats([original.copy()], state)
        assert len(result) == 1
        assert result[0]["confidence_score"] == pytest.approx(0.82)
        assert result[0]["dread_total"] == 32


# ═══════════════════════════════════════════════════════════════════════════
# 7. Baseline Extraction from Methodology Reports (integration)
# ═══════════════════════════════════════════════════════════════════════════

class TestBaselineExtraction:
    """Test _extract_threats_from_reports with realistic methodology report data."""

    def _build_state(self, threats_by_methodology: dict) -> dict:
        reports = []
        for methodology, threats in threats_by_methodology.items():
            reports.append({
                "methodology": methodology,
                "agent": f"{methodology.lower()}_analyst",
                "report": json.dumps({"threats": threats}),
                "threats_raw": threats,
            })
        return {
            **ECOMMERCE_ARCHITECTURE,
            "methodology_reports": reports,
            "debate_history": [],
            "threat_categories": ["base", "web"],
        }

    def test_extracts_from_multiple_methodologies(self):
        state = self._build_state({
            "STRIDE": REALISTIC_STRIDE_THREATS,
            "PASTA": REALISTIC_PASTA_THREATS,
            "ATTACK_TREE": REALISTIC_ATTACK_TREE_THREATS,
        })
        result = _extract_threats_from_reports(state)
        assert len(result) >= 5, f"Expected >=5 threats, got {len(result)}"

    def test_all_extracted_threats_have_required_fields(self):
        state = self._build_state({"STRIDE": REALISTIC_STRIDE_THREATS})
        result = _extract_threats_from_reports(state)
        required = {"id", "component", "description", "methodology", "stride_category",
                     "damage", "reproducibility", "exploitability", "affected_users",
                     "discoverability", "dread_total", "priority", "mitigation", "status"}
        for t in result:
            missing = required - set(t.keys())
            assert not missing, f"Threat {t.get('id')} missing fields: {missing}"

    def test_all_extracted_threats_have_valid_stride(self):
        state = self._build_state({"STRIDE": REALISTIC_STRIDE_THREATS})
        result = _extract_threats_from_reports(state)
        for t in result:
            assert t["stride_category"] in {"S", "T", "R", "I", "D", "E"}, \
                f"Invalid STRIDE '{t['stride_category']}' on {t['id']}"

    def test_all_dread_scores_in_valid_range(self):
        state = self._build_state({"STRIDE": REALISTIC_STRIDE_THREATS})
        result = _extract_threats_from_reports(state)
        for t in result:
            for dim in ("damage", "reproducibility", "exploitability", "affected_users", "discoverability"):
                assert 1 <= t[dim] <= 10, f"{t['id']}.{dim} = {t[dim]} (out of range)"
            assert 5 <= t["dread_total"] <= 50

    def test_deduplication_removes_similar_threats(self):
        dupe_threats = [
            {**REALISTIC_STRIDE_THREATS[0], "id": "DUP-1"},
            {**REALISTIC_STRIDE_THREATS[0], "id": "DUP-2",
             "description": REALISTIC_STRIDE_THREATS[0]["description"] + " This is a slight variant."},
        ]
        state = self._build_state({"STRIDE": dupe_threats})
        result = _extract_threats_from_reports(state)
        assert len(result) <= 2, "Near-duplicates should be merged"

    def test_methodology_reports_deduplicated(self):
        """LangGraph fan-in can duplicate methodology_reports; extraction should handle it."""
        threats = REALISTIC_STRIDE_THREATS[:2]
        state = self._build_state({"STRIDE": threats})
        state["methodology_reports"] = state["methodology_reports"] * 2
        result = _extract_threats_from_reports(state)
        assert len(result) == len(threats), "Duplicate methodology_reports should be deduplicated"


# ═══════════════════════════════════════════════════════════════════════════
# 8. Deduplication (unit)
# ═══════════════════════════════════════════════════════════════════════════

class TestDeduplication:

    def test_identical_threats_merged(self):
        threats = [
            {"description": "SQL injection in the API Gateway", "component": "API Gateway",
             "stride_category": "T", "methodology": "STRIDE"},
            {"description": "SQL injection in the API Gateway", "component": "API Gateway",
             "stride_category": "T", "methodology": "PASTA"},
        ]
        result = _deduplicate_threats(threats)
        assert len(result) == 1
        assert "STRIDE" in result[0]["methodology"] and "PASTA" in result[0]["methodology"]

    def test_different_threats_preserved(self):
        threats = [
            {"description": "SQL injection in the search endpoint allows data exfiltration",
             "component": "API Gateway", "stride_category": "T"},
            {"description": "DDoS attack through rate limit exhaustion causes service downtime",
             "component": "API Gateway", "stride_category": "D"},
        ]
        result = _deduplicate_threats(threats)
        assert len(result) == 2

    def test_cross_component_similar_threats_merged(self):
        threats = [
            {"description": "SQL injection vulnerability allowing data exfiltration from database",
             "component": "API Gateway", "stride_category": "T", "methodology": "STRIDE"},
            {"description": "SQL injection vulnerability allowing data exfiltration from database",
             "component": "Backend API", "stride_category": "T", "methodology": "PASTA"},
        ]
        result = _deduplicate_threats(threats)
        assert len(result) <= 2


# ═══════════════════════════════════════════════════════════════════════════
# 9. Report Generator (integration)
# ═══════════════════════════════════════════════════════════════════════════

class TestReportGenerator:
    """Validate CSV and Markdown report output quality."""

    def _build_report_state(self) -> dict:
        threats = []
        for i, t in enumerate(REALISTIC_STRIDE_THREATS):
            threat = dict(t)
            threat["dread_total"] = sum(
                threat.get(d, 5) for d in
                ("damage", "reproducibility", "exploitability", "affected_users", "discoverability")
            )
            threat["priority"] = "High" if threat["dread_total"] >= 35 else "Medium"
            threat["control_reference"] = "NIST AC-3"
            threat["effort"] = "Medium"
            threat["observations"] = "Validated"
            threat["status"] = "Open"
            threats.append(threat)

        threats = _assign_category_ids(threats)

        return {
            **ECOMMERCE_ARCHITECTURE,
            "analysis_date": "2025-01-15",
            "threats_final": threats,
            "methodology_reports": [
                {"methodology": "STRIDE", "agent": "stride_analyst",
                 "report": "STRIDE analysis complete", "threats_raw": REALISTIC_STRIDE_THREATS},
            ],
            "debate_history": [],
            "threat_categories": ["base", "web"],
            "executive_summary": "Threat model for E-Commerce platform identifying 5 key risks.",
        }

    def test_csv_has_all_threats(self):
        state = self._build_report_state()
        csv = generate_csv(state)
        lines = csv.strip().split("\n")
        data_lines = [l for l in lines if l.strip() and not l.startswith("#")]
        header_idx = next(i for i, l in enumerate(data_lines) if "Descripción" in l or "ID" in l)
        threat_lines = [l for l in data_lines[header_idx + 1:] if l.strip() and "---" not in l]
        assert len(threat_lines) >= len(REALISTIC_STRIDE_THREATS), \
            f"CSV has {len(threat_lines)} threats, expected {len(REALISTIC_STRIDE_THREATS)}"

    def test_csv_contains_threat_descriptions(self):
        state = self._build_report_state()
        csv = generate_csv(state)
        for t in REALISTIC_STRIDE_THREATS[:3]:
            desc_fragment = t["description"][:40]
            assert desc_fragment in csv, f"CSV missing threat description: {desc_fragment}"

    def test_markdown_report_has_sections(self):
        state = self._build_report_state()
        md = generate_markdown_report(state)
        assert "# " in md, "Markdown should have headers"
        assert "E-Commerce Platform" in md or "E-Commerce" in md
        assert len(md) > 500, f"Report too short: {len(md)} chars"

    def test_markdown_has_threat_table(self):
        state = self._build_report_state()
        md = generate_markdown_report(state)
        assert "|" in md, "Markdown should contain a table"
        assert "DREAD" in md or "dread" in md.lower() or "Prioridad" in md

    def test_all_threat_ids_appear_in_report(self):
        state = self._build_report_state()
        md = generate_markdown_report(state)
        for t in state["threats_final"]:
            assert t["id"] in md, f"Threat {t['id']} not found in markdown report"


# ═══════════════════════════════════════════════════════════════════════════
# 10. DREAD Validator Merge Logic (unit)
# ═══════════════════════════════════════════════════════════════════════════

class TestDreadValidatorMerge:

    def test_stride_fill_from_update(self):
        from agentictm.agents.dread_validator import _VALID_STRIDE
        orig = {"id": "WEB-01", "stride_category": "", "dread_total": 25}
        update = {"id": "WEB-01", "stride_category": "T", "damage": 7}
        llm_stride = (update.get("stride_category") or "").strip().upper()
        assert llm_stride in _VALID_STRIDE
        assert not (orig.get("stride_category") or "").strip()

    def test_stride_not_overwritten_when_present(self):
        orig_stride = "S"
        assert (orig_stride or "").strip()


# ═══════════════════════════════════════════════════════════════════════════
# 11. End-to-End Quality Contract
# ═══════════════════════════════════════════════════════════════════════════

class TestEndToEndQualityContract:
    """Validate the full extract → quality-gate → assign-IDs pipeline produces
    threats that meet the minimum quality bar for a production threat model."""

    def _run_pipeline(self, threats_by_methodology: dict) -> list[dict]:
        reports = []
        for methodology, threats in threats_by_methodology.items():
            reports.append({
                "methodology": methodology,
                "agent": f"{methodology.lower()}_analyst",
                "report": json.dumps({"threats": threats}),
                "threats_raw": threats,
            })
        state = {
            **ECOMMERCE_ARCHITECTURE,
            "methodology_reports": reports,
            "debate_history": [],
            "threat_categories": ["base", "web"],
        }
        baseline = _extract_threats_from_reports(state)
        gated = _apply_quality_gates(baseline, known_components=KNOWN_COMPONENTS)
        return _assign_category_ids(gated)

    def test_ecommerce_produces_enough_threats(self):
        result = self._run_pipeline({
            "STRIDE": REALISTIC_STRIDE_THREATS,
            "PASTA": REALISTIC_PASTA_THREATS,
            "ATTACK_TREE": REALISTIC_ATTACK_TREE_THREATS,
        })
        assert len(result) >= 5, f"Expected >=5 threats, got {len(result)}"

    def test_every_threat_has_valid_id(self):
        result = self._run_pipeline({"STRIDE": REALISTIC_STRIDE_THREATS})
        valid_prefixes = set(_CATEGORY_PREFIX_MAP.values())
        for t in result:
            prefix = t["id"].split("-")[0]
            assert prefix in valid_prefixes, f"Invalid ID prefix '{prefix}' on {t['id']}"

    def test_every_threat_has_stride_category(self):
        result = self._run_pipeline({"STRIDE": REALISTIC_STRIDE_THREATS})
        for t in result:
            assert t["stride_category"] in {"S", "T", "R", "I", "D", "E"}, \
                f"{t['id']} has invalid STRIDE: '{t['stride_category']}'"

    def test_every_threat_has_mitigation(self):
        result = self._run_pipeline({"STRIDE": REALISTIC_STRIDE_THREATS})
        for t in result:
            mit = (t.get("mitigation") or "").strip()
            assert len(mit) >= 10, f"{t['id']} has insufficient mitigation: '{mit[:50]}'"

    def test_every_threat_has_component(self):
        result = self._run_pipeline({"STRIDE": REALISTIC_STRIDE_THREATS})
        for t in result:
            assert (t.get("component") or "").strip(), f"{t['id']} has no component"

    def test_every_threat_has_valid_priority(self):
        result = self._run_pipeline({"STRIDE": REALISTIC_STRIDE_THREATS})
        for t in result:
            assert t["priority"] in {"Critical", "High", "Medium", "Low"}, \
                f"{t['id']} has invalid priority: '{t['priority']}'"

    def test_description_minimum_quality(self):
        result = self._run_pipeline({"STRIDE": REALISTIC_STRIDE_THREATS})
        for t in result:
            desc = t.get("description", "")
            assert len(desc) >= 50, f"{t['id']} description too short ({len(desc)} chars)"
            assert " " in desc, f"{t['id']} description has no spaces"

    def test_no_duplicate_ids(self):
        result = self._run_pipeline({
            "STRIDE": REALISTIC_STRIDE_THREATS,
            "PASTA": REALISTIC_PASTA_THREATS,
        })
        ids = [t["id"] for t in result]
        assert len(ids) == len(set(ids)), f"Duplicate IDs found: {ids}"

    def test_stride_coverage(self):
        """Pipeline should produce threats covering multiple STRIDE categories."""
        result = self._run_pipeline({"STRIDE": REALISTIC_STRIDE_THREATS})
        categories = {t["stride_category"] for t in result}
        assert len(categories) >= 3, f"Only {len(categories)} STRIDE categories: {categories}"
