"""Canned JSON responses for each agent — used by MockChatModel in tests."""

from __future__ import annotations

import json

ARCHITECTURE_PARSER_RESPONSE = json.dumps({
    "system_description": "A web application with an API gateway, backend service, and PostgreSQL database. "
                          "Users connect via HTTPS through a CDN.",
    "components": [
        {"name": "CDN", "type": "external_entity", "description": "Content delivery network", "scope": "public"},
        {"name": "API Gateway", "type": "process", "description": "Routes and authenticates requests", "scope": "dmz"},
        {"name": "Backend Service", "type": "process", "description": "Core business logic", "scope": "internal"},
        {"name": "PostgreSQL", "type": "data_store", "description": "Primary database", "scope": "internal"},
    ],
    "data_flows": [
        {"source": "CDN", "destination": "API Gateway", "protocol": "HTTPS", "data_type": "user_requests"},
        {"source": "API Gateway", "destination": "Backend Service", "protocol": "gRPC", "data_type": "authenticated_requests"},
        {"source": "Backend Service", "destination": "PostgreSQL", "protocol": "TLS/PostgreSQL", "data_type": "queries"},
    ],
    "trust_boundaries": [
        {"name": "Internet Boundary", "components_inside": ["API Gateway"], "components_outside": ["CDN"]},
        {"name": "Internal Network", "components_inside": ["Backend Service", "PostgreSQL"], "components_outside": ["API Gateway"]},
    ],
    "external_entities": [
        {"name": "End Users", "type": "external_entity", "description": "Application users"},
    ],
    "data_stores": [
        {"name": "PostgreSQL", "type": "data_store", "description": "Primary relational database"},
    ],
    "assumptions": ["All traffic is encrypted in transit", "Database credentials are stored in a secrets manager"],
})

STRIDE_RESPONSE = json.dumps({
    "threats": [
        {
            "id": "STRIDE-001",
            "component": "API Gateway",
            "description": "Spoofing of user identity through forged JWT tokens",
            "methodology": "STRIDE",
            "stride_category": "S",
            "attack_path": "Attacker forges JWT → bypasses auth → accesses backend",
            "mitigation": "Implement JWT signature verification with key rotation",
            "damage": 7, "reproducibility": 5, "exploitability": 4,
            "affected_users": 8, "discoverability": 3,
        },
        {
            "id": "STRIDE-002",
            "component": "Backend Service",
            "description": "SQL injection through unsanitized query parameters",
            "methodology": "STRIDE",
            "stride_category": "T",
            "attack_path": "Malicious input → SQL injection → data exfiltration",
            "mitigation": "Use parameterized queries and input validation",
            "damage": 9, "reproducibility": 6, "exploitability": 5,
            "affected_users": 9, "discoverability": 4,
        },
        {
            "id": "STRIDE-003",
            "component": "PostgreSQL",
            "description": "Information disclosure through verbose error messages",
            "methodology": "STRIDE",
            "stride_category": "I",
            "attack_path": "Trigger DB errors → error messages leak schema info",
            "mitigation": "Sanitize error responses, implement generic error handler",
            "damage": 4, "reproducibility": 7, "exploitability": 6,
            "affected_users": 3, "discoverability": 5,
        },
    ]
})

PASTA_RESPONSE = json.dumps({
    "threats": [
        {
            "id": "PASTA-001",
            "component": "API Gateway",
            "description": "DDoS attack exhausting API rate limits and causing service unavailability",
            "methodology": "PASTA",
            "attack_path": "Distributed traffic flood → rate limit exhaustion → service degradation",
            "mitigation": "Implement adaptive rate limiting and WAF rules",
            "damage": 6, "reproducibility": 8, "exploitability": 7,
            "affected_users": 9, "discoverability": 2,
        },
        {
            "id": "PASTA-002",
            "component": "Backend Service",
            "description": "Insecure deserialization leading to remote code execution",
            "methodology": "PASTA",
            "attack_path": "Crafted payload → deserialization exploit → RCE",
            "mitigation": "Validate and sanitize all deserialized objects, use allow-lists",
            "damage": 10, "reproducibility": 3, "exploitability": 4,
            "affected_users": 10, "discoverability": 3,
        },
    ]
})

ATTACK_TREE_RESPONSE = json.dumps({
    "threats": [
        {
            "id": "AT-001",
            "component": "Backend Service",
            "description": "Privilege escalation via broken access control in admin endpoints",
            "methodology": "ATTACK_TREE",
            "attack_path": "Enumerate admin endpoints → exploit missing authz check → escalate privileges",
            "mitigation": "Enforce RBAC on all endpoints, audit access control policies",
            "damage": 8, "reproducibility": 5, "exploitability": 5,
            "affected_users": 7, "discoverability": 4,
        },
    ]
})

ATTACK_TREE_ENRICHED_RESPONSE = json.dumps({
    "threats": [
        {
            "id": "ATE-001",
            "component": "API Gateway",
            "description": "Chained attack: JWT spoofing combined with privilege escalation",
            "methodology": "ATTACK_TREE",
            "attack_path": "Forge JWT → bypass gateway auth → hit admin endpoint → full system compromise",
            "mitigation": "Defense-in-depth: JWT validation + endpoint-level RBAC + anomaly detection",
            "damage": 9, "reproducibility": 4, "exploitability": 5,
            "affected_users": 9, "discoverability": 3,
        },
    ]
})

MAESTRO_RESPONSE = json.dumps({
    "threats": [
        {
            "id": "MAESTRO-001",
            "component": "Backend Service",
            "description": "No AI/ML components detected — MAESTRO analysis not applicable",
            "methodology": "MAESTRO",
            "attack_path": "N/A",
            "mitigation": "N/A",
            "damage": 0, "reproducibility": 0, "exploitability": 0,
            "affected_users": 0, "discoverability": 0,
        },
    ]
})

AI_THREAT_RESPONSE = json.dumps({
    "threats": [
        {
            "id": "AI-001",
            "component": "Backend Service",
            "description": "No AI/ML components detected — AI threat analysis not applicable",
            "methodology": "AI_THREAT_ANALYSIS",
            "attack_path": "N/A",
            "mitigation": "N/A",
            "damage": 0, "reproducibility": 0, "exploitability": 0,
            "affected_users": 0, "discoverability": 0,
        },
    ]
})

RED_TEAM_RESPONSE = json.dumps({
    "threat_assessments": [
        {
            "threat_id": "STRIDE-001",
            "verdict": "escalate",
            "reasoning": "JWT spoofing is underestimated — the current score doesn't account "
                         "for automated tooling that makes this trivial to exploit.",
            "proposed_dread_adjustment": {"exploitability": 7, "damage": 8},
        },
        {
            "threat_id": "STRIDE-002",
            "verdict": "maintain",
            "reasoning": "SQL injection assessment is accurate given the tech stack.",
        },
    ]
})

BLUE_TEAM_RESPONSE = json.dumps({
    "threat_assessments": [
        {
            "threat_id": "STRIDE-001",
            "verdict": "maintain",
            "reasoning": "JWT rotation with short TTL and HMAC-256 makes spoofing significantly harder. "
                         "The original scoring is appropriate.",
        },
        {
            "threat_id": "STRIDE-002",
            "verdict": "downgrade",
            "reasoning": "The ORM layer provides parameterized queries by default, "
                         "making raw SQL injection unlikely without developer error.",
            "proposed_dread_adjustment": {"exploitability": 3},
        },
    ]
})

SYNTHESIZER_RESPONSE = json.dumps({
    "threats": [
        {
            "id": "T-001",
            "component": "API Gateway",
            "description": "JWT token spoofing enabling unauthorized API access",
            "methodology": "STRIDE",
            "stride_category": "S",
            "attack_path": "Forge JWT → bypass authentication → access protected endpoints",
            "mitigation": "JWT signature verification with key rotation, short TTL",
            "damage": 7, "reproducibility": 5, "exploitability": 5,
            "affected_users": 8, "discoverability": 3,
            "dread_total": 28, "priority": "High",
            "control_reference": "NIST AC-3", "effort": "Medium",
            "status": "Open",
        },
        {
            "id": "T-002",
            "component": "Backend Service",
            "description": "SQL injection through unsanitized inputs leading to data breach",
            "methodology": "STRIDE",
            "stride_category": "T",
            "attack_path": "Inject SQL → exfiltrate data → compromise database integrity",
            "mitigation": "Parameterized queries, input validation, WAF rules",
            "damage": 9, "reproducibility": 5, "exploitability": 4,
            "affected_users": 9, "discoverability": 4,
            "dread_total": 31, "priority": "Critical",
            "control_reference": "OWASP A03:2021", "effort": "Low",
            "status": "Open",
        },
        {
            "id": "T-003",
            "component": "API Gateway",
            "description": "DDoS attack causing service unavailability",
            "methodology": "PASTA",
            "attack_path": "Traffic flood → resource exhaustion → denial of service",
            "mitigation": "Rate limiting, WAF, CDN-level DDoS protection",
            "damage": 6, "reproducibility": 8, "exploitability": 7,
            "affected_users": 9, "discoverability": 2,
            "dread_total": 32, "priority": "Critical",
            "control_reference": "NIST SC-5", "effort": "Medium",
            "status": "Open",
        },
        {
            "id": "T-004",
            "component": "Backend Service",
            "description": "Privilege escalation via broken access control",
            "methodology": "ATTACK_TREE",
            "attack_path": "Enumerate endpoints → exploit missing authz → escalate to admin",
            "mitigation": "RBAC enforcement, access control audit, principle of least privilege",
            "damage": 8, "reproducibility": 5, "exploitability": 5,
            "affected_users": 7, "discoverability": 4,
            "dread_total": 29, "priority": "High",
            "control_reference": "OWASP A01:2021", "effort": "Medium",
            "status": "Open",
        },
    ],
    "executive_summary": "The system presents 4 significant threats across authentication, "
                         "input validation, availability, and access control domains. "
                         "Critical priorities are SQL injection and DDoS attacks.",
})

DREAD_VALIDATOR_RESPONSE = json.dumps({
    "threats": [
        {
            "id": "T-001", "component": "API Gateway",
            "description": "JWT token spoofing enabling unauthorized API access",
            "damage": 7, "reproducibility": 5, "exploitability": 5,
            "affected_users": 8, "discoverability": 3,
            "dread_total": 28, "priority": "High",
            "validation_notes": "Scores verified — consistent with JWT attack complexity.",
        },
        {
            "id": "T-002", "component": "Backend Service",
            "description": "SQL injection through unsanitized inputs leading to data breach",
            "damage": 9, "reproducibility": 5, "exploitability": 4,
            "affected_users": 9, "discoverability": 4,
            "dread_total": 31, "priority": "Critical",
            "validation_notes": "Adjusted exploitability down (ORM protection).",
        },
        {
            "id": "T-003", "component": "API Gateway",
            "description": "DDoS attack causing service unavailability",
            "damage": 6, "reproducibility": 8, "exploitability": 7,
            "affected_users": 9, "discoverability": 2,
            "dread_total": 32, "priority": "Critical",
            "validation_notes": "Scores accurate for publicly exposed endpoint.",
        },
        {
            "id": "T-004", "component": "Backend Service",
            "description": "Privilege escalation via broken access control",
            "damage": 8, "reproducibility": 5, "exploitability": 5,
            "affected_users": 7, "discoverability": 4,
            "dread_total": 29, "priority": "High",
            "validation_notes": "Scores verified.",
        },
    ]
})

OUTPUT_LOCALIZER_RESPONSE = json.dumps({
    "status": "localized",
    "language": "es",
})

AGENT_RESPONSE_MAP: dict[str, str] = {
    "red team": RED_TEAM_RESPONSE,
    "blue team": BLUE_TEAM_RESPONSE,
    "threat synthesizer": SYNTHESIZER_RESPONSE,
    "dread validator": DREAD_VALIDATOR_RESPONSE,
    "dread risk scoring": DREAD_VALIDATOR_RESPONSE,
    "output localizer": OUTPUT_LOCALIZER_RESPONSE,
    "attack tree enriched": ATTACK_TREE_ENRICHED_RESPONSE,
    "attack tree": ATTACK_TREE_RESPONSE,
    "maestro": MAESTRO_RESPONSE,
    "ai threat": AI_THREAT_RESPONSE,
    "pasta": PASTA_RESPONSE,
    "stride analyst": STRIDE_RESPONSE,
    "stride security": STRIDE_RESPONSE,
}

# Patterns matched against the system prompt (first message) to identify the agent.
# These are ordered most-specific-first to avoid false positives.
SYSTEM_PROMPT_PATTERNS: dict[str, str] = {
    "red team attacker": RED_TEAM_RESPONSE,
    "blue team defender": BLUE_TEAM_RESPONSE,
    "threat synthesizer": SYNTHESIZER_RESPONSE,
    "synthesis of all identified threats": SYNTHESIZER_RESPONSE,
    "dread risk scoring": DREAD_VALIDATOR_RESPONSE,
    "output localizer": OUTPUT_LOCALIZER_RESPONSE,
    "attack tree enriched": ATTACK_TREE_ENRICHED_RESPONSE,
    "attack tree": ATTACK_TREE_RESPONSE,
    "maestro": MAESTRO_RESPONSE,
    "ai threat": AI_THREAT_RESPONSE,
    "ai/ml/agentic": AI_THREAT_RESPONSE,
    "pasta": PASTA_RESPONSE,
    "stride methodology": STRIDE_RESPONSE,
    "stride analysis": STRIDE_RESPONSE,
    "principal engineer": ARCHITECTURE_PARSER_RESPONSE,
    "document the system architecture": ARCHITECTURE_PARSER_RESPONSE,
    "system architecture": ARCHITECTURE_PARSER_RESPONSE,
}
