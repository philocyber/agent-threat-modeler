"""Compliance Mapper — maps threats to regulatory framework controls.

Maps each threat to relevant controls from:
- NIST SP 800-53 Rev 5
- ISO 27001:2022 Annex A
- CIS Controls v8
- OWASP ASVS v4

Usage::

    from agentictm.agents.compliance_mapper import map_threats_to_controls

    mappings = map_threats_to_controls(threats)
    for m in mappings:
        print(f"{m['threat_id']} -> {m['controls']}")
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Control Mappings — keyword-based mapping to security framework controls
# ---------------------------------------------------------------------------

# Each entry: (keywords_to_match, list_of_controls)
# Controls are tuples of (framework, control_id, control_name)

_CONTROL_MAPPINGS: list[tuple[list[str], list[tuple[str, str, str]]]] = [
    # Authentication
    (
        ["authentication", "login", "credential", "password", "brute force", "jwt", "token", "oauth", "session"],
        [
            ("NIST 800-53", "IA-2", "Identification and Authentication"),
            ("NIST 800-53", "IA-5", "Authenticator Management"),
            ("ISO 27001", "A.8.5", "Secure Authentication"),
            ("CIS v8", "6.3", "Require MFA for Externally-Exposed Applications"),
            ("CIS v8", "6.5", "Require MFA for Administrative Access"),
            ("OWASP ASVS", "V2", "Authentication Verification"),
        ],
    ),
    # Authorization / Access Control
    (
        ["authorization", "access control", "privilege", "rbac", "permission", "elevation", "escalation", "idor"],
        [
            ("NIST 800-53", "AC-3", "Access Enforcement"),
            ("NIST 800-53", "AC-6", "Least Privilege"),
            ("ISO 27001", "A.5.15", "Access Control"),
            ("ISO 27001", "A.8.3", "Information Access Restriction"),
            ("CIS v8", "6.8", "Define and Maintain Role-Based Access Control"),
            ("OWASP ASVS", "V4", "Access Control Verification"),
        ],
    ),
    # Injection
    (
        ["injection", "sql injection", "xss", "cross-site", "command injection", "ldap injection", "input validation",
         "sanitization", "sanitizing"],
        [
            ("NIST 800-53", "SI-10", "Information Input Validation"),
            ("NIST 800-53", "SI-3", "Malicious Code Protection"),
            ("ISO 27001", "A.8.26", "Application Security Requirements"),
            ("CIS v8", "16.4", "Establish and Manage a Software Security Policy"),
            ("OWASP ASVS", "V5", "Validation, Sanitization and Encoding"),
        ],
    ),
    # Encryption / Data Protection
    (
        ["encryption", "encrypt", "tls", "ssl", "data at rest", "data in transit", "plaintext",
         "cipher", "cryptography", "key management", "certificate"],
        [
            ("NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
            ("NIST 800-53", "SC-28", "Protection of Information at Rest"),
            ("NIST 800-53", "SC-12", "Cryptographic Key Establishment and Management"),
            ("ISO 27001", "A.8.24", "Use of Cryptography"),
            ("CIS v8", "3.10", "Encrypt Sensitive Data in Transit"),
            ("CIS v8", "3.11", "Encrypt Sensitive Data at Rest"),
            ("OWASP ASVS", "V6", "Stored Cryptography Verification"),
        ],
    ),
    # Logging / Monitoring
    (
        ["logging", "log", "monitoring", "audit", "detection", "alerting", "siem", "tracing"],
        [
            ("NIST 800-53", "AU-2", "Event Logging"),
            ("NIST 800-53", "AU-6", "Audit Record Review, Analysis, and Reporting"),
            ("NIST 800-53", "SI-4", "System Monitoring"),
            ("ISO 27001", "A.8.15", "Logging"),
            ("ISO 27001", "A.8.16", "Monitoring Activities"),
            ("CIS v8", "8.2", "Collect Audit Logs"),
            ("CIS v8", "8.5", "Collect Detailed Audit Logs"),
        ],
    ),
    # Network Security
    (
        ["network", "firewall", "ddos", "denial of service", "dos", "port", "segmentation",
         "proxy", "load balancer", "vpn", "dns"],
        [
            ("NIST 800-53", "SC-7", "Boundary Protection"),
            ("NIST 800-53", "SC-5", "Denial-of-Service Protection"),
            ("ISO 27001", "A.8.20", "Networks Security"),
            ("ISO 27001", "A.8.21", "Security of Network Services"),
            ("CIS v8", "13.1", "Centralize Network-Based Filtering"),
            ("CIS v8", "13.4", "Perform Traffic Filtering Between Network Segments"),
        ],
    ),
    # Configuration / Hardening
    (
        ["configuration", "misconfiguration", "hardening", "default", "patch", "update", "vulnerability",
         "outdated", "deprecated"],
        [
            ("NIST 800-53", "CM-6", "Configuration Settings"),
            ("NIST 800-53", "CM-7", "Least Functionality"),
            ("NIST 800-53", "SI-2", "Flaw Remediation"),
            ("ISO 27001", "A.8.9", "Configuration Management"),
            ("ISO 27001", "A.8.8", "Management of Technical Vulnerabilities"),
            ("CIS v8", "4.1", "Establish and Maintain a Secure Configuration Process"),
            ("CIS v8", "7.4", "Manage Default Accounts on Enterprise Assets"),
        ],
    ),
    # Data Privacy
    (
        ["personal data", "pii", "gdpr", "privacy", "data leak", "data breach", "exposure",
         "sensitive data", "confidential"],
        [
            ("NIST 800-53", "PT-2", "Authority to Process Personally Identifiable Information"),
            ("NIST 800-53", "PT-3", "Personally Identifiable Information Processing Purposes"),
            ("ISO 27001", "A.5.34", "Privacy and Protection of PII"),
            ("CIS v8", "3.1", "Establish and Maintain a Data Management Process"),
            ("OWASP ASVS", "V8", "Data Protection Verification"),
        ],
    ),
    # Supply Chain / Third-party
    (
        ["supply chain", "third-party", "third party", "vendor", "dependency", "library",
         "package", "npm", "pip", "container image"],
        [
            ("NIST 800-53", "SR-3", "Supply Chain Controls and Processes"),
            ("NIST 800-53", "SA-12", "Supply Chain Protection"),
            ("ISO 27001", "A.5.19", "Information Security in Supplier Relationships"),
            ("ISO 27001", "A.5.22", "Monitoring, Review of Supplier Services"),
            ("CIS v8", "16.4", "Establish and Manage a Software Security Policy"),
        ],
    ),
    # API Security
    (
        ["api", "rest", "graphql", "grpc", "endpoint", "rate limit", "throttl"],
        [
            ("NIST 800-53", "SC-7", "Boundary Protection"),
            ("NIST 800-53", "AC-4", "Information Flow Enforcement"),
            ("ISO 27001", "A.8.26", "Application Security Requirements"),
            ("CIS v8", "16.9", "Train Developers in Application Security"),
            ("OWASP ASVS", "V13", "API and Web Service Verification"),
        ],
    ),
    # Cloud Security
    (
        ["cloud", "aws", "azure", "gcp", "s3", "iam", "serverless", "lambda", "kubernetes", "k8s", "docker"],
        [
            ("NIST 800-53", "AC-2", "Account Management"),
            ("NIST 800-53", "SC-7", "Boundary Protection"),
            ("ISO 27001", "A.5.23", "Information Security for Use of Cloud Services"),
            ("CIS v8", "6.1", "Establish an Access Granting Process"),
        ],
    ),
]


def map_threats_to_controls(
    threats: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map each threat to relevant security framework controls.

    Args:
        threats: List of threat dicts from the pipeline

    Returns:
        List of dicts, each with:
        - threat_id: str
        - threat_description: str (truncated)
        - controls: list of {framework, control_id, control_name}
        - frameworks_covered: list of unique framework names
    """
    results: list[dict[str, Any]] = []
    all_frameworks: set[str] = set()

    for threat in threats:
        threat_id = threat.get("id", "UNKNOWN")
        description = threat.get("description", "")
        mitigation = threat.get("mitigation", "")
        attack_path = threat.get("attack_path", "")
        component = threat.get("component", "")

        # Combine all text fields for keyword matching
        search_text = f"{description} {mitigation} {attack_path} {component}".lower()

        matched_controls: list[dict[str, str]] = []
        seen_controls: set[str] = set()  # avoid duplicates

        for keywords, controls in _CONTROL_MAPPINGS:
            if any(kw in search_text for kw in keywords):
                for framework, control_id, control_name in controls:
                    key = f"{framework}:{control_id}"
                    if key not in seen_controls:
                        seen_controls.add(key)
                        matched_controls.append({
                            "framework": framework,
                            "control_id": control_id,
                            "control_name": control_name,
                        })
                        all_frameworks.add(framework)

        results.append({
            "threat_id": threat_id,
            "threat_description": description[:120] + ("..." if len(description) > 120 else ""),
            "controls": matched_controls,
            "controls_count": len(matched_controls),
            "frameworks_covered": sorted({c["framework"] for c in matched_controls}),
        })

    # Summary statistics
    total_mappings = sum(r["controls_count"] for r in results)
    threats_with_mappings = sum(1 for r in results if r["controls_count"] > 0)

    logger.info(
        "Compliance mapping: %d threats mapped to %d controls across %d frameworks",
        threats_with_mappings, total_mappings, len(all_frameworks),
    )

    return results


def generate_compliance_summary(
    mappings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate a summary of compliance coverage from threat-control mappings.

    Returns:
        Dict with per-framework control coverage statistics
    """
    framework_controls: dict[str, set[str]] = {}
    framework_threats: dict[str, int] = {}

    for m in mappings:
        for control in m["controls"]:
            fw = control["framework"]
            cid = control["control_id"]
            if fw not in framework_controls:
                framework_controls[fw] = set()
                framework_threats[fw] = 0
            framework_controls[fw].add(cid)
            framework_threats[fw] += 1

    summary: dict[str, Any] = {
        "frameworks": {},
        "total_unique_controls": sum(len(cids) for cids in framework_controls.values()),
        "total_mappings": sum(m["controls_count"] for m in mappings),
        "threats_with_mappings": sum(1 for m in mappings if m["controls_count"] > 0),
        "threats_without_mappings": sum(1 for m in mappings if m["controls_count"] == 0),
    }

    for fw, controls in sorted(framework_controls.items()):
        summary["frameworks"][fw] = {
            "unique_controls": len(controls),
            "control_ids": sorted(controls),
            "threat_references": framework_threats[fw],
        }

    return summary
