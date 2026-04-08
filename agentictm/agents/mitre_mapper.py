"""MITRE ATT&CK / CAPEC / D3FEND Mapper — programmatic threat-to-technique mapping.

Maps each threat to relevant:
- MITRE ATT&CK Enterprise techniques (Txxxx)
- CAPEC attack patterns (CAPEC-xxx)
- D3FEND defensive techniques (D3-xxx)

Uses keyword-based matching against curated mappings. For full STIX 2.1
integration, see the mitre/cti and attack-stix-data repositories.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ATT&CK Enterprise techniques  (keywords, ID, name, tactic)
# ---------------------------------------------------------------------------

_ATTACK_TECHNIQUES: list[tuple[list[str], str, str, str]] = [
    # Initial Access
    (
        ["phishing", "spear-phishing", "spearphishing", "social engineering", "malicious email", "email attachment"],
        "T1566", "Phishing", "Initial Access",
    ),
    (
        ["supply chain", "dependency confusion", "package poisoning", "third-party compromise", "upstream compromise"],
        "T1195", "Supply Chain Compromise", "Initial Access",
    ),
    (
        ["valid accounts", "stolen credentials", "credential reuse", "default credentials", "leaked credentials"],
        "T1078", "Valid Accounts", "Initial Access",
    ),
    (
        ["exploit public-facing", "public application", "web exploit", "remote exploit", "server vulnerability"],
        "T1190", "Exploit Public-Facing Application", "Initial Access",
    ),
    (
        ["drive-by", "watering hole", "malicious website", "browser exploit"],
        "T1189", "Drive-by Compromise", "Initial Access",
    ),
    # Execution
    (
        ["command injection", "os command", "shell injection", "arbitrary command", "system command"],
        "T1059", "Command and Scripting Interpreter", "Execution",
    ),
    (
        ["scripting", "powershell", "bash script", "python script", "malicious script", "script execution"],
        "T1059.001", "PowerShell", "Execution",
    ),
    (
        ["api exploitation", "api abuse", "api misuse", "unauthorized api", "api vulnerability"],
        "T1106", "Native API", "Execution",
    ),
    (
        ["serverless", "lambda", "cloud function", "function-as-a-service"],
        "T1648", "Serverless Execution", "Execution",
    ),
    # Persistence
    (
        ["account manipulation", "account creation", "rogue account", "unauthorized account", "create account"],
        "T1098", "Account Manipulation", "Persistence",
    ),
    (
        ["scheduled task", "cron job", "task scheduler", "periodic execution", "timer-based"],
        "T1053", "Scheduled Task/Job", "Persistence",
    ),
    (
        ["implant", "backdoor", "web shell", "persistent access", "reverse shell"],
        "T1505.003", "Web Shell", "Persistence",
    ),
    # Privilege Escalation
    (
        ["privilege escalation", "elevation of privilege", "vertical escalation", "root access", "admin access"],
        "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation",
    ),
    (
        ["access token", "token manipulation", "token impersonation", "stolen token", "jwt tampering"],
        "T1134", "Access Token Manipulation", "Privilege Escalation",
    ),
    # Defense Evasion
    (
        ["obfuscation", "obfuscated", "encoding", "encrypted payload", "packing", "code obfuscation"],
        "T1027", "Obfuscated Files or Information", "Defense Evasion",
    ),
    (
        ["masquerading", "impersonation", "disguise", "spoofing identity", "fake process"],
        "T1036", "Masquerading", "Defense Evasion",
    ),
    # Credential Access
    (
        ["brute force", "password spray", "credential stuffing", "dictionary attack", "password guessing"],
        "T1110", "Brute Force", "Credential Access",
    ),
    (
        ["credential dumping", "password dump", "hash extraction", "lsass", "sam database", "memory scraping"],
        "T1003", "OS Credential Dumping", "Credential Access",
    ),
    (
        ["man-in-the-middle", "mitm", "eavesdrop", "interception", "ssl strip", "arp spoofing"],
        "T1557", "Adversary-in-the-Middle", "Credential Access",
    ),
    # Discovery
    (
        ["network scanning", "port scan", "service discovery", "host discovery", "network enumeration"],
        "T1046", "Network Service Discovery", "Discovery",
    ),
    (
        ["system info", "system information", "fingerprinting", "os detection", "version detection"],
        "T1082", "System Information Discovery", "Discovery",
    ),
    # Lateral Movement
    (
        ["remote service", "ssh", "rdp", "lateral movement", "remote access", "remote login"],
        "T1021", "Remote Services", "Lateral Movement",
    ),
    (
        ["pass-the-hash", "pass the hash", "pth", "hash reuse", "ntlm relay"],
        "T1550.002", "Pass the Hash", "Lateral Movement",
    ),
    # Collection
    (
        ["data from repositories", "source code access", "repository scraping", "database dump", "data harvesting"],
        "T1213", "Data from Information Repositories", "Collection",
    ),
    (
        ["input capture", "keylogger", "keystroke", "screen capture", "clipboard"],
        "T1056", "Input Capture", "Collection",
    ),
    # Exfiltration
    (
        ["exfiltration over web", "data exfiltration", "cloud storage exfil", "upload to external", "data leak"],
        "T1567", "Exfiltration Over Web Service", "Exfiltration",
    ),
    (
        ["exfiltration over c2", "covert channel", "command and control exfil", "c2 exfiltration"],
        "T1041", "Exfiltration Over C2 Channel", "Exfiltration",
    ),
    # Impact
    (
        ["data destruction", "data wipe", "ransomware", "data loss", "file deletion", "disk wipe"],
        "T1485", "Data Destruction", "Impact",
    ),
    (
        ["defacement", "web defacement", "site defacement", "visual tampering"],
        "T1491", "Defacement", "Impact",
    ),
    (
        ["denial of service", "dos", "ddos", "resource exhaustion", "service disruption", "flooding"],
        "T1499", "Endpoint Denial of Service", "Impact",
    ),
]

# ---------------------------------------------------------------------------
# CAPEC attack patterns  (keywords, ID, name)
# ---------------------------------------------------------------------------

_CAPEC_PATTERNS: list[tuple[list[str], str, str]] = [
    (
        ["sql injection", "sqli", "sql query manipulation", "database injection"],
        "CAPEC-66", "SQL Injection",
    ),
    (
        ["command injection", "os injection", "shell injection", "command execution"],
        "CAPEC-88", "OS Command Injection",
    ),
    (
        ["cross-site scripting", "xss", "reflected xss", "stored xss", "dom xss", "script injection"],
        "CAPEC-86", "XSS Through HTTP Headers",
    ),
    (
        ["csrf", "cross-site request forgery", "session riding", "one-click attack"],
        "CAPEC-62", "Cross Site Request Forgery",
    ),
    (
        ["buffer overflow", "stack overflow", "heap overflow", "memory corruption", "buffer overrun"],
        "CAPEC-100", "Overflow Buffers",
    ),
    (
        ["session fixation", "session hijacking", "session stealing", "session token"],
        "CAPEC-61", "Session Fixation",
    ),
    (
        ["privilege escalation", "privilege abuse", "unauthorized privilege", "role escalation"],
        "CAPEC-233", "Privilege Escalation",
    ),
    (
        ["authentication bypass", "auth bypass", "login bypass", "access control bypass"],
        "CAPEC-115", "Authentication Bypass",
    ),
    (
        ["path traversal", "directory traversal", "file inclusion", "lfi", "rfi", "dot-dot-slash"],
        "CAPEC-126", "Path Traversal",
    ),
    (
        ["xml injection", "xpath injection", "xxe", "xml external entity", "xml bomb"],
        "CAPEC-250", "XML Injection",
    ),
    (
        ["ldap injection", "ldap query", "directory service injection"],
        "CAPEC-136", "LDAP Injection",
    ),
    (
        ["phishing", "spear phishing", "social engineering", "deceptive communication"],
        "CAPEC-98", "Phishing",
    ),
    (
        ["man-in-the-middle", "mitm", "interception", "eavesdropping", "on-path attack"],
        "CAPEC-94", "Adversary in the Middle",
    ),
    (
        ["brute force", "password cracking", "credential guessing", "dictionary attack", "exhaustive search"],
        "CAPEC-49", "Password Brute Forcing",
    ),
    (
        ["denial of service", "dos", "ddos", "resource exhaustion", "flooding", "amplification"],
        "CAPEC-125", "Flooding",
    ),
    (
        ["parameter tampering", "input manipulation", "hidden field manipulation", "form tampering"],
        "CAPEC-88", "OS Command Injection",
    ),
    (
        ["deserialization", "insecure deserialization", "object injection", "pickle", "yaml load"],
        "CAPEC-586", "Object Injection",
    ),
]

# ---------------------------------------------------------------------------
# D3FEND defensive techniques  (keywords, ID, name, category)
# ---------------------------------------------------------------------------

_D3FEND_TECHNIQUES: list[tuple[list[str], str, str, str]] = [
    (
        ["network monitoring", "traffic analysis", "ids", "intrusion detection", "network inspection"],
        "D3-NTA", "Network Traffic Analysis", "Detect",
    ),
    (
        ["credential hardening", "credential", "password policy", "mfa", "multi-factor", "strong authentication", "secrets management"],
        "D3-CH", "Credential Hardening", "Harden",
    ),
    (
        ["execution prevention", "application whitelisting", "allowlisting", "execution control"],
        "D3-EP", "Execution Prevention", "Harden",
    ),
    (
        ["file integrity", "file monitoring", "integrity check", "checksum", "hash verification"],
        "D3-FIM", "File Integrity Monitoring", "Detect",
    ),
    (
        ["message authentication", "message signing", "hmac", "digital signature", "message integrity"],
        "D3-MA", "Message Authentication", "Harden",
    ),
    (
        ["encryption", "data encryption", "tls", "ssl", "aes", "at-rest encryption", "in-transit encryption"],
        "D3-DE", "Data Encryption", "Harden",
    ),
    (
        ["input validation", "input sanitization", "input filtering", "parameter validation", "whitelisting input"],
        "D3-IV", "Input Validation", "Harden",
    ),
    (
        ["access control", "rbac", "authorization", "least privilege", "permission management"],
        "D3-AC", "Access Control", "Harden",
    ),
    (
        ["log analysis", "audit log", "siem", "event correlation", "security monitoring"],
        "D3-LA", "Log Analysis", "Detect",
    ),
    (
        ["sandboxing", "sandbox execution", "isolated execution", "containment", "application isolation"],
        "D3-SE", "Sandbox Execution", "Isolate",
    ),
    (
        ["network segmentation", "micro-segmentation", "vlan", "network isolation", "dmz"],
        "D3-NS", "Network Segmentation", "Isolate",
    ),
    (
        ["url filtering", "web filtering", "domain blocking", "proxy filtering", "content filtering"],
        "D3-UF", "URL Filtering", "Detect",
    ),
    (
        ["certificate pinning", "certificate validation", "tls verification", "cert check"],
        "D3-CP", "Certificate Pinning", "Harden",
    ),
    (
        ["backup", "data backup", "disaster recovery", "snapshot", "replication"],
        "D3-BK", "Data Backup", "Harden",
    ),
    (
        ["user behavior", "anomaly detection", "behavioral analysis", "ueba", "baseline deviation"],
        "D3-UBA", "User Behavior Analysis", "Detect",
    ),
    (
        ["process monitoring", "process analysis", "endpoint detection", "edr", "runtime monitoring"],
        "D3-PM", "Process Monitoring", "Detect",
    ),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_search_text(threat: dict[str, Any]) -> str:
    """Combine relevant threat fields into a single lowercased search string."""
    parts = [
        str(threat.get("description", "")),
        str(threat.get("component", "")),
        str(threat.get("mitigation", "")),
        str(threat.get("attack_path", "")),
    ]
    return " ".join(parts).lower()


# ---------------------------------------------------------------------------
# Public mapping functions
# ---------------------------------------------------------------------------

def map_threat_to_attack(threat: dict[str, Any]) -> list[dict[str, str]]:
    """Map a single threat to MITRE ATT&CK techniques."""
    text = _build_search_text(threat)
    matches: list[dict[str, str]] = []
    seen: set[str] = set()

    for keywords, tid, name, tactic in _ATTACK_TECHNIQUES:
        if tid in seen:
            continue
        if any(kw in text for kw in keywords):
            matches.append({
                "technique_id": tid,
                "technique_name": name,
                "tactic": tactic,
                "reference_url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
            })
            seen.add(tid)

    return matches


def map_threat_to_capec(threat: dict[str, Any]) -> list[dict[str, str]]:
    """Map a single threat to CAPEC attack patterns."""
    text = _build_search_text(threat)
    matches: list[dict[str, str]] = []
    seen: set[str] = set()

    for keywords, cid, name in _CAPEC_PATTERNS:
        if cid in seen:
            continue
        if any(kw in text for kw in keywords):
            matches.append({
                "capec_id": cid,
                "pattern_name": name,
                "reference_url": f"https://capec.mitre.org/data/definitions/{cid.split('-')[1]}.html",
            })
            seen.add(cid)

    return matches


def map_threat_to_d3fend(threat: dict[str, Any]) -> list[dict[str, str]]:
    """Map a single threat to D3FEND defensive techniques."""
    text = _build_search_text(threat)
    matches: list[dict[str, str]] = []
    seen: set[str] = set()

    for keywords, did, name, category in _D3FEND_TECHNIQUES:
        if did in seen:
            continue
        if any(kw in text for kw in keywords):
            matches.append({
                "d3fend_id": did,
                "technique_name": name,
                "category": category,
                "reference_url": f"https://d3fend.mitre.org/technique/{did}",
            })
            seen.add(did)

    return matches


def map_all_threats(threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map all threats to MITRE frameworks. Returns enriched threat mappings."""
    results: list[dict[str, Any]] = []
    total_attack = 0
    total_capec = 0
    total_d3fend = 0

    for threat in threats:
        attack = map_threat_to_attack(threat)
        capec = map_threat_to_capec(threat)
        d3fend = map_threat_to_d3fend(threat)

        total_attack += len(attack)
        total_capec += len(capec)
        total_d3fend += len(d3fend)

        results.append({
            "threat_id": threat.get("threat_id") or threat.get("id", ""),
            "attack_techniques": attack,
            "capec_patterns": capec,
            "d3fend_techniques": d3fend,
        })

    logger.info(
        "MITRE mapping complete: %d threats → %d ATT&CK, %d CAPEC, %d D3FEND matches",
        len(threats), total_attack, total_capec, total_d3fend,
    )
    return results
