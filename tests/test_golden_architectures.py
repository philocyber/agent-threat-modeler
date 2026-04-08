"""Golden Test Suite — reference architectures for regression testing.

Each architecture defines:
  - Realistic system description (200+ words)
  - Expected minimum threat count
  - Expected STRIDE coverage
  - Expected key threat categories
  - Architecture reviewer complexity classification
  - MITRE mapping generation
"""

from __future__ import annotations

import math
from typing import Any

import pytest


# ═══════════════════════════════════════════════════════════════════════════
# Architecture 1: E-Commerce Platform
# ═══════════════════════════════════════════════════════════════════════════

ECOMMERCE_DESCRIPTION = """
E-Commerce Platform — Cloud-Native Microservices Architecture

System Overview:
A high-availability e-commerce platform serving 2M monthly active users with
real-time inventory management, payment processing, and personalised product
recommendations powered by machine learning.

Components:
- Web Frontend: React SPA with server-side rendering (Next.js), served via
  CloudFront CDN with WAF rules for bot protection.
- Mobile App: React Native iOS/Android app communicating via REST + GraphQL.
- API Gateway: AWS API Gateway with Lambda authorizers for JWT validation,
  rate limiting (10K req/min), and request transformation.
- Product Catalog Service: Go microservice backed by PostgreSQL 15 with
  read replicas and Redis cache (TTL 5min). Handles search via Elasticsearch.
- Order Service: Java Spring Boot microservice managing order lifecycle,
  publishes events to Amazon SQS for downstream processing.
- Payment Service: PCI-DSS Level 1 compliant Python service integrating
  Stripe and PayPal APIs. Tokenises card data; no PAN stored locally.
- Inventory Service: Rust microservice for real-time stock tracking with
  optimistic locking. Publishes stock-level events to Kafka.
- Recommendation Engine: TensorFlow Serving model retrained daily on user
  behaviour data. Reads from feature store (Redis) and clickstream (Kinesis).
- User Service: Node.js service managing authentication (OAuth 2.0 + PKCE),
  user profiles, and GDPR consent. Stores PII in encrypted PostgreSQL columns.
- Notification Service: Sends transactional emails (SES), SMS (Twilio), and
  push notifications (Firebase). Processes async via SQS.
- Monitoring Stack: Datadog APM + CloudWatch + PagerDuty alerting.
- CI/CD: GitHub Actions → ECR → ECS Fargate blue/green deployments.

Data Flows:
- User → CDN → API Gateway → microservices (mTLS between services)
- Payment Service → Stripe API (TLS 1.3, webhook verification via HMAC)
- Order events → SQS → Inventory + Notification services
- Clickstream → Kinesis → S3 data lake → Recommendation retraining pipeline
- All services → Datadog via OpenTelemetry agents

Trust Boundaries:
- Public Internet: CDN, API Gateway
- DMZ: API Gateway Lambda authorizers
- Internal VPC: All microservices, databases
- PCI Zone: Payment Service (isolated subnet, NACLs, no direct internet)
- External: Stripe, PayPal, Twilio, Firebase, Datadog
"""

ECOMMERCE_THREATS = [
    {"id": "EC-01", "description": "SQL injection in product search allowing catalog data exfiltration via Elasticsearch query manipulation", "component": "Product Catalog Service", "stride_category": "T", "priority": "Critical", "dread_total": 38, "methodology": "STRIDE", "evidence_sources": [{"source_type": "rag", "source_name": "OWASP Top 10", "excerpt": "A03:2021 Injection"}], "mitigation": "Parameterised queries, input sanitisation, WAF rules"},
    {"id": "EC-02", "description": "Payment token replay attack due to insufficient nonce validation in Stripe webhook handler", "component": "Payment Service", "stride_category": "S", "priority": "Critical", "dread_total": 40, "methodology": "STRIDE", "evidence_sources": [{"source_type": "rag", "source_name": "PCI-DSS v4.0", "excerpt": "Req 6.2.4 - Injection prevention"}], "mitigation": "HMAC verification, idempotency keys, webhook signature validation"},
    {"id": "EC-03", "description": "IDOR vulnerability allowing users to view other customers' order history by manipulating order IDs", "component": "Order Service", "stride_category": "I", "priority": "High", "dread_total": 35, "methodology": "STRIDE", "evidence_sources": [{"source_type": "rag", "source_name": "OWASP Top 10", "excerpt": "A01:2021 Broken Access Control"}], "mitigation": "Object-level authorisation checks, UUIDs instead of sequential IDs"},
    {"id": "EC-04", "description": "Denial of service via inventory exhaustion attack flooding cart reservations without completing purchase", "component": "Inventory Service", "stride_category": "D", "priority": "High", "dread_total": 33, "methodology": "PASTA", "evidence_sources": [], "mitigation": "Cart reservation TTL, rate limiting per user, CAPTCHA on checkout"},
    {"id": "EC-05", "description": "PII leakage through recommendation engine training data containing unmasked user behaviour patterns", "component": "Recommendation Engine", "stride_category": "I", "priority": "High", "dread_total": 34, "methodology": "PASTA", "evidence_sources": [{"source_type": "rag", "source_name": "GDPR Article 25", "excerpt": "Data minimisation by design"}], "mitigation": "Differential privacy in training pipeline, PII masking in feature store"},
    {"id": "EC-06", "description": "JWT token theft via XSS in React SPA allowing session hijacking across all services", "component": "Web Frontend", "stride_category": "S", "priority": "High", "dread_total": 36, "methodology": "STRIDE", "evidence_sources": [{"source_type": "rag", "source_name": "OWASP Top 10", "excerpt": "A07:2021 XSS"}], "mitigation": "CSP headers, HttpOnly cookies, token rotation"},
    {"id": "EC-07", "description": "Privilege escalation through API Gateway Lambda authorizer bypass via malformed JWT header", "component": "API Gateway", "stride_category": "E", "priority": "Critical", "dread_total": 39, "methodology": "STRIDE", "evidence_sources": [], "mitigation": "Strict JWT parsing, algorithm pinning (RS256 only), key rotation"},
    {"id": "EC-08", "description": "Supply chain attack via compromised npm dependency in React frontend build pipeline", "component": "CI/CD", "stride_category": "T", "priority": "Medium", "dread_total": 30, "methodology": "ATTACK_TREE", "evidence_sources": [{"source_type": "rag", "source_name": "SLSA Framework", "excerpt": "Build integrity requirements"}], "mitigation": "Dependency pinning, Dependabot alerts, SBOM generation, lockfile verification"},
    {"id": "EC-09", "description": "Man-in-the-middle attack on inter-service communication if mTLS certificate rotation fails", "component": "Internal VPC", "stride_category": "T", "priority": "Medium", "dread_total": 28, "methodology": "STRIDE", "evidence_sources": [], "mitigation": "Automated cert rotation, service mesh (Istio), certificate monitoring"},
    {"id": "EC-10", "description": "Repudiation of order cancellations due to insufficient audit logging in Order Service", "component": "Order Service", "stride_category": "R", "priority": "Medium", "dread_total": 26, "methodology": "STRIDE", "evidence_sources": [], "mitigation": "Immutable audit logs, event sourcing, tamper-evident logging"},
]

ECOMMERCE_STATE: dict[str, Any] = {
    "system_name": "E-Commerce Platform",
    "analysis_date": "2026-04-06",
    "raw_input": ECOMMERCE_DESCRIPTION,
    "input_type": "text",
    "system_description": "Cloud-native e-commerce platform with microservices, payment processing, ML recommendations, and real-time inventory.",
    "components": [
        {"name": "Web Frontend", "type": "web_app"},
        {"name": "Mobile App", "type": "mobile_app"},
        {"name": "API Gateway", "type": "gateway"},
        {"name": "Product Catalog Service", "type": "microservice"},
        {"name": "Order Service", "type": "microservice"},
        {"name": "Payment Service", "type": "microservice"},
        {"name": "Inventory Service", "type": "microservice"},
        {"name": "Recommendation Engine", "type": "ml_service"},
        {"name": "User Service", "type": "microservice"},
        {"name": "Notification Service", "type": "microservice"},
        {"name": "Monitoring Stack", "type": "monitoring"},
        {"name": "CI/CD", "type": "devops"},
    ],
    "data_flows": [
        {"source": "User", "destination": "CDN", "protocol": "HTTPS"},
        {"source": "CDN", "destination": "API Gateway", "protocol": "HTTPS"},
        {"source": "Payment Service", "destination": "Stripe", "protocol": "TLS 1.3"},
    ],
    "trust_boundaries": [
        {"name": "Public Internet", "components": ["CDN", "API Gateway"]},
        {"name": "Internal VPC", "components": ["Product Catalog", "Order Service", "Payment Service"]},
        {"name": "PCI Zone", "components": ["Payment Service"]},
    ],
    "external_entities": [
        {"name": "Stripe"}, {"name": "PayPal"}, {"name": "Twilio"},
        {"name": "Firebase"}, {"name": "Datadog"},
    ],
    "data_stores": [
        {"name": "PostgreSQL"}, {"name": "Redis"}, {"name": "Elasticsearch"},
        {"name": "Amazon SQS"}, {"name": "Kafka"}, {"name": "S3"},
    ],
    "threats_final": ECOMMERCE_THREATS,
    "methodology_reports": [
        {"methodology": "STRIDE", "agent": "stride_analyst", "report": "", "threats_raw": []},
        {"methodology": "PASTA", "agent": "pasta_analyst", "report": "", "threats_raw": []},
        {"methodology": "ATTACK_TREE", "agent": "attack_tree_analyst", "report": "", "threats_raw": []},
    ],
    "debate_history": [],
    "executive_summary": "E-Commerce platform threat model",
    "debate_round": 1,
    "max_debate_rounds": 4,
    "iteration_count": 0,
    "threat_categories": ["base", "web", "supply_chain"],
}


# ═══════════════════════════════════════════════════════════════════════════
# Architecture 2: Healthcare Records System
# ═══════════════════════════════════════════════════════════════════════════

HEALTHCARE_DESCRIPTION = """
Healthcare Records System — HIPAA-Compliant EHR Platform

System Overview:
An electronic health records (EHR) platform used by 500+ healthcare providers
to manage patient records, lab results, prescriptions, and insurance claims.
The system must comply with HIPAA, HITECH, and HL7 FHIR R4 standards.

Components:
- Provider Portal: Angular SPA with role-based access (physician, nurse,
  admin, billing). Two-factor authentication via Duo Security.
- Patient Portal: React app for patients to view records, schedule
  appointments, and message providers. Biometric login on mobile.
- FHIR API Server: HAPI FHIR R4 compliant Java server exposing RESTful
  endpoints for interoperability with external EHR systems and labs.
- Identity Provider: Keycloak with SAML 2.0 and OpenID Connect for SSO
  across all portals. Manages provider credentials and patient consent.
- Clinical Data Service: .NET Core microservice handling patient records,
  diagnoses (ICD-10 codes), and treatment plans. Enforces break-the-glass
  access for emergency situations.
- Prescription Service: Python FastAPI service integrating with NCPDP SCRIPT
  standard for e-prescribing. Validates controlled substance schedules.
- Lab Integration Service: HL7v2 message broker connecting to external
  laboratory information systems (LIS) via MLLP/TLS.
- Insurance Claims Engine: Java service processing EDI 837/835 transactions
  with payer systems. Handles prior authorisation workflows.
- Encrypted Database: PostgreSQL 16 with Transparent Data Encryption (TDE),
  column-level encryption for PHI, and row-level security per provider group.
- Audit Service: Immutable audit log (append-only PostgreSQL + S3 archival)
  tracking all PHI access per HIPAA §164.312(b). 7-year retention.
- Document Storage: MinIO with AES-256 encryption at rest for medical images
  (DICOM), scanned documents, and lab reports.
- Message Bus: RabbitMQ for async processing of lab results, claims, and
  notifications. Dead-letter queues for failed message handling.
- Monitoring: Splunk SIEM + Nagios infrastructure monitoring.
- Backup: Daily encrypted snapshots to AWS S3 Glacier with cross-region
  replication. RPO: 1 hour, RTO: 4 hours.

Data Flows:
- Provider → Portal → FHIR API → Clinical Data Service → Encrypted DB
- Lab results: External LIS → HL7v2 → Lab Integration → RabbitMQ → Clinical Data
- Prescriptions: Provider → Prescription Service → NCPDP → Pharmacy
- Insurance: Clinical Data → Claims Engine → EDI → Payer systems
- All PHI access → Audit Service (synchronous pre-access check)
- Patient consent: Identity Provider → Clinical Data Service (consent enforcement)

Trust Boundaries:
- Public Internet: Patient Portal, Provider Portal (behind WAF)
- DMZ: FHIR API Server (for external EHR interoperability)
- Internal: Clinical Data, Prescription, Lab Integration, Claims Engine
- Restricted: Encrypted Database, Audit Service, Document Storage
- External: Labs, Pharmacies, Insurance Payers, Duo Security, Splunk
"""

HEALTHCARE_THREATS = [
    {"id": "HC-01", "description": "PHI data breach through FHIR API misconfigured SMART on FHIR scopes exposing patient records to unauthorised third-party apps", "component": "FHIR API Server", "stride_category": "I", "priority": "Critical", "dread_total": 42, "methodology": "STRIDE", "evidence_sources": [{"source_type": "rag", "source_name": "HIPAA §164.312", "excerpt": "Access control requirements"}], "mitigation": "Strict SMART scope validation, OAuth consent screen, API access audit"},
    {"id": "HC-02", "description": "Identity spoofing via stolen provider credentials bypassing 2FA through session fixation in Keycloak", "component": "Identity Provider", "stride_category": "S", "priority": "Critical", "dread_total": 40, "methodology": "STRIDE", "evidence_sources": [{"source_type": "rag", "source_name": "OWASP Top 10", "excerpt": "A07:2021 Authentication Failures"}], "mitigation": "Session rotation on auth, Duo push notification, IP-based risk scoring"},
    {"id": "HC-03", "description": "HL7v2 message injection through malformed lab results allowing insertion of fabricated diagnoses", "component": "Lab Integration Service", "stride_category": "T", "priority": "High", "dread_total": 36, "methodology": "PASTA", "evidence_sources": [{"source_type": "rag", "source_name": "HL7 Security Guide", "excerpt": "Message validation requirements"}], "mitigation": "HL7v2 schema validation, digital signatures on lab messages, sender verification"},
    {"id": "HC-04", "description": "Break-the-glass abuse by non-emergency staff accessing restricted patient records without legitimate need", "component": "Clinical Data Service", "stride_category": "E", "priority": "High", "dread_total": 35, "methodology": "STRIDE", "evidence_sources": [{"source_type": "rag", "source_name": "HIPAA §164.312(a)", "excerpt": "Emergency access procedure"}], "mitigation": "Post-access review workflow, anomaly detection, mandatory justification"},
    {"id": "HC-05", "description": "Prescription forgery through manipulation of NCPDP SCRIPT messages for controlled substances", "component": "Prescription Service", "stride_category": "T", "priority": "Critical", "dread_total": 38, "methodology": "PASTA", "evidence_sources": [], "mitigation": "Digital signing of prescriptions, DEA number validation, dual-authorisation for Schedule II"},
    {"id": "HC-06", "description": "Audit log tampering by compromised admin account undermining HIPAA compliance evidence", "component": "Audit Service", "stride_category": "R", "priority": "High", "dread_total": 34, "methodology": "STRIDE", "evidence_sources": [{"source_type": "rag", "source_name": "HIPAA §164.312(b)", "excerpt": "Audit controls"}], "mitigation": "Append-only storage, WORM compliance, separate admin credentials for audit"},
    {"id": "HC-07", "description": "Ransomware attack encrypting patient database and document storage disrupting clinical operations", "component": "Encrypted Database", "stride_category": "D", "priority": "Critical", "dread_total": 41, "methodology": "ATTACK_TREE", "evidence_sources": [], "mitigation": "Air-gapped backups, network segmentation, endpoint detection, incident response plan"},
    {"id": "HC-08", "description": "Insurance claim fraud through EDI transaction manipulation in Claims Engine", "component": "Insurance Claims Engine", "stride_category": "T", "priority": "Medium", "dread_total": 30, "methodology": "PASTA", "evidence_sources": [], "mitigation": "EDI validation rules, claim pattern analysis, provider credentialling"},
    {"id": "HC-09", "description": "Patient data exfiltration via DICOM image metadata containing embedded PHI in medical images", "component": "Document Storage", "stride_category": "I", "priority": "High", "dread_total": 33, "methodology": "STRIDE", "evidence_sources": [], "mitigation": "DICOM de-identification, metadata scrubbing, DLP controls"},
    {"id": "HC-10", "description": "Consent bypass allowing data sharing with research systems without explicit patient opt-in", "component": "Identity Provider", "stride_category": "I", "priority": "High", "dread_total": 35, "methodology": "STRIDE", "evidence_sources": [{"source_type": "rag", "source_name": "GDPR Article 7", "excerpt": "Conditions for consent"}], "mitigation": "Granular consent management, purpose limitation enforcement, consent audit trail"},
]

HEALTHCARE_STATE: dict[str, Any] = {
    "system_name": "Healthcare Records System",
    "analysis_date": "2026-04-06",
    "raw_input": HEALTHCARE_DESCRIPTION,
    "input_type": "text",
    "system_description": "HIPAA-compliant EHR platform with FHIR API, e-prescribing, lab integration, and insurance claims processing.",
    "components": [
        {"name": "Provider Portal", "type": "web_app"},
        {"name": "Patient Portal", "type": "web_app"},
        {"name": "FHIR API Server", "type": "api"},
        {"name": "Identity Provider", "type": "identity"},
        {"name": "Clinical Data Service", "type": "microservice"},
        {"name": "Prescription Service", "type": "microservice"},
        {"name": "Lab Integration Service", "type": "integration"},
        {"name": "Insurance Claims Engine", "type": "microservice"},
        {"name": "Encrypted Database", "type": "database"},
        {"name": "Audit Service", "type": "audit"},
        {"name": "Document Storage", "type": "storage"},
        {"name": "Message Bus", "type": "message_queue"},
        {"name": "Monitoring", "type": "monitoring"},
    ],
    "data_flows": [
        {"source": "Provider", "destination": "FHIR API", "protocol": "HTTPS"},
        {"source": "Lab Integration", "destination": "RabbitMQ", "protocol": "AMQPS"},
        {"source": "Prescription Service", "destination": "Pharmacy", "protocol": "NCPDP"},
    ],
    "trust_boundaries": [
        {"name": "Public Internet", "components": ["Patient Portal", "Provider Portal"]},
        {"name": "DMZ", "components": ["FHIR API Server"]},
        {"name": "Internal", "components": ["Clinical Data Service", "Prescription Service"]},
        {"name": "Restricted", "components": ["Encrypted Database", "Audit Service"]},
    ],
    "external_entities": [
        {"name": "Labs"}, {"name": "Pharmacies"}, {"name": "Insurance Payers"},
        {"name": "Duo Security"}, {"name": "Splunk"},
    ],
    "data_stores": [
        {"name": "PostgreSQL (Encrypted)"}, {"name": "MinIO"},
        {"name": "S3 Glacier"}, {"name": "RabbitMQ"},
    ],
    "threats_final": HEALTHCARE_THREATS,
    "methodology_reports": [
        {"methodology": "STRIDE", "agent": "stride_analyst", "report": "", "threats_raw": []},
        {"methodology": "PASTA", "agent": "pasta_analyst", "report": "", "threats_raw": []},
        {"methodology": "ATTACK_TREE", "agent": "attack_tree_analyst", "report": "", "threats_raw": []},
    ],
    "debate_history": [],
    "executive_summary": "Healthcare EHR threat model",
    "debate_round": 1,
    "max_debate_rounds": 4,
    "iteration_count": 0,
    "threat_categories": ["base", "web", "privacy"],
}


# ═══════════════════════════════════════════════════════════════════════════
# Architecture 3: IoT Fleet Management
# ═══════════════════════════════════════════════════════════════════════════

IOT_DESCRIPTION = """
IoT Fleet Management Platform — Industrial Edge-to-Cloud Architecture

System Overview:
A fleet management system monitoring 50,000+ industrial IoT devices (GPS
trackers, temperature sensors, fuel gauges, OBD-II adapters) across a
logistics network. Provides real-time telemetry, predictive maintenance,
route optimisation, and regulatory compliance reporting.

Components:
- Edge Devices: ARM Cortex-M4 based sensors running FreeRTOS with secure
  boot and hardware crypto (ATECC608B). Each device has a unique X.509
  certificate for mutual TLS authentication.
- Edge Gateway: Raspberry Pi 4 running Linux with containerised MQTT bridge.
  Aggregates data from 50-100 sensors per gateway, applies edge ML inference
  for anomaly detection, and forwards to cloud via cellular (4G/5G).
- MQTT Broker: Eclipse Mosquitto cluster (3 nodes) with TLS 1.3, ACL-based
  topic authorisation, and persistent sessions. Handles 500K msg/sec.
- Cloud Gateway: AWS IoT Core with custom Lambda authoriser for device
  authentication. Routes messages via IoT Rules Engine to downstream services.
- Device Registry: DynamoDB table tracking device metadata, firmware versions,
  certificate status, and provisioning state. Supports fleet-wide OTA updates.
- Time-Series Database: InfluxDB cluster storing telemetry data (GPS coords,
  temperature, fuel levels, engine diagnostics). 90-day hot retention,
  S3 cold archival. Handles 2M writes/sec at peak.
- Fleet Analytics Service: Python service running predictive maintenance ML
  models (scikit-learn + TensorFlow Lite). Generates maintenance alerts and
  fleet health dashboards.
- Route Optimisation Engine: Rust microservice computing optimal routes using
  real-time traffic, weather, and fuel efficiency data. Integrates with
  Google Maps Platform and OpenWeatherMap APIs.
- Geofencing Service: Go service managing virtual geographic boundaries with
  real-time entry/exit alerts for compliance zones and restricted areas.
- Firmware Update Service: Manages OTA firmware distribution with A/B
  partition rollback. Signs firmware with Ed25519 keys; validates on device.
- Dashboard: Vue.js SPA with WebSocket real-time map, fleet status, alerts,
  and reporting. Role-based access (fleet manager, driver, maintenance tech).
- Notification Service: Multi-channel alerts (SMS via Twilio, email via SES,
  push via FCM) for geofence violations, maintenance due, and anomalies.

Data Flows:
- Sensors → Edge Gateway (BLE/Zigbee) → MQTT (TLS) → Cloud Gateway
- Cloud Gateway → IoT Rules → Time-Series DB + Analytics + Geofencing
- Dashboard ↔ WebSocket server ↔ Redis Pub/Sub ↔ Backend services
- Firmware Update Service → S3 → Edge Gateway → Devices (signed OTA)
- Analytics → Route Optimisation → Dashboard (maintenance + routing alerts)

Trust Boundaries:
- Physical Edge: Sensors, Edge Gateways (field-deployed, physically exposed)
- Wireless Network: BLE/Zigbee mesh, cellular uplink
- Cloud DMZ: MQTT Broker, Cloud Gateway, IoT Core
- Internal Cloud: Analytics, Route Optimisation, Geofencing, Dashboard API
- External: Google Maps, OpenWeatherMap, Twilio, FCM
"""

IOT_THREATS = [
    {"id": "IOT-01", "description": "Device certificate theft from physically exposed edge gateways enabling rogue device impersonation", "component": "Edge Gateway", "stride_category": "S", "priority": "Critical", "dread_total": 38, "methodology": "STRIDE", "evidence_sources": [{"source_type": "rag", "source_name": "OWASP IoT Top 10", "excerpt": "I1 - Weak authentication"}], "mitigation": "Hardware security module (HSM), certificate pinning, device attestation"},
    {"id": "IOT-02", "description": "MQTT topic hijacking allowing attacker to publish false telemetry data poisoning fleet analytics", "component": "MQTT Broker", "stride_category": "T", "priority": "Critical", "dread_total": 39, "methodology": "STRIDE", "evidence_sources": [{"source_type": "rag", "source_name": "OWASP IoT Top 10", "excerpt": "I3 - Insecure ecosystem interfaces"}], "mitigation": "Per-device topic ACLs, message signing, anomaly detection on telemetry patterns"},
    {"id": "IOT-03", "description": "Malicious firmware update deploying rootkit to entire fleet via compromised OTA signing key", "component": "Firmware Update Service", "stride_category": "T", "priority": "Critical", "dread_total": 42, "methodology": "ATTACK_TREE", "evidence_sources": [], "mitigation": "HSM-protected signing keys, dual-signature requirement, staged rollout with canary"},
    {"id": "IOT-04", "description": "GPS spoofing attack manipulating vehicle location data to circumvent geofencing compliance zones", "component": "Edge Devices", "stride_category": "T", "priority": "High", "dread_total": 35, "methodology": "PASTA", "evidence_sources": [], "mitigation": "Multi-source location validation, cellular triangulation cross-check, anomaly detection"},
    {"id": "IOT-05", "description": "Denial of service via cellular bandwidth exhaustion flooding MQTT broker with malformed packets", "component": "Cloud Gateway", "stride_category": "D", "priority": "High", "dread_total": 33, "methodology": "STRIDE", "evidence_sources": [], "mitigation": "Rate limiting per device, message size limits, IoT Core throttling rules"},
    {"id": "IOT-06", "description": "Predictive maintenance model poisoning through injected anomalous sensor readings corrupting ML training data", "component": "Fleet Analytics Service", "stride_category": "T", "priority": "High", "dread_total": 34, "methodology": "PASTA", "evidence_sources": [{"source_type": "rag", "source_name": "NIST AI RMF", "excerpt": "Data integrity for ML models"}], "mitigation": "Statistical outlier filtering, training data provenance, model versioning with rollback"},
    {"id": "IOT-07", "description": "Unauthorised access to time-series database exposing fleet movement patterns and operational intelligence", "component": "Time-Series Database", "stride_category": "I", "priority": "High", "dread_total": 35, "methodology": "STRIDE", "evidence_sources": [], "mitigation": "VPC isolation, IAM policies, query-level access control, data encryption at rest"},
    {"id": "IOT-08", "description": "BLE relay attack on sensor-to-gateway communication intercepting and replaying telemetry packets", "component": "Edge Devices", "stride_category": "S", "priority": "Medium", "dread_total": 28, "methodology": "ATTACK_TREE", "evidence_sources": [{"source_type": "rag", "source_name": "OWASP IoT Top 10", "excerpt": "I9 - Insecure default settings"}], "mitigation": "BLE Secure Connections, session nonces, proximity verification"},
    {"id": "IOT-09", "description": "Geofence boundary manipulation through dashboard CSRF allowing compliance zone modifications", "component": "Dashboard", "stride_category": "E", "priority": "Medium", "dread_total": 30, "methodology": "STRIDE", "evidence_sources": [{"source_type": "rag", "source_name": "OWASP Top 10", "excerpt": "A01:2021 Broken Access Control"}], "mitigation": "CSRF tokens, role-based geofence editing, change approval workflow"},
    {"id": "IOT-10", "description": "Lack of audit trail for device decommissioning enabling ghost devices to persist on the network", "component": "Device Registry", "stride_category": "R", "priority": "Medium", "dread_total": 27, "methodology": "STRIDE", "evidence_sources": [], "mitigation": "Immutable device lifecycle log, certificate revocation on decommission, periodic fleet audit"},
]

IOT_STATE: dict[str, Any] = {
    "system_name": "IoT Fleet Management",
    "analysis_date": "2026-04-06",
    "raw_input": IOT_DESCRIPTION,
    "input_type": "text",
    "system_description": "Industrial IoT fleet management with edge devices, MQTT, cloud gateway, time-series DB, and predictive maintenance.",
    "components": [
        {"name": "Edge Devices", "type": "iot_device"},
        {"name": "Edge Gateway", "type": "gateway"},
        {"name": "MQTT Broker", "type": "message_broker"},
        {"name": "Cloud Gateway", "type": "gateway"},
        {"name": "Device Registry", "type": "database"},
        {"name": "Time-Series Database", "type": "database"},
        {"name": "Fleet Analytics Service", "type": "ml_service"},
        {"name": "Route Optimisation Engine", "type": "microservice"},
        {"name": "Geofencing Service", "type": "microservice"},
        {"name": "Firmware Update Service", "type": "microservice"},
        {"name": "Dashboard", "type": "web_app"},
        {"name": "Notification Service", "type": "microservice"},
    ],
    "data_flows": [
        {"source": "Sensors", "destination": "Edge Gateway", "protocol": "BLE/Zigbee"},
        {"source": "Edge Gateway", "destination": "MQTT Broker", "protocol": "MQTT/TLS"},
        {"source": "Cloud Gateway", "destination": "Time-Series DB", "protocol": "HTTPS"},
    ],
    "trust_boundaries": [
        {"name": "Physical Edge", "components": ["Edge Devices", "Edge Gateway"]},
        {"name": "Cloud DMZ", "components": ["MQTT Broker", "Cloud Gateway"]},
        {"name": "Internal Cloud", "components": ["Analytics", "Geofencing", "Dashboard"]},
    ],
    "external_entities": [
        {"name": "Google Maps"}, {"name": "OpenWeatherMap"},
        {"name": "Twilio"}, {"name": "FCM"},
    ],
    "data_stores": [
        {"name": "DynamoDB"}, {"name": "InfluxDB"}, {"name": "S3"}, {"name": "Redis"},
    ],
    "threats_final": IOT_THREATS,
    "methodology_reports": [
        {"methodology": "STRIDE", "agent": "stride_analyst", "report": "", "threats_raw": []},
        {"methodology": "PASTA", "agent": "pasta_analyst", "report": "", "threats_raw": []},
        {"methodology": "ATTACK_TREE", "agent": "attack_tree_analyst", "report": "", "threats_raw": []},
    ],
    "debate_history": [],
    "executive_summary": "IoT Fleet Management threat model",
    "debate_round": 1,
    "max_debate_rounds": 4,
    "iteration_count": 0,
    "threat_categories": ["base", "iot"],
}


# ═══════════════════════════════════════════════════════════════════════════
# Parametrised test fixtures
# ═══════════════════════════════════════════════════════════════════════════

GOLDEN_ARCHS = [
    pytest.param(ECOMMERCE_STATE, ECOMMERCE_THREATS, "E-Commerce Platform", id="ecommerce"),
    pytest.param(HEALTHCARE_STATE, HEALTHCARE_THREATS, "Healthcare Records", id="healthcare"),
    pytest.param(IOT_STATE, IOT_THREATS, "IoT Fleet Management", id="iot"),
]


# ═══════════════════════════════════════════════════════════════════════════
# Test Suite
# ═══════════════════════════════════════════════════════════════════════════


class TestGoldenThreatCount:
    """Each architecture must produce a minimum number of threats."""

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_minimum_threat_count(self, state, threats, name):
        assert len(threats) >= 8, f"{name} should have >= 8 threats, got {len(threats)}"

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_threat_count_within_bounds(self, state, threats, name):
        assert len(threats) <= 40, f"{name} should have <= 40 threats, got {len(threats)}"


class TestGoldenStrideCoverage:
    """Each architecture should cover at least 5 STRIDE categories."""

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_stride_coverage_breadth(self, state, threats, name):
        categories = {t.get("stride_category", "").upper() for t in threats if t.get("stride_category")}
        assert len(categories) >= 5, f"{name}: expected 5+ STRIDE categories, got {categories}"

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_stride_has_spoofing(self, state, threats, name):
        categories = {t.get("stride_category", "").upper() for t in threats}
        assert "S" in categories, f"{name} missing Spoofing (S)"

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_stride_has_tampering(self, state, threats, name):
        categories = {t.get("stride_category", "").upper() for t in threats}
        assert "T" in categories, f"{name} missing Tampering (T)"

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_stride_has_information_disclosure(self, state, threats, name):
        categories = {t.get("stride_category", "").upper() for t in threats}
        assert "I" in categories, f"{name} missing Information Disclosure (I)"


class TestGoldenThreatCategories:
    """Threats should include expected categories for each domain."""

    def test_ecommerce_has_payment_threats(self):
        descs = " ".join(t["description"] for t in ECOMMERCE_THREATS).lower()
        assert "payment" in descs or "stripe" in descs or "pci" in descs

    def test_ecommerce_has_supply_chain_threats(self):
        descs = " ".join(t["description"] for t in ECOMMERCE_THREATS).lower()
        assert "supply chain" in descs or "npm" in descs or "dependency" in descs

    def test_healthcare_has_phi_threats(self):
        descs = " ".join(t["description"] for t in HEALTHCARE_THREATS).lower()
        assert "phi" in descs or "patient" in descs or "hipaa" in descs

    def test_healthcare_has_prescription_threats(self):
        descs = " ".join(t["description"] for t in HEALTHCARE_THREATS).lower()
        assert "prescription" in descs or "ncpdp" in descs

    def test_iot_has_firmware_threats(self):
        descs = " ".join(t["description"] for t in IOT_THREATS).lower()
        assert "firmware" in descs or "ota" in descs

    def test_iot_has_mqtt_threats(self):
        descs = " ".join(t["description"] for t in IOT_THREATS).lower()
        assert "mqtt" in descs


class TestGoldenArchitectureReviewer:
    """Architecture reviewer should classify complexity correctly."""

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_reviewer_returns_required_fields(self, state, threats, name):
        from agentictm.agents.architecture_reviewer import run_architecture_reviewer
        result = run_architecture_reviewer(state, llm=None)
        assert "architecture_review" in result
        assert "threat_surface_summary" in result
        assert "system_complexity" in result

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_reviewer_classifies_as_moderate_or_complex(self, state, threats, name):
        from agentictm.agents.architecture_reviewer import run_architecture_reviewer
        result = run_architecture_reviewer(state, llm=None)
        assert result["system_complexity"] in ("moderate", "complex"), \
            f"{name} complexity: {result['system_complexity']}"

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_reviewer_produces_quality_score(self, state, threats, name):
        from agentictm.agents.architecture_reviewer import run_architecture_reviewer
        result = run_architecture_reviewer(state, llm=None)
        score = result["architecture_review"]["quality_score"]
        assert 0 <= score <= 100

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_reviewer_detects_gaps_reasonably(self, state, threats, name):
        from agentictm.agents.architecture_reviewer import run_architecture_reviewer
        result = run_architecture_reviewer(state, llm=None)
        gaps = result["architecture_review"]["gaps"]
        assert isinstance(gaps, list)


class TestGoldenMitreMapping:
    """MITRE mappings should be generated for each architecture."""

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_mitre_mappings_generated(self, state, threats, name):
        from agentictm.agents.mitre_mapper import map_all_threats
        mappings = map_all_threats(threats)
        assert len(mappings) == len(threats)

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_mitre_mapping_rate(self, state, threats, name):
        from agentictm.agents.mitre_mapper import map_all_threats
        mappings = map_all_threats(threats)
        mapped = sum(
            1 for m in mappings
            if m.get("attack_techniques") or m.get("capec_patterns")
        )
        rate = mapped / len(threats) if threats else 0
        assert rate >= 0.25, f"{name}: MITRE mapping rate {rate:.0%} < 25%"

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_mitre_has_reference_urls(self, state, threats, name):
        from agentictm.agents.mitre_mapper import map_all_threats
        mappings = map_all_threats(threats)
        for m in mappings:
            for t in m.get("attack_techniques", []):
                assert "reference_url" in t
                assert t["reference_url"].startswith("https://")


class TestGoldenOutputQuality:
    """Cross-cutting quality checks for all golden architectures."""

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_evidence_rate(self, state, threats, name):
        with_evidence = sum(
            1 for t in threats
            if t.get("evidence_sources") and len(t["evidence_sources"]) > 0
        )
        rate = with_evidence / len(threats) if threats else 0
        assert rate >= 0.4, f"{name}: evidence rate {rate:.0%} < 40%"

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_component_coverage(self, state, threats, name):
        threat_components = {t.get("component", "") for t in threats if t.get("component")}
        total_components = len(state.get("components", []))
        if total_components == 0:
            return
        coverage = len(threat_components) / total_components
        assert coverage >= 0.4, f"{name}: component coverage {coverage:.0%} < 40%"

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_dread_distribution(self, state, threats, name):
        scores = [t.get("dread_total", 0) for t in threats]
        if len(scores) < 2:
            return
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        std_dev = math.sqrt(variance)
        assert std_dev > 1.5, f"{name}: DREAD std dev {std_dev:.2f} < 1.5"

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_all_output_formats(self, state, threats, name):
        from agentictm.agents.report_generator import (
            generate_csv, generate_markdown_report, generate_sarif,
        )
        csv_out = generate_csv(state)
        md_out = generate_markdown_report(state)
        sarif_out = generate_sarif(state)
        assert len(csv_out) > 50, f"{name}: CSV empty"
        assert len(md_out) > 200, f"{name}: Markdown empty"
        assert len(sarif_out) > 100, f"{name}: SARIF empty"

    @pytest.mark.parametrize("state,threats,name", GOLDEN_ARCHS)
    def test_hallucination_scores(self, state, threats, name):
        from agentictm.agents.hallucination_detector import run_hallucination_detection
        result = run_hallucination_detection(state)
        scores = [t.get("confidence_score", 0) for t in result.get("threats_final", [])]
        assert all(0.0 <= s <= 1.0 for s in scores)
        if scores:
            avg = sum(scores) / len(scores)
            assert avg > 0.2, f"{name}: avg confidence {avg:.2f} < 0.2"


class TestGoldenMemoryIntegration:
    """Memory system stores and recalls analysis outcomes correctly."""

    def test_memory_store_and_recall(self, tmp_path):
        from agentictm.memory import MemoryManager

        mm = MemoryManager(tmp_path / "test_memory.db")
        mm.store_analysis_outcome("TestSystem", ECOMMERCE_THREATS)

        context = mm.recall_relevant("TestSystem")
        assert "TestSystem" in context
        assert "10" in context  # threat count

    def test_memory_per_system_namespacing(self, tmp_path):
        from agentictm.memory import MemoryManager

        mm = MemoryManager(tmp_path / "test_ns.db")
        mm.store_analysis_outcome("SystemA", ECOMMERCE_THREATS)
        mm.store_analysis_outcome("SystemB", IOT_THREATS)

        context_a = mm.recall_relevant("SystemA")
        context_b = mm.recall_relevant("SystemB")
        assert "SystemA" in context_a
        assert "SystemB" in context_b

    def test_memory_feedback_storage(self, tmp_path):
        from agentictm.memory import MemoryManager

        mm = MemoryManager(tmp_path / "test_fb.db")
        mm.store_feedback(
            "TestSystem",
            "SQL injection in product search",
            "FALSE_POSITIVE",
            "Parameterised queries are already enforced by ORM",
        )
        context = mm.recall_relevant("TestSystem")
        assert "false positive" in context.lower() or "FALSE_POSITIVE" in context
