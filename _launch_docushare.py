import json
import os
import sys
import time

import requests

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

payload = {
    "system_name": "DocuShare",
    "system_input": (
        "DocuShare is a B2B secure document-sharing SaaS deployed on AWS serverless infrastructure. "
        "Frontend: React single-page application hosted on Amazon S3 and distributed through CloudFront, "
        "protected by AWS WAF. "
        "Authentication and authorization: Amazon Cognito User Pools issue JWT tokens, and API Gateway uses a Cognito authorizer. "
        "Backend: AWS Lambda functions include UploadHandler, AV Scanner using ClamAV, and LinkGenerator. "
        "Storage: Amazon S3 stores confidential legal and financial documents with SSE-KMS encryption and lifecycle policies. "
        "Metadata: DynamoDB stores document records with fields such as doc_id, tenant_id, user_id, status, created_at, and tags. "
        "Asynchronous processing: S3 object-created events go to SQS, which triggers the AV Scanner Lambda. "
        "Alerting: SNS is used for dead-letter and security alert notifications. "
        "Email delivery: SES sends shareable-link notifications. "
        "Key management: AWS KMS handles key rotation and encryption/decryption. "
        "Monitoring and audit: CloudWatch and CloudTrail are enabled. "
        "Core flows: a B2B user authenticates with Cognito, calls API Gateway, UploadHandler creates metadata and generates presigned upload URLs, "
        "the user uploads a binary document directly to S3, S3 emits an event to SQS, AV Scanner validates the file and updates DynamoDB, "
        "and LinkGenerator later creates secure shareable links for authorized tenant users. "
        "The system handles confidential multi-tenant business documents and must preserve tenant isolation, privacy, secure sharing, "
        "malware quarantine, strong access control, and safe presigned URL usage. "
        "There are no AI, LLM, or agentic AI components in this system."
    ),
    "categories": ["aws", "privacy", "web", "base"],
    "upload_ids": [],
    "max_debate_rounds": 2,
    "scan_mode": "deep",
}

print(f"[DOCUSHARE] Starting relaunch at {time.strftime('%H:%M:%S')}")
r = requests.post("http://localhost:8000/api/analyze", json=payload, stream=True, timeout=60)
print(f"[DOCUSHARE] Status: {r.status_code}")

analysis_id = None
for line in r.iter_lines(decode_unicode=True):
    if not line or not line.startswith("data:"):
        continue
    data_str = line[5:].strip()
    if data_str == "[DONE]":
        print("[DOCUSHARE] SSE stream: [DONE]")
        break
    try:
        evt = json.loads(data_str)
    except json.JSONDecodeError:
        continue

    etype = evt.get("type", "")
    if etype == "start":
        analysis_id = evt.get("analysis_id")
        print(f"[DOCUSHARE] Analysis ID: {analysis_id}")
    elif etype == "log":
        msg = evt.get("message", "")
        print(f"  LOG: {msg[:220]}")
    elif etype == "error":
        print(f"  ERROR: {evt.get('message', '')}")
    elif etype == "complete":
        print(f"[DOCUSHARE] COMPLETE | threats={evt.get('threats_count', '?')}")
    else:
        print(f"  [{etype}]: {str(evt)[:180]}")

print(f"\n[DOCUSHARE] Finished at {time.strftime('%H:%M:%S')}")
if analysis_id:
    print(f"[DOCUSHARE] Live URL: http://localhost:8000/{analysis_id}/live")
