import requests, json, sys, time, os
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

payload = {
    "system_name": "TestEcommerce3",
    "system_input": (
        "Plataforma de E-Commerce serverless en AWS. "
        "Frontend: React SPA en S3 + CloudFront CDN. "
        "Backend: Node.js Lambda functions behind API Gateway. "
        "Base de datos: Amazon RDS (PostgreSQL) para pedidos y usuarios, "
        "DynamoDB para catalogo de productos, ElastiCache (Redis) para sesiones. "
        "Pagos: Stripe SDK integrado via API Gateway. "
        "Notificaciones: Amazon SES para emails transaccionales. "
        "Almacenamiento: S3 para imagenes de productos. "
        "Panel admin con acceso restringido via VPN."
    ),
    "scan_mode": "deep",
    "output_language": "en",
    "categories": ["aws", "web", "privacy", "base"],
}

print(f"[TEST] Starting E-Commerce scan at {time.strftime('%H:%M:%S')}")
r = requests.post("http://localhost:8000/api/analyze", json=payload, stream=True)
print(f"[TEST] Status: {r.status_code}")

analysis_id = None
for line in r.iter_lines(decode_unicode=True):
    if not line or not line.startswith("data:"):
        continue
    data_str = line[5:].strip()
    if data_str == "[DONE]":
        print("[TEST] SSE stream: [DONE]")
        break
    try:
        evt = json.loads(data_str)
        etype = evt.get("type", "")
        if etype == "analysis_started":
            analysis_id = evt.get("analysis_id")
            print(f"[TEST] Analysis ID: {analysis_id}")
        elif etype == "log":
            msg = evt.get("message", "")
            print(f"  LOG: {msg[:200]}")
        elif etype == "error":
            print(f"  ERROR: {evt.get('message', '')}")
        elif etype == "threat_update":
            count = evt.get("count", 0)
            print(f"  THREATS: {count}")
        elif etype in ("complete", "analysis_complete"):
            print(f"[TEST] COMPLETE | threats={evt.get('threat_count', '?')}")
        else:
            print(f"  [{etype}]: {str(evt)[:150]}")
    except json.JSONDecodeError:
        pass

print(f"\n[TEST] Finished at {time.strftime('%H:%M:%S')}")
if analysis_id:
    print(f"[TEST] Results at: http://localhost:8000/{analysis_id}/prompt")
