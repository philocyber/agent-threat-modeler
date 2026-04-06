import requests, json, sys, time, os
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

payload = {
    "system_name": "TestAIAgent",
    "system_input": (
        "Sistema de agentes AI para análisis de documentos financieros. "
        "Frontend: React dashboard con WebSocket para updates en tiempo real. "
        "Backend: FastAPI (Python) corriendo en Kubernetes (EKS). "
        "Agentes AI: Pipeline multi-agente usando LangGraph con 4 agentes especializados: "
        "  1. Document Parser Agent - extrae datos de PDFs usando OCR (Tesseract) y un LLM (GPT-4o via API). "
        "  2. Analysis Agent - analiza tendencias financieras usando un modelo fine-tuned de Llama 3 servido localmente con vLLM. "
        "  3. Risk Assessment Agent - evalúa riesgos crediticios usando un modelo de ML (XGBoost) entrenado internamente. "
        "  4. Report Generator Agent - genera reportes ejecutivos usando Claude API. "
        "Orquestación: LangGraph con memoria compartida en Redis. "
        "RAG: ChromaDB para vectores, PostgreSQL para metadata. "
        "Datos: Amazon S3 para documentos originales, RDS PostgreSQL para resultados. "
        "Autenticación: Auth0 con OAuth2 + JWT. "
        "Los agentes tienen acceso a herramientas externas: API de Bloomberg para datos de mercado, "
        "API interna de scoring crediticio, y un sistema de alertas vía Slack webhook. "
        "Modelo de deployment: contenedores Docker en EKS con GPU nodes para inferencia. "
        "Monitoreo: Datadog para métricas, Langfuse para tracing de LLM."
    ),
    "scan_mode": "deep",
    "output_language": "en",
    "categories": ["aws", "web", "privacy", "ai", "base"],
}

print(f"[TEST-AI] Starting AI Agent System scan at {time.strftime('%H:%M:%S')}")
r = requests.post("http://localhost:8000/api/analyze", json=payload, stream=True)
print(f"[TEST-AI] Status: {r.status_code}")

analysis_id = None
for line in r.iter_lines(decode_unicode=True):
    if not line or not line.startswith("data:"):
        continue
    data_str = line[5:].strip()
    if data_str == "[DONE]":
        print("[TEST-AI] SSE stream: [DONE]")
        break
    try:
        evt = json.loads(data_str)
        etype = evt.get("type", "")
        if etype == "analysis_started":
            analysis_id = evt.get("analysis_id")
            print(f"[TEST-AI] Analysis ID: {analysis_id}")
        elif etype == "log":
            msg = evt.get("message", "")
            print(f"  LOG: {msg[:200]}")
        elif etype == "error":
            print(f"  ERROR: {evt.get('message', '')}")
        elif etype == "threat_update":
            count = evt.get("count", 0)
            print(f"  THREATS: {count}")
        elif etype in ("complete", "analysis_complete"):
            print(f"[TEST-AI] COMPLETE | threats={evt.get('threat_count', '?')}")
        else:
            print(f"  [{etype}]: {str(evt)[:150]}")
    except json.JSONDecodeError:
        pass

print(f"\n[TEST-AI] Finished at {time.strftime('%H:%M:%S')}")
if analysis_id:
    print(f"[TEST-AI] Results at: http://localhost:8000/{analysis_id}/prompt")
