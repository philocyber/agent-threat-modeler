import requests, json

payload = {
    "system_name": "TestHealthcare",
    "system_input": (
        "Sistema de gestion de historias clinicas electronicas (EHR) para hospitales. "
        "Incluye portal web para medicos, API REST para integraciones con laboratorios, "
        "base de datos PostgreSQL con datos de pacientes (PII/PHI), servicio de autenticacion LDAP, "
        "almacenamiento S3 para imagenes medicas (radiografias, resonancias), "
        "y cola de mensajes RabbitMQ para notificaciones."
    ),
    "scan_mode": "deep",
    "output_language": "es",
    "categories": ["web", "privacy", "base"],
}

r = requests.post("http://localhost:8000/api/analyze", json=payload)
print(f"Status: {r.status_code}")
data = r.json()
aid = data.get("analysis_id", "N/A")
print(f"Analysis ID: {aid}")
print(json.dumps(data, indent=2, ensure_ascii=False)[:500])
