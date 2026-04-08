"""Upload files and launch DocuShare scan."""
import json
import os
import sys
import time

import requests

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = "http://localhost:8000"
FILES_DIR = r"C:\Users\richi\Desktop\Test-DocuShareApp"

# 1. Upload files
upload_ids = []
files_to_upload = [
    "DocuShare_AWS_ThreatModel.md",
    "1-arquitectura.png",
    "2-data-flow-diagram.png",
    "3-flujo-de-trabajo-critico.png",
]

for fname in files_to_upload:
    fpath = os.path.join(FILES_DIR, fname)
    if not os.path.exists(fpath):
        print(f"SKIP {fname}: not found at {fpath}")
        continue
    with open(fpath, "rb") as f:
        r = requests.post(f"{BASE}/api/upload", files={"file": (fname, f)}, timeout=30)
    if r.status_code == 200:
        data = r.json()
        uid = data.get("upload_id")
        upload_ids.append(uid)
        print(f"OK {fname} -> {uid}")
    else:
        print(f"FAIL {fname}: {r.status_code} {r.text[:200]}")

print(f"\nUploaded {len(upload_ids)} files: {upload_ids}")

# 2. Read the text description
desc_path = os.path.join(FILES_DIR, "mini-descripcion.txt")
if os.path.exists(desc_path):
    with open(desc_path, "r", encoding="utf-8") as f:
        system_input = f.read().strip()
else:
    system_input = (
        "DocuShare es una aplicacion SaaS B2B Serverless alojada 100% en AWS, "
        "disenada para compartir documentos confidenciales mediante enlaces temporales."
    )

# 3. Launch analysis
payload = {
    "system_name": "DocuShare",
    "system_input": system_input,
    "categories": ["aws", "privacy", "web", "base"],
    "upload_ids": upload_ids,
    "max_debate_rounds": 2,
    "scan_mode": "deep",
}

print(f"\nLaunching scan at {time.strftime('%H:%M:%S')}...")
r = requests.post(f"{BASE}/api/analyze", json=payload, stream=True, timeout=(30, None))
print(f"Status: {r.status_code}")

if r.status_code != 200:
    print(f"ERROR: {r.text[:500]}")
    sys.exit(1)

analysis_id = None
for line in r.iter_lines(decode_unicode=True):
    if not line or not line.startswith("data:"):
        continue
    data_str = line[5:].strip()
    try:
        evt = json.loads(data_str)
    except json.JSONDecodeError:
        continue

    etype = evt.get("type", "")
    if etype == "start":
        analysis_id = evt.get("analysis_id")
        print(f"Analysis ID: {analysis_id}")
    elif etype == "log":
        msg = evt.get("message", "")
        level = evt.get("level", "INFO")
        agent = evt.get("agent", "")
        print(f"  [{level}] [{agent or 'system'}] {msg[:250]}")
    elif etype == "error":
        print(f"  ERROR: {evt.get('message', '')}")
    elif etype == "complete":
        print(f"\nCOMPLETE | threats={evt.get('threats_count', '?')}")
    elif etype == "heartbeat":
        pass

print(f"\nFinished at {time.strftime('%H:%M:%S')}")
if analysis_id:
    print(f"View at: http://localhost:8000/live")
