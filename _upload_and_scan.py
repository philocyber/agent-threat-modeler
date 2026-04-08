"""Upload DocuShare files and launch scan."""
import json
import os
import sys
import time

import requests

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = "http://localhost:8000"
FILES_DIR = r"C:\Users\richi\Desktop\Test-DocuShareApp"

# 1) Upload files
upload_ids = []
files_to_upload = [
    "DocuShare_AWS_ThreatModel.md",
    "1-arquitectura.png",
    "2-data-flow-diagram.png",
    "3-flujo-de-trabajo-critico.png",
]

for fname in files_to_upload:
    fpath = os.path.join(FILES_DIR, fname)
    with open(fpath, "rb") as f:
        r = requests.post(f"{BASE}/api/upload", files={"file": (fname, f)}, timeout=30)
    if r.status_code == 200:
        data = r.json()
        uid = data["upload_id"]
        upload_ids.append(uid)
        print(f"  Uploaded {fname} -> {uid} (image={data['is_image']})")
    else:
        print(f"  FAILED {fname}: {r.status_code} {r.text}")

print(f"\nUpload IDs: {upload_ids}")

# 2) Read the mini-descripcion as system_input
with open(os.path.join(FILES_DIR, "mini-descripcion.txt"), "r", encoding="utf-8") as f:
    system_input = f.read().strip()

# 3) Launch scan
payload = {
    "system_name": "DocuShare",
    "system_input": system_input,
    "categories": ["aws", "privacy", "web", "base"],
    "upload_ids": upload_ids,
    "max_debate_rounds": 2,
    "scan_mode": "deep",
}

print(f"\n[SCAN] Launching at {time.strftime('%H:%M:%S')}")
print(f"[SCAN] Categories: {payload['categories']}")
print(f"[SCAN] Uploads: {len(upload_ids)} files")

r = requests.post(f"{BASE}/api/analyze", json=payload, stream=True, timeout=60)
print(f"[SCAN] Response status: {r.status_code}")

if r.status_code != 200:
    print(f"[SCAN] ERROR: {r.text}")
    sys.exit(1)

analysis_id = None
last_agent = None
for line in r.iter_lines(decode_unicode=True):
    if not line or not line.startswith("data:"):
        continue
    data_str = line[5:].strip()
    if data_str == "[DONE]":
        print("[SCAN] SSE stream: [DONE]")
        break
    try:
        evt = json.loads(data_str)
    except json.JSONDecodeError:
        continue

    etype = evt.get("type", "")
    if etype == "start":
        analysis_id = evt.get("analysis_id")
        print(f"[SCAN] Analysis ID: {analysis_id}")
    elif etype == "log":
        agent = evt.get("agent", "system")
        msg = evt.get("message", "")
        if agent != last_agent:
            print(f"\n  --- [{agent}] ---")
            last_agent = agent
        print(f"  {msg[:200]}")
    elif etype == "error":
        print(f"\n  [ERROR] {evt.get('message', '')}")
        if evt.get("traceback"):
            # Print first 5 lines of traceback
            tb_lines = evt["traceback"].strip().split("\n")
            for tl in tb_lines[-5:]:
                print(f"    {tl}")
    elif etype == "complete":
        print(f"\n[SCAN] COMPLETE | threats={evt.get('threats_count', '?')}")
    elif etype == "heartbeat":
        pass  # silent
    else:
        print(f"  [{etype}]: {str(evt)[:180]}")

print(f"\n[SCAN] Finished at {time.strftime('%H:%M:%S')}")
if analysis_id:
    print(f"[SCAN] View at: http://localhost:8000/live")
