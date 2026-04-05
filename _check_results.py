import requests, json, sys

aid = sys.argv[1] if len(sys.argv) > 1 else "65361d73-ad6"
r = requests.get(f"http://localhost:8000/api/results/{aid}")
if r.status_code != 200:
    print(f"Error: {r.status_code}")
    sys.exit(1)

data = r.json()
threats = data.get("threats", [])
print(f"Total threats: {len(threats)}")
print(f"Executive summary: {data.get('executive_summary', 'N/A')[:300]}")
print()

for t in threats:
    tid = t.get("id", "?")
    cat = t.get("stride_category", "?")
    comp = t.get("component", "?")
    pri = t.get("priority", "?")
    desc = t.get("description", "")[:200]
    mit = t.get("mitigation", "")[:100]
    category = t.get("category", "?")
    print(f"--- {tid} [{cat}] Priority={pri} Category={category}")
    print(f"    Component: {comp}")
    print(f"    Description: {desc}")
    print(f"    Mitigation: {mit}")
    print()
