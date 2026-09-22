import json
import urllib.request

CH = "http://127.0.0.1:8123"


def ch(query):
    req = urllib.request.Request(CH + "/?default_format=JSON", data=query.encode("utf-8"), method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8")).get("data", [])


rows = ch("SELECT source, count() AS n FROM cti.raw_threat_intel FINAL GROUP BY source ORDER BY n DESC")
print("SOURCES:", [(r["source"], r["n"]) for r in rows])

print("\n--- DARKWEB sample (12 newest) ---")
for r in ch(
    "SELECT ts, source, substr(raw_text,1,240) AS txt, url "
    "FROM cti.raw_threat_intel FINAL WHERE source='DARKWEB-ONION' ORDER BY ts DESC LIMIT 12"
):
    print(f"\n[{r['ts']}] {r['source']}")
    print(f"   {r['txt']}")
    print(f"   url: {r['url']}")