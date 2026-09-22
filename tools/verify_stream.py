"""End-to-end verification of the merged Dark Web / Telegram monitoring views.

  1. Backend: GET /api/v1/feeds?channel=darkweb returns ONLY DARKWEB-ONION
     rows and a truthful total == the ClickHouse FINAL count.
  2. KPI numbers match reality: "All rows" == total; "In window" recomputed here
     from the same rows with the same 24h/7d windows the UI buttons use.
  3. Telegram channel works (honest 0 until a token is configured) and the
     422 guard on bad channel values.
  4. The SPA bundle served by the container carries all nine original nav
     sections plus the two new monitoring entries.
  5. The routes exist server-side (SPA fallback serves index.html for
     /darkweb-monitor and /telegram-monitor).
"""

import json
import time
import urllib.request
import urllib.parse

API = "http://127.0.0.1:8000"
CLICKHOUSE_HTTP = "http://127.0.0.1:8123"


def ch(query: str) -> list[list]:
    url = f"{CLICKHOUSE_HTTP}/?query={urllib.parse.quote(query + ' FORMAT JSON')}"
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8")).get("data", [])


def api_get(path: str):
    with urllib.request.urlopen(f"{API}{path}", timeout=60) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def e2s(iso: str):
    import datetime
    dt = datetime.datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.astimezone()  # normalized to local tz
    return dt.timestamp()


def section(t: str):
    print("\n" + "=" * 70)
    print(t)
    print("=" * 70)


section("[1] ClickHouse ground truth vs API total (channel=darkweb)")
truth = ch(
    "SELECT count() AS n FROM cti.raw_threat_intel FINAL WHERE source = 'DARKWEB-ONION'"
)[0]["n"]
st, body = api_get("/api/v1/feeds?channel=darkweb&limit=500")
items = body.get("items", [])
non_darkweb = [i for i in items if i.get("source") != "DARKWEB-ONION"]
print(f"    ClickHouse DARKWEB-ONION (FINAL) = {truth}")
print(f"    API  channel=darkweb  total      = {body.get('total')}")
print(f"    API  channel=darkweb  items      = {len(items)}")
print(f"    items with source != DARKWEB-ONION = {len(non_darkweb)}  <- must be 0")
print(f"    MATCH total: {int(truth) == body.get('total')}")

section("[2] KPI numbers the UI will show (windowed counts from real rows)")
now = time.time()
for label, sec in (("24h", 86400), ("7d", 86400 * 7)):
    in_win = sum(1 for i in items if now - sec <= e2s(i["ts"]) <= now)
    srcs = {i.get("source") for i in items if now - sec <= e2s(i["ts"]) <= now}
    print(f"    {label}: In window={in_win}  Sources={len(srcs)}  (All rows={body.get('total')})")

section("[3] channel=telegram (honest empty until configured) + validation")
st, body = api_get("/api/v1/feeds?channel=telegram&limit=500")
print(f"    total = {body.get('total')}  items = {len(body.get('items', []))}")
try:
    api_get("/api/v1/feeds?channel=bogus")
    print("    channel=bogus -> 200 (BAD)")
except urllib.error.HTTPError as e:
    print(f"    channel=bogus -> HTTP {e.code} (expected 422)")

section("[4] SPA bundle inside the container: all 11 nav labels")
bundle = None
with urllib.request.urlopen(f"{API}/", timeout=30) as resp:
    index = resp.read().decode("utf-8")
    assets = [u.lstrip("/") for u in index.split('"') if u.endswith(".js") and "/assets/" in u]
    bundle = assets[0] if assets else None
print(f"    served index.html -> {bundle}")
if bundle:
    with urllib.request.urlopen(f"{API}/{bundle}", timeout=60) as resp:
        js = resp.read().decode("utf-8", errors="replace")
    for m in (
        "Executive Overview", "Threat Landscape", "Threat Actors & APTs",
        "Live Threat Feeds", "Alert Sheets", "IoC Search & Shodan",
        "Autonomous Triage", "Search & Export", "Data Explorer",
        "Dark Web Monitoring", "Telegram Monitoring",
    ):
        print(f"    [{'ok' if m in js else 'MISSING'}] {m}")

section("[5] SPA routes resolve (fallback serves index.html)")
with urllib.request.urlopen(f"{API}/darkweb-monitor", timeout=30) as resp:
    html = resp.read().decode("utf-8")
print(f"    /darkweb-monitor  -> HTTP {resp.status}, serves SPA: {'<div id=\"root\">' in html}")
with urllib.request.urlopen(f"{API}/telegram-monitor", timeout=30) as resp:
    html = resp.read().decode("utf-8")
print(f"    /telegram-monitor -> HTTP {resp.status}, serves SPA: {'<div id=\"root\">' in html}")

print("\nDone.")