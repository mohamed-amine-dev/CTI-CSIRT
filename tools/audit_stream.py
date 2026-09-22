"""Live audit of the Dark Web / Telegram stream data path.

Answers, from the real running stack:
  1. How many DARKWEB-ONION / TELEGRAM rows exist in ClickHouse right now
     (FINAL dedup), and their min/max ts so windows are meaningful.
  2. EXACTLY what GET /api/v1/feeds?channel=darkweb returns (shape, keys,
     number of items) -- the endpoint the StreamPage fetches.
  3. EXACTLY what GET /api/v1/feeds?source=DARKWEB-ONION returns (shape, keys,
     first row fields) -- the known-working filter + return contract.
  4. What /api/v1/feeds/sources reports for the real totals.

Runs against the *running* dockerized stack on localhost:8000 / 8123.
"""

import json
import urllib.request
import urllib.parse

CLICKHOUSE_HTTP = "http://127.0.0.1:8123"
API = "http://127.0.0.1:8000"


def ch(query: str) -> list[list]:
    url = f"{CLICKHOUSE_HTTP}/?query={urllib.parse.quote(query + ' FORMAT JSON')}"
    with urllib.request.urlopen(url, timeout=30) as resp:
        text = resp.read().decode("utf-8")
    try:
        parsed = json.loads(text)
        return parsed.get("data", [])
    except json.JSONDecodeError:
        return [[text.strip()]]


def api_get(path: str):
    with urllib.request.urlopen(f"{API}{path}", timeout=30) as resp:
        return resp.status, resp.read().decode("utf-8")


def section(title: str):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


section("[1] ClickHouse ground truth (raw_threat_intel FINAL)")
rows = ch(
    """
    SELECT source, count() AS n,
           toInt64(min(ts)) AS min_ts, toInt64(max(ts)) AS max_ts,
           uniqExact(source) AS srcs
    FROM cti.raw_threat_intel FINAL
    GROUP BY source
    ORDER BY n DESC
    """
)
total = 0
for r in rows:
    if not isinstance(r, dict):
        print(f"    row not a dict: {r!r}")
        continue
    total += int(r["n"])
    print(
        f"    {r['source']:<20} count={int(r['n']):>7}  min_ts={r['min_ts']}  max_ts={r['max_ts']}"
    )
print(f"    TOTAL rows (FINAL) = {total}")
try:
    age = ch(
        """
        SELECT count() AS n,
               dateDiff('minute', max(ts), now()) AS max_age_min,
               dateDiff('minute', min(ts), now()) AS min_age_min
        FROM cti.raw_threat_intel FINAL
        WHERE source IN ('DARKWEB-ONION','TELEGRAM')
        """
    )
    for r in age:
        print(
            f"    DARKWEB+TELEGRAM combined: n={r['n']} oldest~{r['min_age_min']}min+ new~{r['max_age_min']}min"
        )
except Exception as exc:  # noqa: BLE001
    print(f"    age query failed: {exc}")

section("[2] GET /api/v1/feeds?channel=darkweb  (what StreamPage actually calls)")
try:
    st, body = api_get("/api/v1/feeds?channel=darkweb")
    data = json.loads(body)
    print(f"    HTTP {st}")
    print(f"    top-level type={type(data).__name__}")
    if isinstance(data, dict):
        print(f"    keys={list(data.keys())}")
        items = data.get("items", [])
        print(f"    items len={len(items)}  total={data.get('total')}")
        if items:
            print(f"    first item keys={list(items[0].keys())}")
    else:
        print(f"    body[:200]={body[:200]}")
except Exception as exc:  # noqa: BLE001
    print(f"    ERROR: {exc}")

section("[3] GET /api/v1/feeds?source=DARKWEB-ONION&limit=5  (known-good filter)")
try:
    st, body = api_get("/api/v1/feeds?source=DARKWEB-ONION&limit=5")
    data = json.loads(body)
    print(f"    HTTP {st}")
    items = data.get("items", [])
    print(f"    items len={len(items)}  total={data.get('total')}")
    for it in items[:2]:
        print(f"    row source={it.get('source')!r} ts={it.get('ts')!r}")
        print(f"         raw_text[:70]={it.get('raw_text','')[:70]!r}")
        print(f"         url={it.get('url','')[:60]!r}")
except Exception as exc:  # noqa: BLE001
    print(f"    ERROR: {exc}")

section("[4] GET /api/v1/feeds/sources  (real per-source totals)")
try:
    st, body = api_get("/api/v1/feeds/sources")
    data = json.loads(body)
    srcs = data.get("sources", {})
    for k in ("DARKWEB-ONION", "TELEGRAM"):
        print(f"    {k} -> {srcs.get(k, 'MISSING')}")
except Exception as exc:  # noqa: BLE001
    print(f"    ERROR: {exc}")

print("\nDone.")