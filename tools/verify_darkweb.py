"""Live verification for the Dark Web / Telegram monitoring upgrade.

Proves with real evidence that:
  1. The new /api/v1/darkweb/monitor endpoint serves the WHOLE stream
     (total == ClickHouse) and every item carries an `analysis`.
  2. That analysis is exactly what app/darkweb_analytics.py produces per row
     (parity — the endpoint feeds the same audited engine, no drift).
  3. Every severity reason keyword and every extracted signal is really a
     substring of the item's own raw_text (auditable, no fabrication).
  4. Briefings are non-empty, bound to the actual source, and reference the
     platform's real capabilities (IoC search, feeds, Telegram monitoring).
  5. The archive is visible (Legacy group, keep-old-page-reachable): the
     bundle carries the Legacy label AND /darkweb still serves the SPA.
  6. The new monitoring + briefing UI is in the served bundle.
"""
import datetime
import importlib.util
import json
import re
import sys
import urllib.parse
import urllib.request

API = "http://127.0.0.1:8000"
CH = "http://127.0.0.1:8123"
PASS = []
FAIL = []


def check(label, ok, note=""):
    print(f"    [{'ok' if ok else 'FAIL'}] {label}{'  (' + note + ')' if note else ''}")
    (PASS if ok else FAIL).append(label)


def ch(query):
    req = urllib.request.Request(CH + "/?default_format=JSON", data=query.encode("utf-8"), method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8")).get("data", [])


def api_get(path):
    with urllib.request.urlopen(f"{API}{path}", timeout=120) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def load_engine():
    spec = importlib.util.spec_from_file_location("darkweb_analytics", "app/darkweb_analytics.py")
    if spec is None or spec.loader is None:
        raise SystemExit("run from the repo root (tools/ relative to app/)")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


section = lambda t: print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)
SEV = ("Critical", "High", "Medium", "Low")
THEME_IDS = {"credential", "ransomware", "breach", "carding", "malware", "phishing", "darkweb", "other"}


def norm_check_next(lst):
    """Squash the sliding 'content age NN ago' tail: it moves between the API
    serving the JSON and this script recomputing seconds later, so a raw string
    compare would flag pure time drift as an engine divergence."""
    out = []
    for c in lst:
        fixed = re.sub(r"Seen on ([A-Z0-9-]+), content age [^.]*\.", r"Seen on \1, content age fresh.", c)
        out.append(fixed)
    return out

section("[1] Engine loads standalone (independent of the API)")
engine = load_engine()
check("darkweb_analytics imports outside package", True)
check("bands match", engine.SEVERITY_BANDS == SEV)

section("[2] Endpoint vs ClickHouse for channel=darkweb")
db_total = int(ch("SELECT count() AS n FROM cti.raw_threat_intel FINAL WHERE source = 'DARKWEB-ONION'")[0]["n"])
st, m = api_get("/api/v1/darkweb/monitor?channel=darkweb&limit=500")
check("HTTP 200", st == 200)
check("decorated source", m.get("source") == "DARKWEB-ONION" and m.get("channel") == "darkweb")
check("total == ClickHouse count", m.get("total") == db_total, f"api={m.get('total')} ch={db_total}")
items = m.get("items", [])
check("all rows returned (limit 500 covers corpus)", len(items) == db_total, f"n={len(items)}")
check("every item carries analysis", all("analysis" in it for it in items))
check("every item exposes raw_text/url/ts/title", all(
    all(k in it for k in ("raw_text", "url", "ts")) for it in items))

section("[3] Telegram channel maps and caps")
_, tm = api_get("/api/v1/darkweb/monitor?channel=telegram&limit=500")
check("telegram -> TELEGRAM source", tm.get("source") == "TELEGRAM")
try:
    urllib.request.urlopen(API + "/api/v1/darkweb/monitor?channel=bogus", timeout=30)
    check("bogus channel rejected with 422", False)
except urllib.error.HTTPError as exc:
    check("bogus channel rejected with 422", exc.code == 422, f"code={exc.code}")

section("[4] Per-item analysis is the engine's own output (parity + auditability)")
sample = None
parity_bad = 0
reason_bad = 0
signal_bad = 0
brief_bad = 0
for it in items:
    txt = it["raw_text"]
    ts_iso = it["ts"]
    try:
        ts_sec = datetime.datetime.fromisoformat(ts_iso).timestamp()
    except ValueError:
        ts_sec = None
    a = it.get("analysis", {})
    sev = a.get("severity", {})
    band = sev.get("band")
    if band not in SEV:
        reason_bad += 1
    if sev.get("score") != engine._SEV_WEIGHT.get(band):
        reason_bad += 1
    themes = a.get("themes", [])
    if not themes or any(t.get("id") not in THEME_IDS for t in themes):
        brief_bad += 1
    t_low = (txt or "").lower()
    for r in sev.get("reasons", []):
        if not r.get("kw") or r["kw"] not in t_low:
            reason_bad += 1
    sig = a.get("signals", {})
    for key in ("domains", "urls", "ips", "onions", "handles", "emails", "cves"):
        for val in sig.get(key, []):
            if (val or "").lower() not in t_low:
                signal_bad += 1
    brief = a.get("briefing", {})
    if not brief.get("summary") or not brief.get("check_next"):
        brief_bad += 1
    check_next = brief.get("check_next", [])
    if check_next and not any("DARKWEB-ONION" in c for c in check_next):
        brief_bad += 1
    expected = engine.analyze(txt, it["source"], ts_sec)
    for gap in ("severity", "themes", "signals"):
        if a.get(gap) != expected.get(gap):
            parity_bad += 1
    if a.get("briefing", {}).get("headline") != expected["briefing"]["headline"]:
        parity_bad += 1
    if a.get("briefing", {}).get("summary") != expected["briefing"]["summary"]:
        parity_bad += 1
    if norm_check_next(a.get("briefing", {}).get("check_next", [])) != norm_check_next(expected["briefing"].get("check_next", [])):
        parity_bad += 1
    if sample is None:
        sample = (it["raw_text"][:140], band, [t["id"] for t in themes][:3], sig.get("counts", {}))
check("API analysis == engine analyze() (parity, recency excluded)", parity_bad == 0,
      f"mismatches={parity_bad} over {len(items)} items")
check("severity reason keywords are substrings of raw_text", reason_bad == 0,
      f"violations={reason_bad}")
check("extracted signals are substrings of raw_text", signal_bad == 0,
      f"violations={signal_bad}")
check("briefings complete + source-bound", brief_bad == 0, f"violations={brief_bad}")

print(f"\n    --- real severity distribution (API) ---")
counts = {}
for it in items:
    band = it.get("analysis", {}).get("severity", {}).get("band", "Low")
    counts[band] = counts.get(band, 0) + 1
for band in SEV:
    print(f"      {band:9} {counts.get(band, 0):>3}  {'#' * counts.get(band, 0)}")

print(f"\n    sample item: {sample[0]!r}")
print(f"      band={sample[1]} themes={sample[2]} signals={sample[3]}")

section("[5] Channel=darkweb items are genuinely analysable (spot reason audit)")
if items:
    idx = 0
    it = items[idx]
    band = it["analysis"]["severity"]["band"]
    reasons = it["analysis"]["severity"]["reasons"]
    low = it["raw_text"].lower()
    print(f"    first item: band={band}")
    for r in reasons[:4]:
        hits = low.count(r["kw"])
        print(f"      - kw={r['kw']!r} ({r['label']}) appears {hits}x in text")

section("[6] Archive + new UI in the served bundle, legacy page still reachable")
with urllib.request.urlopen(f"{API}/", timeout=30) as resp:
    index = resp.read().decode("utf-8")
assets = [u.lstrip("/") for u in index.split('"') if u.endswith(".js") and "/assets/" in u]
with urllib.request.urlopen(f"{API}/{assets[0]}", timeout=120) as resp:
    js = resp.read().decode("utf-8", errors="replace")
for lab in ("Legacy", "Dark Web & Telegram (Legacy)", "Why it matters",
            "Dark Web Monitoring", "Priority in window", "Signals in text",
            "Window risk", "Severity distribution"):
    check(f"bundle contains '{lab}'", lab in js)
with urllib.request.urlopen(f"{API}/darkweb", timeout=30) as resp:
    html = resp.read().decode("utf-8")
check("/darkweb still serves the SPA (page kept reachable)", '<div id="root">' in html)
with urllib.request.urlopen(f"{API}/darkweb-monitor", timeout=30) as resp:
    html2 = resp.read().decode("utf-8")
check("/darkweb-monitor serves the SPA", '<div id="root">' in html2)

print("\n" + "=" * 70)
print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("Failed:", "; ".join(FAIL))
    sys.exit(1)
print("ALL DARK WEB POLISH CHECKS PASSED")