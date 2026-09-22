import datetime
import importlib.util
import json
import urllib.request

API = "http://127.0.0.1:8000"


def load_engine():
    spec = importlib.util.spec_from_file_location("darkweb_analytics", "app/darkweb_analytics.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


with urllib.request.urlopen(f"{API}/api/v1/darkweb/monitor?channel=darkweb&limit=500", timeout=120) as resp:
    body = json.loads(resp.read().decode("utf-8"))

engine = load_engine()
items = body["items"]
print(f"items: {len(items)}  total: {body['total']}")

def diff_fields(it, a, expected):
    bad = []
    for k in ("severity", "themes", "signals"):
        if a.get(k) != expected.get(k):
            bad.append(k)
    for k in ("summary", "check_next"):
        if a["briefing"].get(k) != expected["briefing"].get(k):
            bad.append("briefing." + k)
    return bad

n = 0
for it in items:
    txt = it["raw_text"]
    try:
        ts = datetime.datetime.fromisoformat(it["ts"]).timestamp()
    except ValueError:
        ts = None
    a = it["analysis"]
    expected = engine.analyze(txt, it["source"], ts)
    fields = diff_fields(it, a, expected)
    empty_summary = not a["briefing"].get("summary")
    no_source_binder = a["briefing"].get("check_next") and not any("DARKWEB-ONION" in c for c in a["briefing"]["check_next"])
    if fields or empty_summary or no_source_binder:
        n += 1
        print("\n----- item", n, "ts=", it["ts"], "len(text)=", len(txt))
        print("  url:", it["url"][:120])
        if fields:
            print("  differing fields:", fields)
            if "briefing.check_next" in fields:
                a_cn = a["briefing"]["check_next"]
                e_cn = expected["briefing"]["check_next"]
                print("    api check_next:", json.dumps(a_cn, ensure_ascii=False)[:300])
                print("    eng check_next:", json.dumps(e_cn, ensure_ascii=False)[:300])
            if "briefing.summary" in fields:
                print("    api summary:", json.dumps(a["briefing"]["summary"], ensure_ascii=False)[:300])
                print("    eng summary:", json.dumps(expected["briefing"]["summary"], ensure_ascii=False)[:300])
            if "severity" in fields:
                print("    api sev:", json.dumps(a["severity"], ensure_ascii=False)[:300])
                print("    eng sev:", json.dumps(expected["severity"], ensure_ascii=False)[:300])
            if "themes" in fields:
                print("    api themes:", json.dumps(a["themes"], ensure_ascii=False)[:300])
                print("    eng themes:", json.dumps(expected["themes"], ensure_ascii=False)[:300])
            if "signals" in fields:
                print("    api signals:", json.dumps(a["signals"], ensure_ascii=False)[:300])
                print("    eng signals:", json.dumps(expected["signals"], ensure_ascii=False)[:300])
        if empty_summary:
            print("  !! api summary EMPTY  text=", json.dumps(txt[:200]))
        if no_source_binder:
            print("  !! check_next missing source line:", json.dumps(a["briefing"]["check_next"], ensure_ascii=False))
print(f"\ntotal differing/flagged items: {n}")