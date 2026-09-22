# Lightweight compile check for the Dark Web monitoring backend modules.
# Imports darkweb_analytics WITHOUT the app package (stdlib import only), then
# py_compile's the router and main. Real behavioural checks live in
# tools/verify_darkweb.py.
import importlib.util
import py_compile
import sys

def _load_analytics():
    spec = importlib.util.spec_from_file_location(
        "darkweb_analytics", "app/darkweb_analytics.py"
    )
    if spec is None or spec.loader is None:
        raise SystemExit("FAIL: could not build spec for app/darkweb_analytics.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def main() -> int:
    try:
        mod = _load_analytics()
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: darkweb_analytics import error: {exc}")
        return 1

    ok = True
    if not hasattr(mod, "analyze"):
        print("FAIL: analyze() missing")
        ok = False
    if mod.SEVERITY_BANDS != ("Critical", "High", "Medium", "Low"):
        print("FAIL: SEVERITY_BANDS mismatch")
        ok = False

    # smoke the full pipeline with a realistic item
    sample = (
        "Hi @darkweb_feed_admin, breach of a store dumpsite: below is a credential dump "
        "loot (combolist) with stealer logs and CVV cards, plus CVE-2024-3400 and "
        "https://example.com, t.me/dumps Channel, ip 203.0.113.7\n"
    )
    try:
        a = mod.analyze(sample, "TELEGRAM", 1720000000)
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: analyze() raised: {exc}")
        return 1

    for field in ("severity", "themes", "signals", "briefing"):
        if field not in a:
            print(f"FAIL: analyze() missing '{field}'")
            ok = False
    sev = a.get("severity", {})
    if sev.get("band") not in mod.SEVERITY_BANDS:
        print(f"FAIL: severity band invalid: {sev.get('band')}")
        ok = False
    if sev.get("score") not in (1, 2, 3, 4):
        print(f"FAIL: severity score invalid: {sev.get('score')}")
        ok = False
    if not (a.get("signals", {}).get("counts", {}).get("cves")):
        print("FAIL: expected a CVE signal")
        ok = False
    if not a.get("briefing", {}).get("check_next"):
        print("FAIL: briefing missing check_next")
        ok = False
    # every severity reason keyword must actually be a substring of the text
    t = sample.lower()
    for r in sev.get("reasons", []):
        if not r.get("kw") or r["kw"] not in t:
            print(f"FAIL: severity reason kw not in text: {r}")
            ok = False
    # every extracted signal must appear in the raw text
    raw = sample.lower()
    for key in ("domains", "urls", "ips", "onions", "handles", "emails", "cves"):
        for val in a.get("signals", {}).get(key, []):
            if val.lower() not in raw:
                print(f"FAIL: signal '{val}' not in raw_text (key {key})")
                ok = False

    try:
        py_compile.compile("app/routers/darkweb.py", doraise=True)
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: app/routers/darkweb.py does not compile: {exc}")
        ok = False

    try:
        py_compile.compile("app/main.py", doraise=True)
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: app/main.py does not compile: {exc}")
        ok = False

    print("OK" if ok else "FAIL")
    if ok:
        print(
            f"sample band={sev.get('band')} score={sev.get('score')} "
            f"themes={[th.get('id') for th in a.get('themes', [])]} "
            f"signals={a.get('signals', {}).get('counts', {})}"
        )
        print("sample check_next:", a.get("briefing", {}).get("check_next", [])[:2])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())