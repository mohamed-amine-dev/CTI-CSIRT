# Backend compile + engine behaviour check for Org Exposure Search & Watchlist.
#   - watchlist.py imports standalone (stdlib only) and its matcher behaves
#     (domain exact/subdomain/anti-false-positive, phone normalisation,
#     email/org case-insensitive substring).
#   - py_compile touches: watchlist.py, routers/watchlist.py, ingestion_engine.py,
#     main.py, db_init.py.
import importlib.util
import py_compile
import sys

def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def main() -> int:
    ok = True
    try:
        wl = _load("watchlist", "app/watchlist.py")
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: app/watchlist.py import error: {exc}")
        return 1

    # --- domain --------------------------------------------------------------
    m = wl.match_item("mail.example.com and evilexample.com and notexample.com and fooexample.com", "domain", "example.com")
    m = wl.match_item("Contactor reached mail.example.com in the dump, but avoid notexample.com.", "domain", "example.com")
    terms = [x["term"] for x in m]
    if "mail.example.com" not in terms:
        print("FAIL: subdomain mail.example.com not matched", terms)
        ok = False
    # extracted-entity exact path
    me = wl.match_item("scanned AXE.Example.COM ", "domain", "example.com", domains=["axe.example.com"])
    if not me or me[0]["term"].lower() != "axe.example.com":
        print("FAIL: extracted-entity exact path", me)
        ok = False
    # anti-false-positive: notexample.com / fooexample.com are NOT the target
    bad = [x["term"] for x in wl.match_item("hit notexample.com and fooexample.com today", "domain", "example.com")]
    if bad:
        print("FAIL: false positive", bad)
        ok = False
    print("domain: ok" if ok else "domain: FAIL")

    # --- phone ----------------------------------------------------------------
    ph = wl.phone_candidates("+1 (555) 123-4567")
    if ph[0] != "15551234567" or "5551234567" not in ph:
        print("FAIL: phone_candidates('+1 (555) 123-4567') =", ph)
        ok = False
    mp = wl.match_item("call 555.123.4567 now", "phone", "+1 (555) 123-4567")
    if not mp:
        print("FAIL: phone variant 555.123.4567 not matched")
        ok = False
    mp2 = wl.match_item("press 0033 1 23 45 67 89 to talk", "phone", "+33 1 23 45 67 89")
    if not mp2:
        print("FAIL: international-format phone missed")
        ok = False
    print("phone: ok" if (ph[0] == "15551234567" and mp and mp2) else "phone: FAIL")

    # --- email / org ----------------------------------------------------------
    me = wl.match_item("Cisco Systems: president@CISCO.COM was listed", "email", "president@cisco.com")
    if not me or me[0]["term"] != "president@CISCO.COM":
        print("FAIL: email case-insensitive", me)
        ok = False
    mo = wl.match_item("the ACME Corp leaked its files", "org", "acme corp")
    if not mo or mo[0]["term"] != "ACME Corp":
        print("FAIL: org case-insensitive substring", mo)
        ok = False
    print("email/org: ok" if (me and mo) else "email/org: FAIL")

    # zero-match honesty
    z = wl.match_item("nothing relevant here", "org", "zzz-notpresent-org")
    if z:
        print("FAIL: zero-match returned something", z)
        ok = False
    print("zero-match: ok" if not z else "zero-match: FAIL")

    # --- compile --------------------------------------------------------------
    for path in ("app/watchlist.py", "app/routers/watchlist.py", "app/ingestion_engine.py", "app/main.py", "app/db_init.py"):
        try:
            py_compile.compile(path, doraise=True)
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL: {path} does not compile: {exc}")
            ok = False
    print("py_compile: all files ok" if ok else "py_compile: FAIL")

    print("OK" if ok else "FAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())