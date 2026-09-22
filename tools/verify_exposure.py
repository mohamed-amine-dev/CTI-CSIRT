"""Live verification for the Org Exposure Search & Watchlist feature.

Proves with real evidence that:
  1. Matching engine semantics (domain exact/subdomain/anti-false-positive,
     phone format normalisation, case-insensitive email/org substring).
  2. Watchlist tables exist and the CRUD API works (add / list / delete).
  3. Real exposure search: a value known to appear in the LIVE corpus returns
     real matches whose matched terms are genuine substrings (no fabrication);
     a nonsense value returns an HONEST zero (HTTP 200, total=0).
  4. The background sweep (mirrored by POST /api/v1/watchlist/sweep) records
     real matches for a saved target and NONE for a guaranteed-non-present
     target, and payloads the existing notification pipeline (WATCHLIST rows in
     the notifications table).
  5. Navigation + UI: 'Exposure & Watchlist' ships in the served bundle and
     /exposure serves the SPA; existing nav labels are undisturbed.
"""
import datetime
import importlib.util
import json
import re
import sys
import urllib.parse
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

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
    req = urllib.request.Request(API + path)
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def api_post(path, payload=None, token=None):
    body = json.dumps(payload or {}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(API + path, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=180) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def api_delete(path, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(API + path, headers=headers, method="DELETE")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def load_watchlist():
    spec = importlib.util.spec_from_file_location("watchlist", "app/watchlist.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


section = lambda t: print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)

WL = load_watchlist()

section("[1] Watchlist engine semantics (standalone, stdlib-only)")
# domain: subdomain + extracted-entity exact match + anti-false-positive
m = WL.match_item("Contactor reached mail.example.com in the dump, but avoid notexample.com.",
                  "domain", "example.com")
terms = [x["term"] for x in m]
check("subdomain matches (mail.example.com)", "mail.example.com" in terms, f"terms={terms}")
check("no false positive for notexample.com", "notexample.com" not in terms)
me = WL.match_item("scanned AXE.Example.COM", "domain", "example.com", domains=["axe.example.com"])
check("extracted-entity exact match", bool(me) and me[0]["term"].lower() == "axe.example.com")
# phone: normalisation variants
ph = WL.phone_candidates("+1 (555) 123-4567")
mp = WL.match_item("call 555.123.4567 now", "phone", "+1 (555) 123-4567")
check("phone variant (dots/space-dash) matched", bool(mp), f"cand={ph[:3]}")
mp2 = WL.match_item("press 0033 1 23 45 67 89 to talk", "phone", "+33 1 23 45 67 89")
check("international-format phone matched", bool(mp2))
# email/org: case-insensitive substring
mo = WL.match_item("the ACME Corp leaked its files", "org", "acme corp")
check("org case-insensitive substring", bool(mo) and mo[0]["term"] == "ACME Corp")
z = WL.match_item("nothing relevant here", "org", "zzz-notpresent-org")
check("zero-match returns []", z == [])
check("spans are in-bounds of source text", all(
    0 <= s["start"] < s["end"] <= len("call 555.123.4567 now")
    for s in (mp or []) if s["start"] is not None))

section("[2] Watchlist tables exist (created at app startup)")
tbls = ch("SELECT name FROM system.tables WHERE database='cti' AND name IN ('watchlist_targets','watchlist_matches')")
names = {r["name"] for r in tbls}
check("watchlist_targets table", "watchlist_targets" in names)
check("watchlist_matches table", "watchlist_matches" in names)
eng = ch("SELECT engine FROM system.tables WHERE database='cti' AND name='watchlist_matches'")
check("watchlist_matches is ReplacingMergeTree (dedups re-sweeps)",
      bool(eng) and "ReplacingMergeTree" in eng[0]["engine"])

section("[3] CRUD: add -> list -> dedup -> soft-delete")
st, before = api_get("/api/v1/watchlist")
check("GET /api/v1/watchlist 200", st == 200, f"total={before.get('total')}")
token = "E1ny_xcppvQANQb8TXNrC8PXYqdXyZpdCP1kRur2CTvwPce1kqwkYcZ5LC3hxjjC"

# -- make the script re-runnable: clean up any leftovers from a partial run ----
for t in before.get("items", []):
    if str(t.get("label", "")).startswith("VERIFY-"):
        api_delete(f"/api/v1/watchlist/{t['id']}", token=token)
    if t.get("value") in ("zzz-verifynotpresent-org",):
        api_delete(f"/api/v1/watchlist/{t['id']}", token=token)

# -- real target: a domain that genuinely appears in the live dark corpus -----
sample_dom = None
rows = ch("SELECT raw_text FROM cti.raw_threat_intel FINAL WHERE source='DARKWEB-ONION' ORDER BY ts DESC LIMIT 500")
words = []
for r in rows:
    words += re.findall(r"[a-z0-9-]+\.(?:com|net|org|onion|io|ru|info|biz|xyz)", (r["raw_text"] or "").lower())
dom_counts = {}
for w in words:
    dom_counts[w] = dom_counts.get(w, 0) + 1
for w, c in sorted(dom_counts.items(), key=lambda kv: -kv[1]):
    if len(w) > 8:
        sample_dom = w
        break
check("a real (non-fabricated) domain harvested from live dark corpus", bool(sample_dom), f"dom={sample_dom}")

st, created = api_post("/api/v1/watchlist",
                       {"type": "domain", "value": sample_dom, "label": "VERIFY-REAL-TARGET"}, token=token)
check("POST /api/v1/watchlist (real target) 201", st == 201 and created.get("created") is True,
      f"created={created.get('created')}")
tid = created.get("target", {}).get("id")

st, created2 = api_post("/api/v1/watchlist",
                        {"type": "domain", "value": sample_dom, "label": "VERIFY-REAL-TARGET"}, token=token)
check("duplicate target is not re-created", st == 201 and created2.get("created") is False)

st, fake = api_post("/api/v1/watchlist",
                    {"type": "org", "value": "zzz-verifynotpresent-org", "label": "VERIFY-NONPRESENT"}, token=token)
check("POST fake-nonpresent org target 201", st == 201, f"value={fake.get('target', {}).get('value')}")
tid_fake = fake.get("target", {}).get("id")

st, listed = api_get("/api/v1/watchlist")
labels = [t["label"] for t in listed["items"]]
check("both targets listed", "VERIFY-REAL-TARGET" in labels and "VERIFY-NONPRESENT" in labels,
      f"labels={labels}")

section("[4] Search: real value hits, honourable zero")
st, real = api_get(f"/api/v1/watchlist/search?type=domain&value={urllib.parse.quote(sample_dom)}")
check("search real domain 200 and >0 matches", st == 200 and real.get("total", 0) > 0,
      f"total={real.get('total')} items_matched={real.get('items_matched')} scanned={real.get('scanned')}")
bad_span = 0
for it in real.get("items", [])[:10]:
    txt = it.get("raw_text") or ""
    for m in it.get("matches", []):
        if not (0 <= (m.get("start") or -1) < (m.get("end") or 0) <= len(txt)):
            bad_span += 1
        if (m.get("term") or "").lower() and (m.get("term") or "").lower() not in txt.lower():
            bad_span += 1
check("search spans are real substrings of the item content", bad_span == 0, f"violations={bad_span}")

st, zero = api_get("/api/v1/watchlist/search?type=org&value=zzz-verifynotpresent-org")
check("search non-present value -> honest zero (200, total=0)", st == 200 and zero.get("total") == 0,
      f"total={zero.get('total')} scanned={zero.get('scanned')}")

section("[5] Sweep: records REAL match(es) for the saved target, NONE for the facade")
st, sweep = api_post("/api/v1/watchlist/sweep", {}, token=token)
check("POST /api/v1/watchlist/sweep 202", st == 202, f"status={sweep.get('status')}")
check("sweep scanned rows (targets present)", sweep.get("targets", 0) >= 2, f"targets={sweep.get('targets')}")

st, mres = api_get("/api/v1/watchlist/matches?limit=100")
check("matches endpoint 200", st == 200)
rows = mres.get("items", [])
real_hits = [r for r in rows if r.get("target_label") == "VERIFY-REAL-TARGET"]
fake_hits = [r for r in rows if r.get("target_label") == "VERIFY-NONPRESENT"]
check("REAL target has >=1 recorded match", len(real_hits) >= 1, f"n={len(real_hits)}")
check("NON-present target has ZERO recorded matches", len(fake_hits) == 0, f"n={len(fake_hits)}")
match_bad = 0
for r in real_hits:
    low = (r.get("target_value") or "").lower()
    term = (r.get("matched_term") or "").lower()
    if not term or (low not in term and term != low and low not in term):
        match_bad += 1
check("matched_term genuinely contains the target value", match_bad == 0, f"violations={match_bad}")
check("recorded match tied to a target watching the same value",
      all((r.get("target_value") or "").lower() == (sample_dom or "").lower() for r in real_hits))
real_url_hits = [r for r in real_hits if r.get("url")]
check("at least one match carries the source item URL", bool(real_url_hits), f"n={len(real_url_hits)}")

section("[6] Existing notification pipeline carried real WATCHLIST alerts")
notif = ch("SELECT category, count() AS n FROM cti.notifications FINAL WHERE category='WATCHLIST' GROUP BY category")
ncount = int(notif[0]["n"]) if notif else 0
check("WATCHLIST notifications recorded in the existing table", ncount >= 1, f"n={ncount}")
if ncount:
    one = ch("SELECT title, severity FROM cti.notifications FINAL WHERE category='WATCHLIST' ORDER BY created_at DESC LIMIT 1")
    check("alerts carry label + severity", "VERIFY-REAL-TARGET" in one[0]["title"] and one[0]["severity"], 
          f"title={one[0]['title'][:60]!r} sev={one[0]['severity']}")

section("[7] Cleanup (remove the two temporary verify targets)")
st, d1 = api_delete(f"/api/v1/watchlist/{tid}", token=token)
st, d2 = api_delete(f"/api/v1/watchlist/{tid_fake}", token=token)
check("soft-delete real target", st == 200 and d1.get("deleted"))
check("soft-delete facade target", st == 200 and d2.get("deleted") if st == 200 else False)
st, after = api_get("/api/v1/watchlist")
check("deleted targets no longer listed", all(t["id"] not in (tid, tid_fake) for t in after["items"]))

section("[8] UI + navigation in the served bundle, nav undisturbed")
with urllib.request.urlopen(f"{API}/", timeout=30) as resp:
    index = resp.read().decode("utf-8")
assets = [u.lstrip("/") for u in index.split('"') if u.endswith(".js") and "/assets/" in u]
with urllib.request.urlopen(f"{API}/{assets[0]}", timeout=120) as resp:
    js = resp.read().decode("utf-8", errors="replace")
for lab in ("Exposure & Watchlist", "Org Exposure", "Recorded matches",
            "Nothing watched yet", "No exposure found"):
    check(f"bundle contains '{lab}'", lab in js)
for existing in ("Dark Web Monitoring", "Telegram Monitoring", "Executive Overview",
                 "Threat Landscape", "Malware & Tools", "Autonomous Triage",
                 "Dark Web & Telegram (Legacy)", "Live Threat Feeds"):
    check(f"existing nav label '{existing}' still present", existing in js)
with urllib.request.urlopen(f"{API}/exposure", timeout=30) as resp:
    html = resp.read().decode("utf-8")
check("/exposure serves the SPA", '<div id="root">' in html)

print("\n" + "=" * 70)
print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("Failed:", "; ".join(FAIL))
    sys.exit(1)
print("ALL ORG EXPOSURE & WATCHLIST CHECKS PASSED")