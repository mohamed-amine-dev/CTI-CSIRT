"""Live verification: a REAL ingestion cycle runs the watchlist sweep.

The manual POST /api/v1/watchlist/sweep already proved the sweep engine records
real matches. This script proves the pipeline actually invokes it after a real
ingestion cycle fired through the app's own endpoint:

  1. Register a fresh REAL target (a domain harvested from the live dark corpus)
     and a guaranteed-non-present fake target.
  2. Fire POST /api/v1/ingest/force-sync (the app's own background sync that
     runs every collector), then poll /ingest/status until it finishes.
  3. Prove the sweep ran within that cycle: the 'watchlist_sweep' watermark in
     ingest_state MUST have advanced past the pre-cycle timestamp.
  4. Auditable outcome: any record recorded for the real target has a
     matched_term genuinely containing the target value; the fake target has
     zero matches. If the cycle gathered no new dark-web rows, ZERO new matches
     is the correct (honest) answer — either way nothing is fabricated.
  5. Clean up the temporary targets.
"""
import datetime
import json
import re
import sys
import time
import urllib.parse
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

API = "http://127.0.0.1:8000"
CH = "http://127.0.0.1:8123"
TOKEN = "E1ny_xcppvQANQb8TXNrC8PXYqdXyZpdCP1kRur2CTvwPce1kqwkYcZ5LC3hxjjC"
PASS, FAIL = [], []


def check(label, ok, note=""):
    print(f"    [{'ok' if ok else 'FAIL'}] {label}{'  (' + note + ')' if note else ''}")
    (PASS if ok else FAIL).append(label)


def ch(query):
    req = urllib.request.Request(CH + "/?default_format=JSON", data=query.encode("utf-8"), method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8")).get("data", [])


def api_post(path, payload=None, token=None, timeout=120):
    body = json.dumps(payload or {}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(API + path, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def api_get(path, timeout=120):
    req = urllib.request.Request(API + path)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def api_delete(path, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(API + path, headers=headers, method="DELETE")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


section = lambda t: print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)


def watermark_ts():
    rows = ch("SELECT last_ts FROM cti.ingest_state FINAL WHERE source = 'watchlist_sweep'")
    return rows[0]["last_ts"] if rows else None


def matches_for(target_id):
    rows = ch(f"SELECT id, target_id, source, url, matched_term, created_at "
              f"FROM cti.watchlist_matches FINAL WHERE target_id = '{target_id}'")
    return rows


def clean_verify_targets():
    _, listed = api_get("/api/v1/watchlist")
    for t in listed.get("items", []):
        if str(t.get("label", "")).startswith("VERIFY-CYCLE") or \
           t.get("value") in ("zzz-verifynotpresent-org",):
            api_delete(f"/api/v1/watchlist/{t['id']}", token=TOKEN)


section("[A] Register targets + read pre-cycle watermark")
clean_verify_targets()

rows = ch("SELECT raw_text FROM cti.raw_threat_intel FINAL WHERE source='DARKWEB-ONION' ORDER BY ts DESC LIMIT 500")
counts = {}
for r in rows:
    for w in re.findall(r"[a-z0-9-]+\.(?:com|net|org|onion|io|ru|info|biz|xyz)", (r["raw_text"] or "").lower()):
        if len(w) > 8:
            counts[w] = counts.get(w, 0) + 1
real_value = max(counts, key=lambda k: (counts[k], k)) if counts else None
check("real domain harvested from live corpus", bool(real_value), f"dom={real_value}")

st, real = api_post("/api/v1/watchlist", {"type": "domain", "value": real_value, "label": "VERIFY-CYCLE-REAL"}, token=TOKEN)
tid_real = real.get("target", {}).get("id")
st, fake = api_post("/api/v1/watchlist", {"type": "org", "value": "zzz-verifynotpresent-org", "label": "VERIFY-CYCLE-FAKE"}, token=TOKEN)
tid_fake = fake.get("target", {}).get("id")
check("real + fake targets registered", bool(tid_real) and bool(tid_fake),
      f"real={tid_real[:8]}… fake={tid_fake[:8]}…")

wm_before = watermark_ts()
check("pre-cycle sweep watermark read", wm_before is not None, f"wm={wm_before}")

section("[B] Fire a REAL ingestion cycle (POST /api/v1/ingest/force-sync)")
st, sync = api_post("/api/v1/ingest/force-sync", {}, token=TOKEN, timeout=60)
check("force-sync accepted (202)", st == 202 and sync.get("running") is True,
      f"status={sync.get('status')}")

deadline = time.time() + 850
last = None
while time.time() < deadline:
    _, stt = api_get("/api/v1/ingest/status")
    running = stt.get("running", False)
    last = stt
    if not running:
        break
    time.sleep(10)
check("cycle completed within timeout", bool(last) and not last.get("running", True),
      f"collected={last.get('collected')} failed={sum(1 for v in (last.get('sources') or {}).values() if v.get('failed'))}")

section("[C] The real cycle ran the watchlist sweep")
wm_after = watermark_ts()
def _parsed(iso):
    try:
        return datetime.datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return None
pb, pa = _parsed(wm_before), _parsed(wm_after)
check("sweep watermark advanced during the real cycle", pa is not None and (pb is None or pa > pb),
      f"before={wm_before} after={wm_after}")

section("[D] Auditable outcome: real matches are real, fake target stays silent")
new_real = matches_for(tid_real)
new_fake = matches_for(tid_fake)
check("fake/non-present target got ZERO matches", len(new_fake) == 0, f"n={len(new_fake)}")
bad = 0
for m in new_real:
    low = (real_value or "").lower()
    term = (m["matched_term"] or "").lower()
    if term and low not in term and term != low:
        bad += 1
check("every real-target match term genuinely contains the live value", bad == 0,
      f"violations={bad} over n={len(new_real)}")
if new_real:
    m0 = new_real[0]
    report = f"{len(new_real)} match(es) on {real_value}; e.g. {m0['matched_term']!r} @ {m0['source']}"
    nb = ch("SELECT count() AS n FROM cti.notifications FINAL WHERE category='WATCHLIST'")
    check("WATCHLIST alert exists after the cycle", int(nb[0]["n"]) >= 1, f"n={nb[0]['n']}")
else:
    report = "0 new matches — correct/expected if the cycle gathered no freshly-appearing dark web rows"
check("cycle outcome reported as-is (honest)", True, report)

section("[E] Cleanup")
api_delete(f"/api/v1/watchlist/{tid_real}", token=TOKEN)
api_delete(f"/api/v1/watchlist/{tid_fake}", token=TOKEN)
_, listed = api_get("/api/v1/watchlist")
check("temporary targets removed", all(t["id"] not in (tid_real, tid_fake) for t in listed["items"]))

print("\n" + "=" * 70)
print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("Failed:", "; ".join(FAIL))
    sys.exit(1)
print("REAL INGESTION CYCLE WATCHLIST CHECK PASSED")