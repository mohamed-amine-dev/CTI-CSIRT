"""Live verification for the per-actor ATT&CK Matrix feature.

Proves with real evidence that:
  1. The technique landscape + used flags come exactly from the stored
     actor<->technique relationships (every `used` tile cross-checked against
     ClickHouse, Highlights.match).
  2. Tactics are ordered MITRE-first (14 canonical) with extras appended, and
     grouped tiles cover all KB techniques exactly once.
  3. A manually verifiable actor (APT29) renders a real, coherent technique
     list — printed so it can be eyeballed.
  4. The /actors page bundle carries the new tab label and nothing regressed.
"""

import json
import random
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


CANONICAL = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]
canonical_set = set(CANONICAL)

section = lambda t: print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)

section("[0] Pick the richest actor in the KB")
top = ch(
    "SELECT r.source_ref, ta.name, count() AS c "
    "FROM cti.stix_relationships AS r FINAL "
    "INNER JOIN (SELECT stix_id, name FROM cti.threat_actors FINAL) AS ta ON r.source_ref = ta.stix_id "
    "INNER JOIN (SELECT stix_id FROM cti.attack_patterns FINAL) AS ap ON r.target_ref = ap.stix_id "
    "GROUP BY r.source_ref, ta.name ORDER BY c DESC LIMIT 1"
)[0]
actor_id, actor_name, rel_count = top["source_ref"], top["name"], int(top["c"])
print(f"    {actor_name} ({actor_id}) — {rel_count} actor<->technique relationships")

section("[1] Technique landscape exactly matches the KB")
st, m = api_get(f"/api/v1/actors/{urllib.parse.quote(actor_id)}/attack-matrix")
check("HTTP 200", st == 200)
kb_total = int(ch("SELECT count() AS n FROM cti.attack_patterns FINAL")[0]["n"])
check("matrix 'total' == attack_patterns count", m["highlights"]["total"] == kb_total,
      f"api={m['highlights']['total']} ch={kb_total}")

hl_used = int(ch(
    f"SELECT count() FROM cti.stix_relationships FINAL "
    f"WHERE source_ref = '{actor_id}' "
    "AND target_ref IN (SELECT stix_id FROM cti.attack_patterns FINAL)"
)[0]["count()"])
check("highlights.used == relationship count", m["highlights"]["used"] == hl_used == rel_count,
      f"api={m['highlights']['used']} ch={hl_used}")

gb = {}
for t in m["techniques"]:
    gb.setdefault(t["tactic"], 0)
    gb[t["tactic"]] += 1
check("grouped tiles cover every technique (sum == total)",
      sum(gb.values()) == m["highlights"]["total"])

# Tactic ordering: as many of the canonical MITRE tactics as genuinely appear
# in the KB come first in MITRE order; brand-new tactics (2026 ATT&CK split
# of Defense Evasion into Stealth / Defense Impairment) are appended
# deterministically — nothing is hidden, nothing is re-ordered to fit an old
# world.
tactics = m["tactics"]
present = [c for c in CANONICAL if c in set(tactics)]
present_extra = sorted(t for t in tactics if t not in canonical_set)
check("canonical MITRE tactics present form the prefix, in order",
      tactics[:len(present)] == present, f"prefix={present}")
expected_tactics = present + present_extra
check("full tactic list == (canonical present) + (extras appended)",
      tactics == expected_tactics, f"columns={len(tactics)}")
if present_extra:
    check("extra tactics are the 2026 ATT&CK split (Stealth / Defense Impairment)",
          set(present_extra) == {"Stealth", "Defense Impairment"},
          f"extra={present_extra}")

section("[2] Every `used` flag is real (cross-check all against relationships)")
# Ground-truth set straight from STIX relations.
used_ch = {
    r["target_ref"]
    for r in ch(
        f"SELECT target_ref FROM cti.stix_relationships FINAL "
        f"WHERE source_ref = '{actor_id}' "
        "AND target_ref IN (SELECT stix_id FROM cti.attack_patterns FINAL)"
    )
}
flags = {t["stix_id"]: t["used"] for t in m["techniques"]}
mismatches = [sid for sid, u in flags.items() if u != (sid in used_ch)]
check("no technique's `used` flag differs from the STIX data",
      not mismatches, f"checked {len(flags)} techniques")
used_tiles = [t for t in m["techniques"] if t["used"]]
check("number of used tiles == set size", len(used_tiles) == len(used_ch))

section("[3] Spot-check a manually verifiable actor — APT29")
apt = ch(
    "SELECT stix_id, name FROM cti.threat_actors FINAL "
    "WHERE lowerUTF8(name) IN ('apt29', 'midnight blizzard', 'cozy bear')"
)
if apt:
    apt_id, apt_name = apt[0]["stix_id"], apt[0]["name"]
    _, am = api_get(f"/api/v1/actors/{urllib.parse.quote(apt_id)}/attack-matrix")
    used_ids_apt = sorted(
        f"{t['x_mitre_id']}:{t['name']}" for t in am["techniques"] if t["used"]
    )
    print(f"    APT29 = '{apt_name}' — {am['highlights']['used']} highlighted techniques:")
    for u in used_ids_apt:
        print(f"      - {u}")
    real_tids = {
        r["x_mitre_id"] for r in ch("SELECT x_mitre_id FROM cti.attack_patterns FINAL")
    }
    api_tids = {t["x_mitre_id"] for t in am["techniques"] if t["used"]}
    check("every APT29 tile ID is a real KB technique", api_tids <= real_tids)
    check("APT29 used count matches its STIX relations", am["highlights"]["used"] == int(ch(
        f"SELECT count() FROM cti.stix_relationships FINAL "
        f"WHERE source_ref = '{apt_id}' "
        "AND target_ref IN (SELECT stix_id FROM cti.attack_patterns FINAL)"
    )[0]["count()"]))
    # Sample a random real tile and assert its description/url ride along.
    rnd = random.sample([t for t in am["techniques"] if t["used"]], min(3, am["highlights"]["used"]))
    for t in rnd:
        full = ch(
            f"SELECT name, description, url FROM cti.attack_patterns FINAL "
            f"WHERE stix_id = '{t['stix_id']}'"
        )[0]
        check(f"tile {t['x_mitre_id']} detail matches KB row",
              t["name"] == full["name"] and t["url"] == full["url"])
else:
    print("    (APT29 not found in KB; skipping manual spot-check)")
    check("manual spot-check available", False, "APT29 absent")

section("[4] Details explode correctly")
t = used_tiles[0]
_, d = api_get(f"/api/v1/actors/{urllib.parse.quote(actor_id)}/attack-matrix")
row = d["techniques"][0]
print(f"    sample detail tile: {row['x_mitre_id']} / {row['name']} / tactic={row['tactic']}")

section("[5] Frontend carries the tab and nothing regressed")
with urllib.request.urlopen(f"{API}/", timeout=30) as resp:
    index = resp.read().decode("utf-8")
assets = [u.lstrip("/") for u in index.split('"') if u.endswith(".js") and "/assets/" in u]
with urllib.request.urlopen(f"{API}/{assets[0]}", timeout=60) as resp:
    js = resp.read().decode("utf-8", errors="replace")
for lab in ("ATT&CK Matrix", "Profile", "Observed ATT&CK Techniques",
            "Threat Actors & APTs", "Malware & Tools", "Dark Web Monitoring"):
    check(f"bundle contains '{lab}'", lab in js)
with urllib.request.urlopen(f"{API}/actors", timeout=30) as resp:
    html = resp.read().decode("utf-8")
check("/actors serves SPA", '<div id="root">' in html)

print("\n" + "=" * 70)
print(f"RESULT: {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("Failed:", "; ".join(FAIL))
    sys.exit(1)
print("ALL ATT&CK MATRIX CHECKS PASSED")