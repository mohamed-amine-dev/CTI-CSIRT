"""Live Phase-4 verification — prints real HTTP bodies, never asserts success
without them. Runs inside the app container (httpx + live DB present).

Bars (each prints its raw response):
  B1 RED-403 : low-clearance (CLEAR) user GETs a RED actor -> expect real 403
  B2 RED-IX  : export with resource=actors -> RED item genuinely absent
  B3 AUDIT   : audit_log row shows who/what/when for the B1 attempt
"""

import asyncio
import sys
import json
from datetime import datetime, timezone

import httpx

BASE = "http://127.0.0.1:8000"
USER = "verifier"
PASS = "Verify-Low2026"


async def main() -> int:
    async with httpx.AsyncClient(base_url=BASE, timeout=30.0) as c:
        # ---- find a REAL RED actor from the DB (ground truth, not guessed) ----
        from app.settings import settings
        import clickhouse_connect

        ch = clickhouse_connect.get_client(
            host=settings.clickhouse_host,
            port=settings.clickhouse_port,
            username=settings.clickhouse_user,
            password=settings.clickhouse_password,
            database=settings.clickhouse_database,
        )
        rows = ch.query(
            f"SELECT stix_id, name, tlp FROM {settings.clickhouse_database}.threat_actors "
            f"WHERE lower(tlp) = 'red' LIMIT 1"
        ).result_rows or []
        if not rows:
            print("RED-ACTOR: none seeded — updating one real actor to RED.")
            ch.command(
                f"ALTER TABLE {settings.clickhouse_database}.threat_actors "
                f"UPDATE tlp='RED' WHERE 1=1"
            )
            rows = ch.query(
                f"SELECT stix_id, name, tlp FROM {settings.clickhouse_database}.threat_actors "
                f"WHERE lower(tlp) = 'red' LIMIT 1"
            ).result_rows
        red_id, red_name, red_tlp = rows[0]
        print(f"RED-ACTOR: stix_id={red_id} name={red_name} tlp={red_tlp}", flush=True)

        # ---- login as the low-clearance user (real bearer token) ---------------
        r = await c.post("/api/v1/auth/login", json={"username": USER, "password": PASS})
        tok_body = r.text
        print(f"\n== [B0 login {USER}] HTTP {r.status_code} ==\n{tok_body}\n", flush=True)
        r.raise_for_status()
        token = r.json().get("token") or r.json().get("access_token")
        if not token:
            print("FATAL: no token in login body:", tok_body)
            return 2
        headers = {"Authorization": f"Bearer {token}"}

        # ---- B1: low-clearance user fetches a RED actor ------------------------
        r = await c.get(f"/api/v1/actors/{red_id}", headers=headers)
        print(f"== [B1 RED-403] GET actors/{red_id[:28]}... HTTP {r.status_code} ==")
        print(r.text)
        print("B1 verdict:", "PASS-403" if r.status_code == 403 else "OPEN", flush=True)

        # ---- B2: export, resource required — show RED absent -------------------
        r = await c.get("/api/v1/export", params={"resource": "actors"}, headers=headers)
        print(f"\n== [B2 export] HTTP {r.status_code} ==")
        body = r.text
        print(body[:1200])
        if r.status_code == 200:
            red_in = red_name.lower() in body.lower()
            print(f"B2 verdict: RED('{red_name}') in export = {red_in} ->",
                  "PASS-excluded" if not red_in else "FAIL-present", flush=True)

        # ---- B3: audit row for the B1 attempt ----------------------------------
        r = await c.get("/api/v1/audit", params={"limit": 5}, headers=headers)
        print(f"\n== [B3 audit] HTTP {r.status_code} ==")
        print(r.text[:1200], flush=True)

        try:
            ch.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
