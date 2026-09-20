# =============================================================================
# Phase 4 - create / manage a platform user from the command line
# -----------------------------------------------------------------------------
# The only supported way to provision an account (RBAC is asymmetric by
# design: sign-up is *not* exposed by the API). Call inside the app container:
#
#   docker compose exec -T app python tools/create_user.py
#         --username alice --password 'S3cure-Pass!' \
#         --workspace TI --tlp-clearance RED --admin
#
# Flags
#   --username, --password      required
#   --workspace (repeatable)    one or more of TI / CERT / DFIR (default: TI)
#   --tlp-clearance             CLEAR|GREEN|AMBER|AMBER+STRICT|RED (default CLEAR)
#   --admin / --no-admin        grant/deny the platform-admin role
#   --add-totp-secret <base32>  attach an existing TOTP secret (auto-enables 2FA)
#   --disable / --enable        flip the soft "disabled" flag
#   --list                      print a summary of every account
# =============================================================================

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from typing import Any

from app.auth import WORKSPACES, TLP_ORDER, hash_password
from app.config import settings
from app.db import get_sync_client

USER_COLUMNS = ["username", "password_hash", "totp_secret", "totp_enabled",
                 "workspace_tags", "tlp_clearance", "is_admin", "is_disabled", "version"]


def _find_user(client, username: str) -> dict[str, Any] | None:
    rows = client.query(
        f"""
        SELECT id, username, password_hash, totp_secret, totp_enabled,
               workspace_tags, tlp_clearance, is_admin, is_disabled, version
        FROM {settings.clickhouse_database}.users FINAL
        WHERE username = {{u:String}}
        """,
        parameters={"u": username},
    )
    if not rows.result_rows:
        return None
    r = rows.result_rows[0]
    return {
        "username": r[1],
        "password_hash": r[2],
        "totp_secret": r[3],
        "totp_enabled": bool(r[4]),
        "workspace_tags": r[5] or [],
        "tlp_clearance": (r[6] or "CLEAR").upper(),
        "is_admin": bool(r[7]),
        "is_disabled": bool(r[8]),
        "version": r[9],
    }


def _upsert(client, user: dict[str, Any]) -> None:
    client.insert(
        table=f"{settings.clickhouse_database}.users",
        data=[[
            user["username"],
            user["password_hash"],
            user.get("totp_secret", ""),
            1 if user.get("totp_enabled") else 0,
            user.get("workspace_tags", []),
            (user.get("tlp_clearance") or "CLEAR").upper(),
            1 if user.get("is_admin") else 0,
            1 if user.get("is_disabled") else 0,
            int(time.time() * 1_000_000),
        ]],
        column_names=USER_COLUMNS,
    )


def cmd_create(args: argparse.Namespace) -> None:
    tags = [w.upper() for w in args.workspace]
    bad = [w for w in tags if w not in WORKSPACES]
    if bad:
        print(f"error: invalid workspace tag(s): {', '.join(bad)} "
              f"(allowed: {', '.join(WORKSPACES)})")
        sys.exit(2)
    tlp = args.tlp_clearance.upper()
    if tlp not in TLP_ORDER:
        print(f"error: invalid TLP clearance: {tlp} "
              f"(allowed: {', '.join(TLP_ORDER)})")
        sys.exit(2)
    if len(args.username.strip()) < 3 or len(args.password) < 8:
        print("error: username (>=3 chars) and password (>=8 chars) required")
        sys.exit(2)

    client = get_sync_client()
    try:
        existing = _find_user(client, args.username)
        if existing is not None:
            print(f"error: user '{args.username}' already exists "
                  "(use --tlp-clearance/--workspace/etc. with --enable to update, "
                  "or --list to inspect)")
            sys.exit(1)
        _upsert(client, {
            "username": args.username,
            "password_hash": hash_password(args.password),
            "totp_secret": args.add_totp_secret or "",
            "totp_enabled": bool(args.add_totp_secret),
            "workspace_tags": tags,
            "tlp_clearance": tlp,
            "is_admin": args.admin,
            "is_disabled": False,
        })
        print(f"created user '{args.username}' "
              f"workspace={','.join(tags)} clearance={tlp} "
              f"admin={args.admin} 2fa={'on' if args.add_totp_secret else 'off'}")
    finally:
        client.close()


def cmd_update(args: argparse.Namespace) -> None:
    client = get_sync_client()
    try:
        user = _find_user(client, args.username)
        if user is None:
            print(f"error: user '{args.username}' not found")
            sys.exit(1)
        if args.password:
            user["password_hash"] = hash_password(args.password)
        if args.workspace:
            tags = [w.upper() for w in args.workspace]
            bad = [w for w in tags if w not in WORKSPACES]
            if bad:
                print(f"error: invalid workspace tag(s): {', '.join(bad)}")
                sys.exit(2)
            user["workspace_tags"] = tags
        if args.tlp_clearance:
            tlp = args.tlp_clearance.upper()
            if tlp not in TLP_ORDER:
                print(f"error: invalid TLP clearance: {tlp}")
                sys.exit(2)
            user["tlp_clearance"] = tlp
        if args.admin is not None:
            user["is_admin"] = args.admin
        if args.add_totp_secret:
            user["totp_secret"] = args.add_totp_secret
            user["totp_enabled"] = True
        if args.disable:
            user["is_disabled"] = True
        if args.enable:
            user["is_disabled"] = False
            user["username"] = args.username
        _upsert(client, user)
        print(f"updated user '{args.username}'")
    finally:
        client.close()


def cmd_list(args: argparse.Namespace) -> None:
    client = get_sync_client()
    try:
        rows = client.query(
            f"""
            SELECT username, workspace_tags, tlp_clearance, is_admin,
                   totp_enabled, is_disabled
            FROM {settings.clickhouse_database}.users FINAL
            ORDER BY username
            """
        )
        if not rows.result_rows:
            print("(no users yet)")
            return
        print(f"{'USERNAME':<16}{'WORKSPACES':<22}{'CLEARANCE':<12}{'ADMIN':<6}{'2FA':<5}STATE")
        for r in rows.result_rows:
            admin = "yes" if r[3] else "no"
            tfa = "on" if r[4] else "off"
            state = "disabled" if r[5] else "active"
            print(f"{r[0]:<16}{','.join(r[1] or []):<22}{r[2] or 'CLEAR':<12}{admin:<6}{tfa:<5}{state}")
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision / scrub CTI platform user accounts (RBAC + TLP).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="provision a new account")
    p_create.add_argument("--username", required=True)
    p_create.add_argument("--password", required=True)
    p_create.add_argument("--workspace", action="append", default=["TI"])
    p_create.add_argument("--tlp-clearance", default="CLEAR")
    p_create.add_argument("--admin", action="store_true")
    p_create.add_argument("--add-totp-secret", default="")

    p_update = sub.add_parser("update", help="modify an existing account")
    p_update.add_argument("--username", required=True)
    p_update.add_argument("--password", default="")
    p_update.add_argument("--workspace", action="append")
    p_update.add_argument("--tlp-clearance", default="")
    p_update.add_argument("--admin", action=argparse.BooleanOptionalAction, default=None)
    p_update.add_argument("--add-totp-secret", default="")
    p_update.add_argument("--disable", action="store_true")
    p_update.add_argument("--enable", action="store_true")

    sub.add_parser("list", help="summarise every account")

    args = parser.parse_args()
    if args.command == "create":
        cmd_create(args)
    elif args.command == "update":
        cmd_update(args)
    else:
        cmd_list(args=args)


if __name__ == "__main__":
    main()
