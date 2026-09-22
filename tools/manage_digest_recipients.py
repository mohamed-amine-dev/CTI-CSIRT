# =============================================================================
# Daily email digest - manage the CSIRT recipient list from the command line
# -----------------------------------------------------------------------------
# The mailing list is admin-managed by design: there is NO public sign-up. Use
# this tool (or the admin API at /api/v1/digest) to add / change / remove the
# people who receive the scheduled digest. Call inside the app container:
#
#   docker compose exec -T app python tools/manage_digest_recipients.py add \
#         --email analyst@example.org --frequency daily
#
# Subcommands
#   add     --email <addr> [--frequency daily|every_2_days] [--disabled] [--added-by <who>]
#   update  --email <addr> [--frequency ...] [--enable|--disable]
#   remove  --email <addr>
#   reset-sent --email <addr>     force the recipient due again (last_sent_at = epoch)
#   list                          print every recipient and its cadence
# =============================================================================

from __future__ import annotations

import argparse
import datetime as _dt
import sys
import time
from typing import Any

from app.config import settings
from app.db import get_sync_client
from app.digest import FREQUENCIES, valid_email, valid_frequency

_EPOCH = _dt.datetime(1970, 1, 1, 0, 0, 0)
_COLUMNS = ["email", "enabled", "frequency", "added_by", "created_at", "last_sent_at", "version"]


def _table() -> str:
    return f"{settings.clickhouse_database}.digest_recipients"


def _find(client, email: str) -> dict[str, Any] | None:
    rows = client.query(
        f"SELECT email, enabled, frequency, added_by, created_at, last_sent_at "
        f"FROM {_table()} FINAL WHERE email = {{e:String}}",
        parameters={"e": email},
    )
    if not rows.result_rows:
        return None
    r = rows.result_rows[0]
    return {
        "email": str(r[0]),
        "enabled": bool(r[1]),
        "frequency": str(r[2]),
        "added_by": str(r[3] or ""),
        "created_at": r[4] or _dt.datetime.now(),
        "last_sent_at": r[5] or _EPOCH,
    }


def _write(client, rec: dict[str, Any]) -> None:
    client.insert(
        table=_table(),
        data=[[
            rec["email"], 1 if rec["enabled"] else 0, rec["frequency"],
            rec.get("added_by", ""), rec["created_at"], rec["last_sent_at"],
            int(time.time() * 1_000_000),
        ]],
        column_names=_COLUMNS,
    )


def _check_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not valid_email(email):
        print(f"error: invalid email address: {email!r}")
        sys.exit(2)
    return email


def cmd_add(args: argparse.Namespace) -> None:
    email = _check_email(args.email)
    frequency = args.frequency.strip().lower()
    if not valid_frequency(frequency):
        print(f"error: frequency must be one of {', '.join(FREQUENCIES)}")
        sys.exit(2)
    client = get_sync_client()
    try:
        existing = _find(client, email)
        if existing is not None:
            print(f"error: recipient '{email}' already exists "
                  "(use `update` to change cadence / enable state)")
            sys.exit(1)
        _write(client, {
            "email": email, "enabled": not args.disabled, "frequency": frequency,
            "added_by": args.added_by, "created_at": _dt.datetime.now(),
            "last_sent_at": _EPOCH,
        })
        state = "disabled" if args.disabled else "enabled"
        print(f"added recipient '{email}' frequency={frequency} ({state})")
    finally:
        client.close()


def cmd_update(args: argparse.Namespace) -> None:
    email = _check_email(args.email)
    client = get_sync_client()
    try:
        rec = _find(client, email)
        if rec is None:
            print(f"error: recipient '{email}' not found")
            sys.exit(1)
        if args.frequency:
            frequency = args.frequency.strip().lower()
            if not valid_frequency(frequency):
                print(f"error: frequency must be one of {', '.join(FREQUENCIES)}")
                sys.exit(2)
            rec["frequency"] = frequency
        if args.enable is not None:
            rec["enabled"] = args.enable
        _write(client, rec)
        print(f"updated recipient '{email}' frequency={rec['frequency']} "
              f"enabled={rec['enabled']}")
    finally:
        client.close()


def cmd_remove(args: argparse.Namespace) -> None:
    email = _check_email(args.email)
    client = get_sync_client()
    try:
        if _find(client, email) is None:
            print(f"error: recipient '{email}' not found")
            sys.exit(1)
        client.command(
            f"ALTER TABLE {_table()} DELETE WHERE email = {{e:String}}",
            parameters={"e": email},
        )
        print(f"removed recipient '{email}'")
    finally:
        client.close()


def cmd_reset_sent(args: argparse.Namespace) -> None:
    email = _check_email(args.email)
    client = get_sync_client()
    try:
        rec = _find(client, email)
        if rec is None:
            print(f"error: recipient '{email}' not found")
            sys.exit(1)
        rec["last_sent_at"] = _EPOCH
        _write(client, rec)
        print(f"reset last_sent_at for '{email}' (recipient is due again)")
    finally:
        client.close()


def cmd_list(args: argparse.Namespace) -> None:
    client = get_sync_client()
    try:
        rows = client.query(
            f"SELECT email, enabled, frequency, last_sent_at "
            f"FROM {_table()} FINAL ORDER BY email"
        )
        if not rows.result_rows:
            print("(no recipients yet)")
            return
        print(f"{'EMAIL':<34}{'FREQUENCY':<14}{'STATE':<10}LAST_SENT_AT")
        for r in rows.result_rows:
            last = r[3] or _EPOCH
            last_txt = "never" if last <= _EPOCH else last.strftime("%Y-%m-%d %H:%M:%S")
            state = "enabled" if r[1] else "disabled"
            print(f"{r[0]:<34}{r[2]:<14}{state:<10}{last_txt}")
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Manage the CSIRT daily-digest recipient list (no public sign-up).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="add a recipient")
    p_add.add_argument("--email", required=True)
    p_add.add_argument("--frequency", default="daily")
    p_add.add_argument("--disabled", action="store_true")
    p_add.add_argument("--added-by", default="cli")

    p_update = sub.add_parser("update", help="change cadence / enable state")
    p_update.add_argument("--email", required=True)
    p_update.add_argument("--frequency", default="")
    p_update.add_argument("--enable", action=argparse.BooleanOptionalAction, default=None)

    p_remove = sub.add_parser("remove", help="remove a recipient")
    p_remove.add_argument("--email", required=True)

    p_reset = sub.add_parser("reset-sent", help="force a recipient due again")
    p_reset.add_argument("--email", required=True)

    sub.add_parser("list", help="print every recipient")

    args = parser.parse_args()
    {
        "add": cmd_add,
        "update": cmd_update,
        "remove": cmd_remove,
        "reset-sent": cmd_reset_sent,
        "list": cmd_list,
    }[args.command](args)


if __name__ == "__main__":
    main()
