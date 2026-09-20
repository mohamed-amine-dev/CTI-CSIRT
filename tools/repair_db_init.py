# Byte-safe repair for app/db_init.py. The parser dies at line 474 with an
# unterminated triple-quoted string (detected at 497/EOF) -- a corrupted tail.
# This keeps lines 1-472 exactly as-is (the parser reached 474, so those bytes
# are provably fine) and rewrites ONLY the tail 473..EOF as a canonical block.
# Then it gates itself with py_compile. No shell quoting anywhere.

import io
import os
import sys
import py_compile

P = "app/db_init.py"

# Read text as UTF-8 (file has no BOM; keep it that way).
with io.open(P, "r", encoding="utf-8", newline="") as f:
    text = f.read()

# Diagnose first: confirm the file actually ends with the corrupt def.
j = text.index("def create_schema(")
head, tail = text[:j], text[j:]
print("tail byte-length:", len(tail))
print("tail first 120 bytes:", repr(tail[:120]))

# New canonical tail. Ends-of-lines: preserve whatever the file mostly uses.
sample = text.split("\n")
nl = "\r\n" if len(sample) > 2 and sample[0].endswith("\r") else "\n"
print("newline style:", repr(nl))

canonical = (
    'def create_schema() -> None:\n'
    '    """Create the database and every table. Idempotent (IF NOT EXISTS)."""\n'
    '    # 1. Bootstrap: create the database using a no-default-DB connection.\n'
    '    admin: clickhouse_connect.driver.Client = get_admin_sync_client()\n'
    '    try:\n'
    '        admin.command('
    'f"CREATE DATABASE IF NOT EXISTS {settings.clickhouse_database}")\n'
    '    finally:\n'
    '        admin.close()\n'
    '\n'
    '    # 2. Create the tables using a client bound to the target database.\n'
    '    client: clickhouse_connect.driver.Client = get_sync_client()\n'
    '    try:\n'
    '        for name, ddl in DDL.items():\n'
    '            client.command(ddl)\n'
    '            logger.info("created table %s.%s", '
    'settings.clickhouse_database, name)\n'
    '        _migrate(client)\n'
    '        logger.info("schema migrations applied")\n'
    '    finally:\n'
    '        client.close()\n'
    '\n'
    '\n'
    'if __name__ == "__main__":\n'
    '    logger.info("initialising schema on %s", settings.clickhouse_url)\n'
    '    create_schema()\n'
    '    logger.info("done. next: uvicorn app.main:app --reload")\n'
)
if nl == "\r\n":
    canonical = canonical.replace("\n", "\r\n")

out = head + canonical
with io.open(P, "w", encoding="utf-8", newline="") as f:
    f.write(out)

# Gate: the repaired file must actually compile.
try:
    py_compile.compile(P, doraise=True)
    print("REPAIR: PASS (db_init.py compiles)")
except py_compile.PyCompileError as e:
    print("REPAIR: FAIL ->", e)
    sys.exit(1)
