"""Syntax-check the Brief #5 backend files (compile at text level; the app deps
like fastapi only exist inside the container)."""

from pathlib import Path

files = [
    "app/routers/malware.py",
    "app/ingestion_engine.py",
    "app/attack_importer.py",
    "app/db_init.py",
    "app/threat_classify.py",
    "app/routers/actors.py",
]
ok, bad = [], []
for rel in files:
    p = Path(rel)
    try:
        compile(p.read_text(encoding="utf-8"), str(p), "exec")
        ok.append(rel)
    except SyntaxError as e:
        bad.append(f"{rel}:{e.lineno} {e.msg}")
print("OK:", "; ".join(ok))
print("BAD:", "; ".join(bad) if bad else "(none)")
raise SystemExit(1 if bad else 0)