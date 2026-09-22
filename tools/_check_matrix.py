"""Syntax-level compile check for the ATT&CK Matrix backend change.

No inline shell `python -c` — this file is the check itself. The JSX side is
validated by the Vite production build (npm run build) before the stack is
rebuilt.
"""
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent.parent
targets = ["app/routers/actors.py"]
ok = True
for rel in targets:
    src = (root / rel).read_text(encoding="utf-8")
    try:
        compile(src, rel, "exec")
    except SyntaxError as exc:
        ok = False
        print(f"SYNTAX ERROR {rel}: {exc}")
    else:
        print(f"ok {rel}")

sys.exit(0 if ok else 1)