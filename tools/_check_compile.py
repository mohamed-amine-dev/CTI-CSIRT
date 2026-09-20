import sys

files = ["app/main.py", "app/db_init.py", "app/routers/actors.py",
         "app/routers/export.py", "app/auth.py"]
ok, bad = [], []
for f in files:
    try:
        with open(f, encoding="utf-8") as fh:
            compile(fh.read(), f, "exec")
        ok.append(f)
    except SyntaxError as e:
        bad.append(f"{f}:{e.lineno} {e.msg[:70]}")
print("OK:", "; ".join(ok))
print("BAD:", "; ".join(bad) if bad else "(none)")
