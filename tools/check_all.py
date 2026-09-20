import py_compile, sys

fails = []
for f in ["app/main.py", "app/routers/actors.py", "app/routers/export.py",
          "app/auth.py", "app/db_init.py"]:
    try:
        py_compile.compile(f, doraise=True)
        print("OK  ", f)
    except Exception as e:
        fails.append(f)
        print("BAD ", f, "->", str(e).splitlines()[-1][:160])
if fails:
    print("FAILURES:", fails)
    sys.exit(1)
print("ALL FIVE MODULES COMPILE CLEAN")
