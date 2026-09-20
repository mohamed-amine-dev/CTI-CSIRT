import io, tokenize

src = io.open("app/db_init.py", encoding="utf-8").read()
# Naive parity scan: every occurrence of a triple-quote (""", '''). If the
# count is odd, the module is genuinely mis-paired and py_compile's verdict is
# correct. If even, the docstring lines are balanced and something else is
# wrong.
even = 0
odd = 0
seen = []
for kind, pat in (("DQUOTE", '"""'), ("SQUOTE", "'''")):
    start = 0
    while True:
        i = src.find(pat, start)
        if i < 0:
            break
        ln = src.count("\n", 0, i) + 1
        seen.append((ln, kind, i))
        start = i + 3
print("total triple-quote markers:", len(seen))
print("line:marker offset")
for ln, kind, off in seen:
    print(f"{ln}: {kind} @off={off}")
print("EVEN" if len(seen) % 2 == 0 else "ODD")

# Tokenize view of the exact lines tokenizer flags around 470-497.
try:
    with io.open("app/db_init.py", "rb") as f:
        toks = list(tokenize.tokenize(f.readline))
    print("tokenize: OK")
except Exception as e:
    print("tokenize: FAIL ->", type(e).__name__, str(e)[:200])
