# One-pass repair of app/db_init.py tail corruption (unterminated triple-quote
# at ~474 reached EOF). Strategy: locate every TOP-LEVEL def via byte offsets,
# verify the migrate/create tail region, and only then decide — no guessing.

import re
import io

P = "app/db_init.py"
src = open(P, encoding="utf-8").read()

# Top-level statements: a def starts at line-start (no leading whitespace).
tops = []
for m in re.finditer(r"^(?:async )?def \w+\([^\n]*:\n", src, re.M):
    line_no = src.count("\n", 0, m.start()) + 1
    tops.append((line_no, m.group(0).strip()))

for ln, sig in tops:
    print(f"{ln:4d} {sig}")

# Sanity: the file should end with create_schema(); there must be exactly one
# `def create_schema(` and no duplicated `def _migrate(`.
mis = [sig for _, sig in tops if sig.startswith("def create_schema(")]
dbl = [sig for _, sig in tops if sig.startswith("def _migrate(")]
print("create_schema defs:", len(mis))
print("_migrate defs:", len(dbl))
