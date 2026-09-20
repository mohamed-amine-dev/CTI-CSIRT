import sys

P = "app/db_init.py"
src = open(P, "r", encoding="utf-8").read()

inside = False
opener_line = -1
opener_col = -1
line = 0
col = 0
i = 0
n = len(src)

def newline_at(j):
    return src[j:j+2] == "\r\n" or src[j] in "\r\n"

while i < n:
    c = src[i]
    if c in "\r\n":
        if i + 1 < n and src[i:i+2] == "\r\n":
            i += 2
        else:
            i += 1
        line += 1
        col = 0
        continue
    if src.startswith('"""', i) or src.startswith("'''", i):
        if not inside:
            inside = True
            opener_line = line + 1
            opener_col = col
        else:
            inside = False
        i += 3
        col += 3
        continue
    i += 1
    col += 1

print("inside_string_at_EOF =", inside)
if inside:
    print("TRUE_FIRST_OPENED = line %d, col %d" % (opener_line, opener_col))
    lines = src.split("\r\n" if "\r\n" in src else "\n")
    lo = max(0, opener_col - 14)
    print("opener byte lensight (col -14 .. +45):")
    print(repr(lines[opener_line - 1][max(0, opener_col - 14): opener_col + 45]))
    print("neighbor lines:")
    for k in range(max(0, opener_line - 4), min(len(lines), opener_line + 4)):
        print("%4d %s" % (k + 1, repr(lines[k])))
else:
    print("NO unclosed triple-quote in file by this scan.")
