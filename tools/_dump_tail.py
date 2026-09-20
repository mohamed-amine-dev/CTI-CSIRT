import ast
p = "app/db_init.py"
s = open(p, encoding="utf-8").read()
lines = s.split("\n")
start = 408
end = min(len(lines), 498)
for i in range(start, end):
    print(i + 1, repr(lines[i]))
