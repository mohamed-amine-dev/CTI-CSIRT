import ast
src = open("/app/app/main.py").read()
tree = ast.parse(src)
wanted = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and "WEB" in t.id.upper():
                wanted.add(t.id)
for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id in wanted:
                print("WEB_ASSIGN", t.id, "=", ast.unparse(node.value), "line", node.lineno)
for node in ast.walk(tree):
    if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "StaticFiles":
        print("STATICFILES line", node.lineno, ast.unparse(node))
print("== served-dir candidates ==")
for node in ast.walk(tree):
    s = ast.unparse(node) if isinstance(node, ast.Assign) else ""
    if "FileResponse" in s or "index.html" in s or "Web" in s:
        print("line", getattr(node, "lineno", "?"), s[:110])
