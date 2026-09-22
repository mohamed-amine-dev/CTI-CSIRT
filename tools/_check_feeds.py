"""Compile-check the feed router after the channel/total change."""
import pathlib

f = pathlib.Path("app/routers/feeds.py")
try:
    compile(f.read_text(encoding="utf-8"), str(f), "exec")
    print(f"OK {f}")
except SyntaxError as e:
    print(f"BAD {f}:{e.lineno} {e.msg}")
    raise