# =============================================================================
# Argus CTI - build the YARA rule bundle (Docker image build step)
# -----------------------------------------------------------------------------
# Downloads the pinned Neo23x0/signature-base tree and pre-compiles the .yar
# files with `yarac` into ONE `.yarc` bundle. Rules that fail to compile (usually
# because they pull modules missing from the slim image, e.g. `cuckoo`) are
# SKIPPED individually and named in a sidecar .txt manifest — the scanner never
# fabricates coverage for them. Run inside the image build where yara is apt.
# =============================================================================

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile signature-base -> one YARA bundle")
    parser.add_argument("--source", required=True, help="dir holding *.yar files")
    parser.add_argument("--out", required=True, help="output bundle path (e.g. /opt/yara/bundle.yarc)")
    parser.add_argument("--binary", default="/usr/bin/yarac", help="yarac binary")
    args = parser.parse_args()

    src = Path(args.source)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    rules = sorted(p for p in src.iterdir() if p.suffix.lower() in (".yar", ".yara"))
    if not rules:
        print(f"FATAL: no YARA rules found under {src}")
        return 1

    good: list[Path] = []
    skipped: list[str] = []
    for rule in rules:
        probe = out.parent / ("probe_" + rule.name)
        try:
            r = subprocess.run([args.binary, str(rule), str(probe)],
                               capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            skipped.append(f"{rule.name} (timeout)")
            continue
        probe.unlink(missing_ok=True)
        if r.returncode == 0:
            good.append(rule)
        else:
            skipped.append(rule.name)

    print(f"compiling {len(good)} good rules -> {out}")
    r = subprocess.run([args.binary, *[str(g) for g in good], str(out)],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        print("bundle compile failed:")
        print(r.stderr[-2000:] if r.stderr else "no stderr")
        return 1

    manifest = out.with_suffix(out.suffix + ".txt")
    manifest.write_text(
        f"Neo23x0/signature-base (pinned) - {len(good)} rules compiled; "
        f"{len(skipped)} skipped: {', '.join(skipped)}",
        encoding="utf-8",
    )
    print(f"OK: {len(good)} rules bundled; {len(skipped)} skipped")
    if skipped:
        print("skipped:", ", ".join(skipped))
    return 0


if __name__ == "__main__":
    sys.exit(main())