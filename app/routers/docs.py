# =============================================================================
# CTI Platform - /api/v1/docs routes (Architecture Decision Records viewer)
# -----------------------------------------------------------------------------
# Serves the ADR markdown files from the `adr/` directory so the dashboard can
# render the architectural decisions that shaped the platform (see report §5.13).
#
#   GET /api/v1/docs/adr        -> list of records (number + title)
#   GET /api/v1/docs/adr/{num}  -> one record's raw markdown + title
# =============================================================================

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/v1/docs", tags=["docs"])

# `adr/` sits at the repository root: <repo>/app/routers/docs.py -> parents[2].
# Works both locally and inside the Docker image (where the build context root
# is /build and the Dockerfile does `COPY adr ./adr`).
_ADR_DIR = Path(__file__).resolve().parents[2] / "adr"


def _adr_files() -> list[Path]:
    if not _ADR_DIR.is_dir():
        return []
    return sorted(_ADR_DIR.glob("*.md"))


def _adr_title(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem


@router.get("/adr")
async def list_adrs() -> dict[str, Any]:
    """List all Architecture Decision Records (number + title)."""
    items: list[dict[str, str]] = []
    for p in _adr_files():
        name = p.stem  # e.g. "0001-use-clickhouse-and-fastapi-for-cti"
        num = name.split("-", 1)[0]
        items.append({"file": p.name, "num": num, "title": _adr_title(p)})
    return {"items": items, "count": len(items)}


@router.get("/adr/{num}")
async def get_adr(num: str) -> dict[str, Any]:
    """Return one ADR's raw markdown and title."""
    if not num.isdigit():
        raise HTTPException(status_code=422, detail="ADR number must be numeric")
    for p in _adr_files():
        if p.stem.split("-", 1)[0] == num:
            return {
                "file": p.name,
                "num": num,
                "title": _adr_title(p),
                "content": p.read_text(encoding="utf-8"),
            }
    raise HTTPException(status_code=404, detail=f"No ADR numbered {num}")
