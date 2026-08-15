# =============================================================================
# CTI Platform - /api/v1/explore routes (read-only Data Explorer)
# -----------------------------------------------------------------------------
# Powers the "Data Explorer" page of the React frontend: browse every table,
# inspect its schema, page through rows and run ad-hoc SELECT queries.
#
# SECURITY MODEL: every query here runs through the dedicated `cti_ro`
# ClickHouse account (clickhouse/users.d/ro.xml, mounted by docker-compose) that
# has readonly=1. Even the free-text query box cannot INSERT / ALTER / DROP —
# the server itself rejects those. The query validation below is therefore a
# UX layer (friendly 400s) on top of a hard server-side guarantee.
# =============================================================================

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/explore", tags=["explore"])

# Tables the explorer knows about, with the column used to sort newest-first.
# `ORDER BY` references are always taken from this dict, never from user input.
_SORT_COLUMN = {
    "raw_threat_intel": "ts",
    "processed_iocs": "ts",
    "vulnerability_alerts": "ts",
    "ingest_state": "last_ts",
    "alert_sheet_pending": "updated_at",
    "notifications": "created_at",
}

# Whole-word write keywords rejected by the query box (server-side readonly=1 is
# the real protection; this is just for a clean error message).
_FORBIDDEN = (
    r"\b(insert|update|delete|alter|drop|create|truncate|rename|attach|detach"
    r"|grant|revoke|kill|optimize|set|use|system)\b"
)
_FORBIDDEN_RE = re.compile(_FORBIDDEN, re.IGNORECASE)
_LIMIT_RE = re.compile(r"\blimit\b", re.IGNORECASE)

_VALID_TABLES = tuple(_SORT_COLUMN)


def _ro_db(request: Request) -> Any:
    """The shared read-only client, or a clear 503 if cti_ro isn't configured."""
    db = getattr(request.app.state, "ro_db", None)
    if db is None:
        raise HTTPException(
            status_code=503,
            detail="Read-only explorer user not configured — check clickhouse/users.d/ro.xml is mounted",
        )
    return db


def _ensure_table(table: str) -> None:
    if table not in _VALID_TABLES:
        raise HTTPException(status_code=404, detail=f"unknown table: {table}")


def _json_rows(result_rows: list[list[Any]]) -> list[list[Any]]:
    """JSON-safe row serialisation (datetimes -> ISO strings)."""
    return [
        [r.isoformat() if hasattr(r, "isoformat") else r for r in row]
        for row in result_rows
    ]


@router.get("/tables")
async def list_tables(request: Request) -> dict[str, Any]:
    """Every table in the platform database with engine + live row count."""
    db = _ro_db(request)
    rows = await db.query(
        """
        SELECT t.name, t.engine, ifNull(sum(p.rows), 0) AS total_rows
        FROM system.tables t
        LEFT JOIN system.parts p
               ON p.database = t.database AND p.table = t.name AND p.active
        WHERE t.database = {db:String}
        GROUP BY t.name, t.engine
        ORDER BY total_rows DESC, t.name
        """,
        parameters={"db": request.app.state.settings.clickhouse_database},
    )
    return {
        "tables": [{"name": r[0], "engine": r[1], "rows": r[2]} for r in rows.result_rows]
    }


@router.get("/{table}/columns")
async def table_columns(request: Request, table: str) -> dict[str, Any]:
    """Column names + types for one table (in declaration order)."""
    _ensure_table(table)
    db = _ro_db(request)
    rows = await db.query(
        """
        SELECT name, type
        FROM system.columns
        WHERE database = {db:String} AND table = {tbl:String}
        ORDER BY position
        """,
        parameters={
            "db": request.app.state.settings.clickhouse_database,
            "tbl": table,
        },
    )
    return {
        "table": table,
        "columns": [{"name": r[0], "type": r[1]} for r in rows.result_rows],
    }


@router.get("/{table}/rows")
async def table_rows(
    request: Request,
    table: str,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Newest-first page of rows for one table (FINAL collapses merged rows)."""
    _ensure_table(table)
    db = _ro_db(request)
    sort = _SORT_COLUMN[table]
    rows = await db.query(
        f"""
        SELECT *
        FROM {{db:Identifier}}.{table} FINAL
        ORDER BY {sort} DESC
        LIMIT {{lim:UInt32}} OFFSET {{off:UInt32}}
        """,
        parameters={
            "db": request.app.state.settings.clickhouse_database,
            "lim": limit,
            "off": offset,
        },
    )
    return {
        "table": table,
        "columns": rows.column_names,
        "rows": _json_rows(rows.result_rows),
    }


class QueryRequest(BaseModel):
    sql: str = Field(description="A single read-only SELECT statement")


@router.post("/query")
async def run_query(request: Request, body: QueryRequest) -> dict[str, Any]:
    """Run an ad-hoc SELECT against the platform database (read-only)."""
    sql = body.sql.strip().rstrip(";").strip()
    if not sql:
        raise HTTPException(status_code=400, detail="empty query")
    first = sql.lower().split(None, 1)[0] if sql else ""
    if first not in {"select", "with"}:  # `with` => SELECT ... CTE queries
        raise HTTPException(status_code=400, detail="only SELECT statements are allowed")
    if ";" in sql:
        raise HTTPException(status_code=400, detail="multiple statements are not allowed")
    if _FORBIDDEN_RE.search(sql):
        raise HTTPException(status_code=400, detail="query looks like a write statement (INSERT/ALTER/DROP/...)")

    if not _LIMIT_RE.search(sql):
        sql = f"{sql} LIMIT 500"

    db = _ro_db(request)
    try:
        rows = await db.query(sql)
    except Exception as e:  # server-side rejection (readonly, syntax, row cap...)
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "columns": rows.column_names,
        "rows": _json_rows(rows.result_rows),
    }
