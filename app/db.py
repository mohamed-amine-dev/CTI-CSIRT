# =============================================================================
# CTI Platform - database access layer (ClickHouse)
# -----------------------------------------------------------------------------
# Single place that owns the ClickHouse connection. Both the async client
# (used by the FastAPI app + ingestion engine) and the sync client (used by
# the one-shot db_init.py bootstrap) live here, so swapping or tuning the
# transport never touches collectors, routers or the AI processor.
#
# The async client comes from clickhouse-connect's `get_async_client`
# (verified present in v0.7+). It performs HTTP/2-less REST calls under the
# hood, so it integrates cleanly with asyncio without blocking the loop.
# =============================================================================

from __future__ import annotations

import logging
from typing import Any, Sequence

import clickhouse_connect

from .config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Client factories
# ---------------------------------------------------------------------------
def _connect_args() -> dict[str, Any]:
    """Shared connection kwargs for both sync and async clients (no DB yet)."""
    return {
        "host": settings.clickhouse_host,
        "port": settings.clickhouse_port,
        "username": settings.clickhouse_user,
        "password": settings.clickhouse_password,
        "secure": settings.clickhouse_secure,
    }


def get_sync_client() -> clickhouse_connect.driver.Client:
    """Synchronous client bound to the target database — bootstrap script."""
    return clickhouse_connect.get_client(database=settings.clickhouse_database, **_connect_args())


def get_admin_sync_client() -> clickhouse_connect.driver.Client:
    """Bootstrap client with NO default database (so the DB itself can be
    created first). Only used before the schema exists."""
    return clickhouse_connect.get_client(**_connect_args())


async def get_async_client() -> clickhouse_connect.driver.asyncclient.AsyncClient:
    """Async client — used by the FastAPI app and the ingestion engine.

    `get_async_client` is itself a coroutine (confirmed against the installed
    wheel), so it must be awaited. Each awaitable method (`query`, `command`,
    `insert`, `ping`) runs the HTTP round-trip without blocking the loop.
    """
    return await clickhouse_connect.get_async_client(database=settings.clickhouse_database, **_connect_args())


async def get_admin_async_client() -> clickhouse_connect.driver.asyncclient.AsyncClient:
    """Bootstrap async client with no default database (DB creation)."""
    return await clickhouse_connect.get_async_client(**_connect_args())


# ---------------------------------------------------------------------------
# Small helpers used by the ingestion engine and the AI processor
# ---------------------------------------------------------------------------
async def ensure_database(client: clickhouse_connect.driver.asyncclient.AsyncClient) -> None:
    """Create the target database if it does not exist yet."""
    await client.command(f"CREATE DATABASE IF NOT EXISTS {settings.clickhouse_database}")


async def table_exists(client: clickhouse_connect.driver.asyncclient.AsyncClient, table: str) -> bool:
    """Cheap existence check via system.tables (no try/except churn)."""
    rows = await client.query(
        "SELECT count() FROM system.tables WHERE database = {db:String} AND name = {tbl:String}",
        parameters={"db": settings.clickhouse_database, "tbl": table},
    )
    return rows.result_rows[0][0] > 0


async def insert_rows(
    client: clickhouse_connect.driver.asyncclient.AsyncClient,
    table: str,
    data: Sequence[Sequence[Any]],
    column_names: Sequence[str],
) -> None:
    """Insert many rows into a table in a single batched request.

    clickhouse-connect's `insert` accepts a list of rows aligned with
    `column_names` and sends them as one Native/Binary packet — far cheaper
    than one INSERT per row when a collector poll yields thousands of records.
    """
    if not data:
        return
    await client.insert(table=table, data=list(data), column_names=list(column_names))
