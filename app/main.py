# =============================================================================
# CTI Platform - FastAPI application entry point
# -----------------------------------------------------------------------------
# Wiring everything together:
#   * lifespan()       -> opens the ClickHouse async client, ensures the schema,
#                         builds and starts the ingestion pipeline
#   * CORS             -> allows the future React (Vite) dev server
#   * static mount     -> serves a compiled React build when `web/` exists
#   * routers          -> /api/v1/alerts, /api/v1/iocs, /api/v1/ingest
#
# Run:   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
# =============================================================================

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .db import get_admin_async_client, get_async_client, get_readonly_async_client
from .db_init import DDL
from .ingestion_engine import ThreatIntelPipeline
from .routers import agent, ai, alerts, enrich, explore, export, feeds, geo, iocs, ingest, notifications, search, threats

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Directory that will hold the compiled React app. `npm run build` inside
# frontend/ emits the SPA here, and the app mounts it as static content when
# present (same-origin deployment, no CDN/proxy needed in prod).
WEB_DIR = Path(__file__).resolve().parent.parent / "web" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Open shared resources on startup and tear them down cleanly on exit."""
    # -- 1. ClickHouse async client ------------------------------------------
    # Bootstrap with a no-default-DB client so the database itself can be
    # created on first run, then open the real bound client.
    admin = await get_admin_async_client()
    try:
        await admin.command(f"CREATE DATABASE IF NOT EXISTS {settings.clickhouse_database}")
    finally:
        await admin.close()
    db = await get_async_client()
    # -- 2. Ensure the schema exists (idempotent) ------------------------------
    for ddl in DDL.values():
        await db.command(ddl)
    logger.info("clickhouse schema ready (%s)", settings.clickhouse_database)

    # -- 3. Read-only explorer client (SELECT-only cti_ro user) ----------------
    # Optional: if cti_ro isn't configured (bare-metal run without the
    # users.d/ro.xml mount) we degrade gracefully — the app still starts and the
    # explore router returns 503 instead of failing the whole lifecycle.
    ro_db = None
    try:
        ro_db = await get_readonly_async_client()
        await ro_db.command("SELECT 1")
    except Exception as exc:  # pragma: no cover - depends on deployment
        logger.warning("read-only explorer user unavailable: %s", exc)

    # -- 4. Build + start the ingestion pipeline --------------------------------
    pipeline = await ThreatIntelPipeline(db, settings).build()
    await pipeline.start()

    app.state.db = db
    app.state.ro_db = ro_db
    app.state.pipeline = pipeline
    app.state.settings = settings

    logger.info("CTI platform started (llm=%s, collectors=%d)",
                settings.active_provider, len(pipeline.collectors))
    try:
        yield
    finally:
        await pipeline.shutdown()
        if ro_db is not None:
            await ro_db.close()
        await db.close()
        logger.info("CTI platform stopped")


app = FastAPI(
    title="Argus CTI — Cyber Threat Intelligence Platform",
    description=(
        "Async CTI ingestion + ClickHouse OLAP + free-tier AI extraction "
        "(Alert Sheets). See adr/ for architectural decisions."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# --- CORS: allow the React/Vite dev server to call the API --------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Routers (JSON contract for the React frontend) ----------------------------
app.include_router(alerts.router)
app.include_router(iocs.router)
app.include_router(feeds.router)
app.include_router(enrich.router)
app.include_router(ai.router)
app.include_router(notifications.router)
app.include_router(search.router)
app.include_router(export.router)
app.include_router(ingest.router)
app.include_router(explore.router)
app.include_router(threats.router)
app.include_router(geo.router)
app.include_router(agent.router)


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    """Simple liveness endpoint used by orchestration / docker-compose."""
    return {"status": "ok", "llm_provider": settings.active_provider}


# --- Serve the compiled React frontend when present -----------------------------
# Future-proofing: once `npm run build` has produced web/dist, the SPA is served
# from the same origin as the API (no separate CDN / proxy needed in prod).
if WEB_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=WEB_DIR / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        """Serve index.html for client-side routes (React Router)."""
        file = WEB_DIR / full_path
        if full_path and file.is_file():
            return FileResponse(file)
        return FileResponse(WEB_DIR / "index.html")
