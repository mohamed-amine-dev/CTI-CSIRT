# =============================================================================
# CTI Platform - single image (React SPA + FastAPI backend)
# -----------------------------------------------------------------------------
# Multi-stage build:
#   Stage 1 (frontend) : npm ci + vite build  ->  ../web/dist (served by FastAPI)
#   Stage 2 (runtime)  : python:3.13-slim + deps + app code + built SPA
#
# The image is self-contained: one container serves both the API and the
# dashboard on :8000 (same origin, no CDN/proxy needed).
# Run with docker compose (see docker-compose.yml) so ClickHouse + Ollama
# start alongside it.
# =============================================================================

# ---------- Stage 1: build the React dashboard -------------------------------
FROM node:20-slim AS frontend
# Build from a *subdirectory* (/build/frontend) so vite's relative outDir
# `../web/dist` resolves to /build/web/dist — the path the runtime stage copies.
# Building with the source at the workdir root would send the bundle to /web/dist
# (outside /build) and break `COPY --from=frontend`.
WORKDIR /build/frontend
# Bearer token baked into the SPA so state-changing buttons (Force Sync, Retry,
# Mark-read) authenticate against the backend. Matches the backend token via
# ${API_ACCESS_TOKEN:-change-me-in-production} in docker-compose.yml. If you
# set a real token in .env, compose passes it here automatically.
ARG VITE_API_TOKEN=change-me-in-production
ENV VITE_API_TOKEN=$VITE_API_TOKEN
# RIVERT. Stage 1 bakes the COMPLETE platform from `frontend_legacy/` (all
# ten nav sections: Executive Overview, Threat Landscape, Threat Actors & APTs,
# Live Threat Feeds, Dark Web & Telegram, Alert Sheets, IoC Search & Shodan,
# Autonomous Triage, Search & Export, Data Explorer). The `web/` tree is the
# isolated Phase-1 feature SPA (Dark Web + Telegram monitoring only) — it is
# NOT a superset of the platform McKINERD and must never replace this bake.
# Phase-1 feature code will be merged INTO frontend_legacy's router as a nav
# section (Step 3), not swapped in as the whole tree (Step 1 revert).
COPY frontend_legacy/package.json frontend_legacy/package-lock.json ./
RUN npm ci
# Then the sources; output lands in /build/web/dist (vite base is "./",
# legacy outDir is ../web/dist).
COPY frontend_legacy/ .
RUN npm run build

# ---------- Stage 2: Python backend + bundled SPA ----------------------------
FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

# System deps: none required for the pure-Python stack (all wheels).
# pip is prevented from pulling a full index copy; installs are layered so a
# half-downloaded stream does not leave a broken build.
# `--retries` + `--timeout` absorb transient PyPI drops; `PIP_EXTRA_INDEX_URL`
# (compose arg) lets you point at a local mirror (e.g. internal devpi) when the
# public index is flaky — see docker-compose build.extra_pip_index.
COPY requirements.txt .
ARG EXTRA_PIP_INDEX=
ENV PIP_EXTRA_INDEX_URL=$EXTRA_PIP_INDEX
RUN pip install --retries 10 --timeout 120 -r requirements.txt

COPY app ./app
# Operational tooling (create_user.py, live_verify.py, …) is deliberately part
# of the *image*, not a host-side import: account provisioning has no public
# signup, so create_user.py is THE supported way to create/audit users and must
# always be present inside the running container — no per-session `docker cp`.
COPY tools ./tools
COPY --from=frontend /build/web/dist ./web/dist

EXPOSE 8000

# Liveness probe: FastAPI /health (plain urllib; slim image has no curl/wget).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
