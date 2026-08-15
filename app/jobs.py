# =============================================================================
# CTI Platform - in-process async job registry
# -----------------------------------------------------------------------------
# Turns slow, on-demand work (e.g. "Generate Alert Sheet" LLM inference) into
# an async job: the endpoint enqueues and returns a job id immediately, the
# frontend polls GET /jobs/{id} until it reaches a terminal state.
#
# Deliberately in-process and volatile:
#   * survives the single HTTP request (the whole problem the sync endpoint had)
#   * lost on restart — acceptable, because on-demand generation is a UX nicety.
#     The durable, crash-safe pipeline lives in `alert_sheet_pending` + the AI worker,
#     and that path is untouched. Long-lived jobs also fail fast here since a
#     stuck model fails over within `ai_engine_timeout_seconds`.
# =============================================================================

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

#: Transient jobs older than this are purged lazily on every access.
_JOB_TTL_SECONDS = 1800.0

_jobs: dict[str, dict[str, Any]] = {}
_lock = asyncio.Lock()


async def start_job(worker: Callable[[], Awaitable[Any]]) -> str:
    """Register + launch `worker` as a background task, return its job id."""
    job_id = uuid.uuid4().hex
    now = time.time()
    job: dict[str, Any] = {
        "id": job_id,
        "status": "queued",
        "created_at": now,
        "updated_at": now,
        "result": None,
        "error": None,
    }
    async with _lock:
        _purge_locked()
        _jobs[job_id] = job
    asyncio.create_task(_run(job_id, worker))
    return job_id


async def get_job(job_id: str) -> dict[str, Any] | None:
    """Return a copy of the job, or None when it is unknown / purged."""
    async with _lock:
        _purge_locked()
        job = _jobs.get(job_id)
        return dict(job) if job else None


async def _run(job_id: str, worker: Callable[[], Awaitable[Any]]) -> None:
    job = _jobs.get(job_id)
    if job is None:
        return
    job["status"] = "processing"
    job["updated_at"] = time.time()
    try:
        job["result"] = await worker()
        job["status"] = "done"
    except Exception as exc:  # noqa: BLE001 - surface any worker failure to the UI
        job["status"] = "failed"
        job["error"] = str(exc)
        logger.warning("job %s failed: %s", job_id, exc)
    finally:
        job["updated_at"] = time.time()


def _purge_locked() -> None:
    """Drop finished / abandoned jobs past their TTL (caller must hold `_lock`)."""
    cutoff = time.time() - _JOB_TTL_SECONDS
    stale = [jid for jid, j in _jobs.items() if j["updated_at"] < cutoff]
    for jid in stale:
        _jobs.pop(jid, None)
    if stale:
        logger.debug("purged %d stale job(s)", len(stale))
