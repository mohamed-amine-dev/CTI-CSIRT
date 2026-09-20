# =============================================================================
# Cooperative Ollama arbitration between the interactive Assistant and the
# CVE alert-sheet background generator.
# -----------------------------------------------------------------------------
# Both features share a single local Ollama model, and Ollama serialises
# requests per model. When a user asks the ATT&CK Assistant something we raise
# a process-wide flag; the background sheet job then waits for that flag to
# clear before it starts its own generation, so the interactive answer gets the
# model first. When nobody is chatting, the pipeline runs exactly as before.
# No downloads, no configuration, and a failed flag reset simply unblocks the
# background job (best-effort only).
# =============================================================================

from __future__ import annotations

import asyncio
import time

# After the last chat request completes, the background sheet job keeps waiting
# for this long, so a user firing off consecutive questions never fights the
# pipeline for the shared model. The pipeline simply works through the backlog
# during quiet periods — alerts are best-effort, the chat is interactive.
RELEASE_BUFFER = 120.0  # seconds of quiet before sheets resume

_active = False
_last_end = 0.0
_event: asyncio.Event | None = None


def _evt() -> asyncio.Event:
    global _event
    if _event is None:
        _event = asyncio.Event()
    return _event


async def begin() -> None:
    """Mark the assistant as actively generating (idempotent)."""
    global _active
    _active = True
    _evt().set()


def end() -> None:
    """Release the shared model so background generation can proceed."""
    global _active, _last_end
    _active = False
    _last_end = time.monotonic()
    _evt().clear()


def is_active() -> bool:
    """True while a chat request is waiting on the model."""
    return _active


async def yield_to_assistant(max_wait: float) -> None:
    """Background jobs call this before touching the shared model.

    Waits while a chat request is in flight and for a short quiet window after
    the most recent one, so interactive answers win the model. Returns when the
    quiet period has elapsed or the budget is spent (the pipeline can never be
    blocked forever — it only defers to chats).
    """
    if not _active and time.monotonic() >= _last_end + RELEASE_BUFFER:
        return
    waited = 0.0
    while waited < max_wait:
        if not _active and time.monotonic() >= _last_end + RELEASE_BUFFER:
            return
        await asyncio.sleep(0.5)
        waited += 0.5