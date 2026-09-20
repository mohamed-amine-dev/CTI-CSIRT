# =============================================================================
# Phase 4 - Authentication & authorization (RBAC + TLP clearance)
# -----------------------------------------------------------------------------
# Additive core, no refactor of existing modules:
#   * argon2id password hashing (argon2-cffi)
#   * optional TOTP 2FA (pyotp, free/official)
#   * HMAC-SHA256 signed bearer tokens (12h TTL, stateless)
#   * TLP clearance model enforced server-side on every content endpoint
#
# Authorization is TWO independent dimensions (supervisor agnostic of it):
#   (a) workspace tags (TI / CERT / DFIR) -> control the default nav/dashboard
#   (b) per-user TLP clearance  CLEAR < GREEN < AMBER < AMBER+STRICT < RED
#       a user may only ever read items whose TLP <= their clearance; a RED
#       item over a low clearance is a hard 403 from the API.
#
# Requester policy resolution order:
#   1. Bearer == API_ACCESS_TOKEN (the ops token already protecting state
#      changes) -> privileged admin persona (tier RED).
#   2. Bearer == user token (issued by /auth/login) -> that user's tier/admin.
#   3. No / invalid token -> anonymous, tier CLEAR, no privileges.
# =============================================================================

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Any

import argon2
import pyotp
from fastapi import Depends, HTTPException, Request

logger = logging.getLogger(__name__)

_password_hasher = argon2.PasswordHasher()

#: Canonical TLP values, lowest → highest. '' or NULL rows are treated as CLEAR.
TLP_ORDER = ["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]
TLP_TIER = {v: i for i, v in enumerate(TLP_ORDER)}

WORKSPACES = ("TI", "CERT", "DFIR")

#: Tables carrying a nullable `tlp` column (Phase 4, added via _migrate).
TLP_TABLES = (
    "threat_actors",
    "malware_tools",
    "attack_patterns",
    "processed_iocs",
    "raw_threat_intel",
    "vulnerability_alerts",
    "agent_triage_results",
)


# ---------------------------------------------------------------------------
# Passwords (argon2id)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Hash a plaintext password with argon2id (memory/hash params in lib)."""
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Constant-time-ish argon2 verify; never raises on garbage input."""
    try:
        return _password_hasher.verify(password_hash, password)
    except Exception:  # noqa: BLE001 - any argon2 failure == not verified
        return False


# ---------------------------------------------------------------------------
# TOTP 2FA (pyotp)
# ---------------------------------------------------------------------------
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str, issuer: str = "Argus CTI") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Bearer tokens (HMAC-SHA256, stateless, expiring)
# ---------------------------------------------------------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def issue_token(
    secret: str,
    username: str,
    *,
    ttl_hours: float,
    tier: int,
    is_admin: bool,
) -> str:
    """Sign a user token embedding username, clearance tier and admin flag.

    The tier is signed in so endpoint enforcement needs no DB lookup per
    request; a clearance change applies on next login. Tokens expire after
    `ttl_hours` and are stateless (no server-side session store).
    """
    issued = int(time.time())
    payload = {
        "u": username,
        "t": tier,
        "a": 1 if is_admin else 0,
        "i": issued,
        "e": issued + int(ttl_hours * 3600),
        "n": secrets.token_hex(6),
    }
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64url(sig)}"


def decode_token(secret: str, token: str) -> dict[str, Any] | None:
    """Validate the HMAC signature and expiry; return the payload or None."""
    try:
        body, sep, sig = token.partition(".")
        if not sep:
            return None
        expected = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(sig)):
            return None
        payload = json.loads(_b64url_decode(body))
        if not isinstance(payload, dict) or int(payload.get("e", 0)) < int(time.time()):
            return None
        return payload
    except Exception:  # noqa: BLE001 - malformed token == invalid
        return None


# ---------------------------------------------------------------------------
# TLP model
# ---------------------------------------------------------------------------
def tlp_tier(value: str | None) -> int:
    """Numeric tier for a stored `tlp` ('' / None / unknown → CLEAR = 0)."""
    v = (value or "").strip().upper()
    return TLP_TIER.get(v, 0)


def allowed_tlp_values(tier: int) -> list[str]:
    """TLP strings a requester with clearance `tier` may read."""
    return [v for v, t in TLP_TIER.items() if t <= tier]


def tlp_predicate(tier: int) -> str:
    """SQL fragment selecting the TLP strings the requester may see.

    Content tables use `''` (or NULL) to mean CLEAR, so `empty(tlp)` is always
    allowed. RED-marked rows only pass for reqesters whose tier >= RED — this
    is the server-side half of the clearance check (the non-trivial one).
    """
    allowed = allowed_tlp_values(tier)
    if len(allowed) == len(TLP_ORDER):
        return "1"  # full clearance ≡ no predicate needed
    quoted = ", ".join("'" + v.replace("'", "\\'") + "'" for v in allowed)
    return f"(empty(tlp) OR tlp IN ({quoted}))"


# ---------------------------------------------------------------------------
# Requester policy (per-request authorization state)
# ---------------------------------------------------------------------------
def requester_policy(request: Request) -> dict[str, Any]:
    """Resolution order documented in the module docstring."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        settings = request.app.state.settings
        if token and token == settings.api_access_token:
            return {
                "privileged": True,
                "is_admin": True,
                "tier": TLP_TIER["RED"],
                "username": "",
                "source": "ops-token",
            }
        secret = settings.auth_token_secret or settings.api_access_token
        payload = decode_token(secret, token)
        if payload:
            return {
                "privileged": bool(payload.get("a")),
                "is_admin": bool(payload.get("a")),
                "tier": int(payload.get("t", 0)),
                "username": str(payload.get("u", "")),
                "source": "user",
            }
    cached = getattr(request.state, "user_policy", None)
    if cached is not None:
        return cached
    return {
        "privileged": False,
        "is_admin": False,
        "tier": 0,  # anonymous ≈ CLEAR
        "username": "",
        "source": "anonymous",
    }


def assert_tlp_allowed(item_tlp: str | None, tier: int) -> None:
    """Raise a real 403 when a row's TLP exceeds the requester's clearance."""
    if tlp_tier(item_tlp) > tier:
        raise HTTPException(
            status_code=403,
            detail="This item is classified above your TLP clearance",
        )


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------
def optional_user(request: Request) -> dict[str, Any]:
    """Resolve requester policy once and cache it for the request lifetime."""
    policy = requester_policy(request)
    request.state.user_policy = policy
    return policy


def require_user(
    request: Request,
    policy: dict[str, Any] = Depends(optional_user),
) -> dict[str, Any]:
    if not policy.get("username") and not policy.get("privileged"):
        raise HTTPException(status_code=401, detail="Authentication required")
    return policy


def require_admin(
    request: Request,
    policy: dict[str, Any] = Depends(optional_user),
) -> dict[str, Any]:
    if not policy.get("is_admin"):
        raise HTTPException(status_code=403, detail="Administrator access required")
    return policy


# ---------------------------------------------------------------------------
# Append-only audit log
# ---------------------------------------------------------------------------
async def audit(
    request: Request,
    event: str,
    resource: str,
    detail: str = "",
) -> None:
    """Write one append-only audit row (event, who, what, when).

    Best-effort by design: a failed audit write must never break an action.
    `username` comes from the resolved requester policy.
    """
    try:
        from .db import insert_rows
        policy = requester_policy(request)
        username = policy.get("username") or ("ops-token" if policy.get("privileged") else "anonymous")
        version = int(time.time() * 1_000_000)
        await insert_rows(
            request.app.state.db,
            "audit_log",
            [[event, username, str(resource)[:500], detail[:2000], version]],
            ["event", "username", "resource", "detail", "version"],
        )
    except Exception as exc:  # noqa: BLE001 - audit must not break the action
        logger.warning("audit write failed for event=%s: %s", event, exc)