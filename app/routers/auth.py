# =============================================================================
# Phase 4 - /api/v1/auth routes (login, me, optional TOTP 2FA)
# -----------------------------------------------------------------------------
# Stateless bearer-token auth on top of the existing stack — nothing existing
# is touched. Password hashing = argon2id; 2FA = TOTP (free, pyotp).
# =============================================================================

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth import (
    TLP_ORDER,
    TLP_TIER,
    WORKSPACES,
    audit,
    generate_totp_secret,
    hash_password,
    issue_token,
    require_admin,
    require_user,
    totp_uri,
    verify_password,
    verify_totp,
)
from app.db import insert_rows

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

_USER_COLUMNS = [
    "username",
    "password_hash",
    "totp_secret",
    "totp_enabled",
    "workspace_tags",
    "tlp_clearance",
    "is_admin",
    "is_disabled",
    "version",
]


async def _get_user(request: Request, username: str) -> dict[str, Any] | None:
    """Fetch one user row (collapsed) from ClickHouse."""
    db = request.app.state.db
    rows = await db.query(
        f"""
        SELECT password_hash, totp_secret, totp_enabled, workspace_tags,
               tlp_clearance, is_admin, is_disabled
        FROM {request.app.state.settings.clickhouse_database}.users FINAL
        WHERE username = {{u:String}}
        """,
        parameters={"u": username},
    )
    if not rows.result_rows:
        return None
    r = rows.result_rows[0]
    return {
        "username": username,
        "password_hash": r[0],
        "totp_secret": r[1],
        "totp_enabled": bool(r[2]),
        "workspace_tags": r[3] or [],
        "tlp_clearance": r[4] or "CLEAR",
        "is_admin": bool(r[5]),
        "is_disabled": bool(r[6]),
    }


async def _upsert_user(request: Request, user: dict[str, Any]) -> None:
    import time
    version = int(time.time() * 1_000_000)
    await insert_rows(
        request.app.state.db,
        "users",
        [[
            user["username"],
            user["password_hash"],
            user.get("totp_secret", ""),
            1 if user.get("totp_enabled") else 0,
            user.get("workspace_tags", []),
            user.get("tlp_clearance", "CLEAR").upper(),
            1 if user.get("is_admin") else 0,
            1 if user.get("is_disabled") else 0,
            version,
        ]],
        _USER_COLUMNS,
    )


def _public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": user.get("username", ""),
        "workspace_tags": user.get("workspace_tags", []),
        "tlp_clearance": (user.get("tlp_clearance") or "CLEAR").upper(),
        "is_admin": bool(user.get("is_admin")),
        "totp_enabled": bool(user.get("totp_enabled")),
    }


class LoginBody(BaseModel):
    username: str
    password: str
    totp_code: str = ""


@router.post("/login")
async def login(request: Request, body: LoginBody) -> dict[str, Any]:
    """Authenticate a user (argon2id) + optional TOTP; return a bearer token.

    2FA flow: when the user has TOTP enabled and no `totp_code` is supplied the
    API answers `{"requires_2fa": true}`; the client re-submits with the code.
    """
    username = body.username.strip()
    user = await _get_user(request, username)
    if user is None or user.get("is_disabled") or not verify_password(user["password_hash"], body.password):
        await audit(request, "auth.login_failed", f"user:{username}")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if user["totp_enabled"]:
        if not body.totp_code.strip():
            await audit(request, "auth.2fa_challenge", f"user:{username}")
            return {"requires_2fa": True}
        if not verify_totp(user["totp_secret"], body.totp_code.strip()):
            await audit(request, "auth.2fa_failed", f"user:{username}")
            raise HTTPException(status_code=401, detail="Invalid two-factor authentication code")

    settings = request.app.state.settings
    secret = settings.auth_token_secret or settings.api_access_token
    tier = TLP_TIER.get(user["tlp_clearance"].upper(), 0)
    token = issue_token(
        secret,
        user["username"],
        ttl_hours=settings.auth_token_ttl_hours,
        tier=tier,
        is_admin=user["is_admin"],
    )
    await audit(request, "auth.login", f"user:{user['username']}",
                json.dumps({"2fa": user["totp_enabled"]}))
    return {"token": token, "user": _public_user(user)}


@router.get("/me")
async def me(
    request: Request,
    policy: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    """Current requester identity: username, workspaces, clearance, admin flag."""
    if policy.get("privileged"):
        return {
            "username": "ops-token",
            "workspace_tags": ["TI"],
            "tlp_clearance": "RED",
            "is_admin": True,
            "totp_enabled": False,
            "source": "ops-token",
        }
    user = await _get_user(request, policy.get("username", ""))
    if user is None or user.get("is_disabled"):
        raise HTTPException(status_code=401, detail="Account no longer available")
    return {**_public_user(user), "source": "user"}


class TwoFactorBody(BaseModel):
    code: str = ""


@router.post("/2fa/setup")
async def setup_two_factor(
    request: Request,
    body: TwoFactorBody,
    policy: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    """Generate a TOTP secret for the logged-in user (not yet enabled).

    The secret is stored and the otpauth:// URL returned for scanning; the
    user then POSTs /2fa/enable with a code proven from their authenticator.
    """
    username = policy.get("username", "")
    if policy.get("privileged") or not username:
        raise HTTPException(status_code=403, detail="2FA is for real user accounts only")
    user = await _get_user(request, username)
    if user is None or user.get("is_disabled"):
        raise HTTPException(status_code=401, detail="Account no longer available")

    secret = generate_totp_secret()
    await _upsert_user(request, {**user, "totp_secret": secret})
    settings = request.app.state.settings
    await audit(request, "auth.2fa_setup", f"user:{username}")
    return {
        "secret": secret,
        "otpauth_url": totp_uri(secret, username, settings.totp_issuer),
    }


@router.post("/2fa/enable")
async def enable_two_factor(
    request: Request,
    body: TwoFactorBody,
    policy: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    username = policy.get("username", "")
    if policy.get("privileged") or not username:
        raise HTTPException(status_code=403, detail="2FA is for real user accounts only")
    user = await _get_user(request, username)
    if user is None or user.get("is_disabled"):
        raise HTTPException(status_code=401, detail="Account no longer available")
    if not user["totp_secret"]:
        raise HTTPException(status_code=400, detail="Run /2fa/setup first")

    code = body.code.strip()
    if not verify_totp(user["totp_secret"], code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    await _upsert_user(request, {**user, "totp_enabled": True})
    await audit(request, "auth.2fa_enabled", f"user:{username}")
    return {"status": "ok", "totp_enabled": True}


class DisableTwoFactorBody(BaseModel):
    code: str = ""


@router.post("/2fa/disable")
async def disable_two_factor(
    request: Request,
    body: DisableTwoFactorBody,
    policy: dict[str, Any] = Depends(require_user),
) -> dict[str, Any]:
    username = policy.get("username", "")
    if policy.get("privileged") or not username:
        raise HTTPException(status_code=403, detail="2FA is for real user accounts only")
    user = await _get_user(request, username)
    if user is None or user.get("is_disabled"):
        raise HTTPException(status_code=401, detail="Account no longer available")
    if user["totp_enabled"]:
        if not body.code.strip() or not verify_totp(user["totp_secret"], body.code.strip()):
            raise HTTPException(status_code=400, detail="Invalid TOTP code")
    await _upsert_user(request, {**user, "totp_secret": "", "totp_enabled": False})
    await audit(request, "auth.2fa_disabled", f"user:{username}")
    return {"status": "ok", "totp_enabled": False}


def _validate_user_input(
    workspace_tags: list[str],
    tlp_clearance: str,
    is_admin: bool,
) -> None:
    bad = [w for w in workspace_tags if w not in WORKSPACES]
    if bad:
        raise HTTPException(status_code=422, detail=f"Invalid workspace tag(s): {', '.join(bad)}")
    if tlp_clearance.upper() not in TLP_ORDER:
        raise HTTPException(status_code=422, detail="tlp_clearance must be one of " + ", ".join(TLP_ORDER))
    if not is_admin and not workspace_tags:
        raise HTTPException(
            status_code=422,
            detail="Non-admin users need at least one workspace tag (TI/CERT/DFIR)",
        )


class CreateUserBody(BaseModel):
    username: str
    password: str
    workspace_tags: list[str] = []
    tlp_clearance: str = "CLEAR"
    is_admin: bool = False


@router.post("/users", status_code=201)
async def admin_create_user(
    request: Request,
    body: CreateUserBody,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Create a user (admin only). Admin creation also allowed via the CLI seed
    tool; this endpoint is the API equivalent."""
    username = body.username.strip()
    if len(username) < 3 or len(body.password) < 8:
        raise HTTPException(status_code=422, detail="username (>=3 chars) and password (>=8 chars) required")
    user = await _get_user(request, username)
    if user:
        raise HTTPException(status_code=409, detail="Username already exists")
    _validate_user_input(body.workspace_tags, body.tlp_clearance, body.is_admin)
    await _upsert_user(request, {
        "username": username,
        "password_hash": hash_password(body.password),
        "workspace_tags": body.workspace_tags,
        "tlp_clearance": body.tlp_clearance,
        "is_admin": body.is_admin,
    })
    await audit(request, "modify.user_create", f"user:{username}",
                json.dumps({"workspace_tags": body.workspace_tags,
                            "tlp_clearance": body.tlp_clearance}))
    return {"status": "ok", "user": {"username": username, **body.model_dump(exclude={"password"})}}


class UpdateUserBody(BaseModel):
    password: str | None = None
    workspace_tags: list[str] | None = None
    tlp_clearance: str | None = None
    is_admin: bool | None = None


@router.patch("/users/{username}")
async def admin_update_user(
    request: Request,
    username: str,
    body: UpdateUserBody,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    user = await _get_user(request, username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    updates: dict[str, Any] = {}
    if body.workspace_tags is not None:
        _validate_user_input(body.workspace_tags,
                             (body.tlp_clearance or user["tlp_clearance"]),
                             body.is_admin if body.is_admin is not None else user["is_admin"])
        updates["workspace_tags"] = body.workspace_tags
    if body.tlp_clearance is not None:
        if body.tlp_clearance.upper() not in TLP_ORDER:
            raise HTTPException(status_code=422, detail="Invalid TLP clearance")
        updates["tlp_clearance"] = body.tlp_clearance.upper()
    if body.is_admin is not None:
        updates["is_admin"] = body.is_admin
    if body.password:
        if len(body.password) < 8:
            raise HTTPException(status_code=422, detail="Password must be at least 8 characters")
        updates["password_hash"] = hash_password(body.password)
    await _upsert_user(request, {**user, **updates})
    await audit(request, "modify.user_update", f"user:{username}")
    return {"status": "ok", "user": _public_user({**user, **updates})}


@router.delete("/users/{username}")
async def admin_delete_user(
    request: Request,
    username: str,
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Soft-delete a user (is_disabled=1, clearance dropped to CLEAR)."""
    if username == request.state.user_policy.get("username") and not request.state.user_policy.get("privileged"):
        raise HTTPException(status_code=409, detail="You cannot delete your own account")
    user = await _get_user(request, username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    await _upsert_user(request, {**user, "is_disabled": True,
                                "tlp_clearance": "CLEAR", "workspace_tags": []})
    await audit(request, "modify.user_delete", f"user:{username}")
    return {"status": "ok"}


@router.get("/users")
async def admin_list_users(
    request: Request,
    search: str = "",
    _: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    db = request.app.state.db
    clause = ""
    params: dict[str, Any] = {}
    if search:
        clause = "WHERE positionCaseInsensitive(username, {s:String}) > 0"
        params["s"] = search
    rows = await db.query(
        f"""
        SELECT username, workspace_tags, tlp_clearance, is_admin, totp_enabled, is_disabled, ts
        FROM {request.app.state.settings.clickhouse_database}.users FINAL
        {clause}
        ORDER BY username
        """,
        parameters=params,
    )
    users = [
        {
            "username": r[0],
            "workspace_tags": r[1] or [],
            "tlp_clearance": r[2] or "CLEAR",
            "is_admin": bool(r[3]),
            "totp_enabled": bool(r[4]),
            "is_disabled": bool(r[5]),
            "ts": r[6].isoformat() if r[6] else None,
        }
        for r in rows.result_rows
    ]
    return {"users": users}