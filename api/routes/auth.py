"""Login, logout, OIDC callback, TOTP enrollment, profile."""
from __future__ import annotations

import logging
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import local, oidc
from api.auth.middleware import create_access_token, get_current_user
from api.core.config import get_settings
from api.core.db import get_session
from api.core.encryption import decrypt, encrypt, search_hash
from api.models.user import User, UserRole

router = APIRouter()
_templates = Jinja2Templates(directory="api/web/templates")
log = logging.getLogger("open-ctem.auth")

_LOGIN_FAILED = "Sign-in failed. Check your credentials or contact your administrator."
# Failed sign-ins answer 200 because the LB eats 4xx bodies, form and all
_PENDING_TTL = 300          # seconds to finish the MFA step
_PW_FAIL_LIMIT = 10         # failed passwords before a cool-off
_PW_LOCK_SECONDS = 900
# Verifying against a throwaway hash keeps "no such user" as slow as "wrong password"
_DUMMY_HASH = local.hash_password(secrets.token_hex(16))


async def _render_login(request: Request, db: AsyncSession, *, error: str | None = None,
                        status: int = 200, totp_step: bool = False, enroll: dict | None = None) -> HTMLResponse:
    from api.core.security import generate_csrf_token
    from api.models.settings import AppSetting
    if "session_id" not in request.session:
        request.session["session_id"] = secrets.token_hex(16)
    rows = await db.execute(select(AppSetting).where(AppSetting.key.like("brand.%")))
    branding = {s.key.removeprefix("brand."): s.value for s in rows.scalars()}
    return _templates.TemplateResponse(request, "pages/login.html", {
        "request": request,
        "settings": get_settings(),
        "csrf_token": generate_csrf_token(request.session["session_id"]),
        "error": error,
        "totp_step": totp_step,
        "enroll": enroll,
        "app_title": branding.get("title", "open-ctem"),
        "accent_color": branding.get("accent_color", "#f5a623"),
        "logo_url": branding.get("logo_url"),
        "org_name": branding.get("org_name"),
    }, status_code=status)


def _check_csrf(request: Request, token: str | None) -> None:
    from api.core.security import verify_csrf_token
    if not token or not verify_csrf_token(token, request.session.get("session_id", "")):
        raise HTTPException(403, detail="CSRF validation failed")


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, db: AsyncSession = Depends(get_session)):
    if get_settings().auth_mode == "oidc_only":
        return RedirectResponse(await oidc.start_flow(request), status_code=302)
    return await _render_login(request, db)


@router.get("/auth/sso")
async def sso_redirect(request: Request):
    """Explicit SSO redirect for 'both' mode."""
    return RedirectResponse(await oidc.start_flow(request), status_code=302)


@router.get("/auth/callback")
async def oidc_callback(request: Request, code: str, state: str, db: AsyncSession = Depends(get_session)):
    user_info = await oidc.handle_callback(request, code, state)
    user = await _upsert_oidc_user(user_info, db)
    return await _create_session(request, user, db)


@router.post("/auth/login")
async def browser_login(
    request: Request,
    username: Annotated[str, Form(max_length=128)],
    password: Annotated[str, Form(max_length=1024)],
    csrf: Annotated[str | None, Form(alias="_csrf")] = None,
    db: AsyncSession = Depends(get_session),
):
    _check_csrf(request, csrf)
    settings = get_settings()
    if settings.auth_mode == "oidc_only":
        raise HTTPException(400, detail="Local auth is disabled")

    if await _pw_locked(username):
        local.verify_password(password, _DUMMY_HASH)
        return await _render_login(request, db, error=_LOGIN_FAILED)

    result = await db.execute(select(User).where(User.username == username, User.is_local == True))  # noqa: E712
    user = result.scalar_one_or_none()
    ok = local.verify_password(password, user.password_hash if user and user.password_hash else _DUMMY_HASH)
    if not ok or user is None or not user.is_active or user.is_locked:
        if not ok:
            await _pw_fail(username)
        return await _render_login(request, db, error=_LOGIN_FAILED)
    await _pw_clear(username)

    if user.totp_enabled or settings.mfa_required:
        request.session["pending_user_id"] = str(user.id)
        request.session["pending_at"] = int(time.time())
        if user.totp_enabled and user.totp_secret:
            return await _render_login(request, db, totp_step=True)
        # MFA is mandatory and this account has none yet: enroll right here
        secret = local.generate_totp_secret()
        request.session["totp_enroll"] = encrypt(secret)
        return await _render_login(request, db, totp_step=True, enroll=_enroll_view(secret, user.username))

    return await _create_session(request, user, db)


@router.post("/auth/totp")
async def browser_totp(
    request: Request,
    totp_code: Annotated[str, Form(min_length=6, max_length=8)],
    csrf: Annotated[str | None, Form(alias="_csrf")] = None,
    db: AsyncSession = Depends(get_session),
):
    _check_csrf(request, csrf)
    uid = request.session.get("pending_user_id")
    started = int(request.session.get("pending_at", 0))
    if not uid or time.time() - started > _PENDING_TTL:
        request.session.pop("pending_user_id", None)
        return await _render_login(request, db, error="Sign-in expired. Please start again.")

    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    if user is None or not user.is_active or user.is_locked:
        return await _render_login(request, db, error=_LOGIN_FAILED)

    enrolling = request.session.get("totp_enroll")
    if enrolling:
        import pyotp
        secret = decrypt(enrolling)
        if not pyotp.TOTP(secret).verify(totp_code.strip(), valid_window=1):
            return await _render_login(request, db, error="That code didn't match. Try the next one.",
                                       totp_step=True, enroll=_enroll_view(secret, user.username))
        user.totp_secret = enrolling  # same shape as the other enrollment paths
        user.totp_enabled = True
        return await _create_session(request, user, db)

    if not user.totp_secret:
        return await _render_login(request, db, error=_LOGIN_FAILED)
    try:
        await local.verify_totp(user.username, totp_code.strip(), user.totp_secret)
    except HTTPException as e:
        return await _render_login(request, db, error=str(e.detail), totp_step=True)
    return await _create_session(request, user, db)


def _enroll_view(secret: str, username: str) -> dict:
    from api.routes.admin import _qr_png_b64
    return {"secret": secret, "qr_png": _qr_png_b64(local.totp_provisioning_uri(secret, username))}


@router.get("/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _create_session(request: Request, user: User, db: AsyncSession) -> RedirectResponse:
    # Fresh session on every login so nothing from before sign-in carries over
    request.session.clear()
    request.session["session_id"] = secrets.token_hex(16)
    request.session["access_token"] = create_access_token(str(user.id), user.username)
    request.session["user_id"] = str(user.id)
    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    return RedirectResponse("/", status_code=302)


async def _pw_locked(username: str) -> bool:
    try:
        return bool(await local._redis().exists(f"pw_lock:{username.lower()}"))
    except Exception:
        log.warning("login lockout check skipped (Redis down?)")
        return False  # the per-IP rate limit still applies


async def _pw_fail(username: str) -> None:
    try:
        r = local._redis()
        key = f"pw_fail:{username.lower()}"
        count = await r.incr(key)
        await r.expire(key, _PW_LOCK_SECONDS)
        if count >= _PW_FAIL_LIMIT:
            await r.set(f"pw_lock:{username.lower()}", "1", ex=_PW_LOCK_SECONDS)
    except Exception:
        log.warning("could not record failed login (Redis down?)")


async def _pw_clear(username: str) -> None:
    try:
        await local._redis().delete(f"pw_fail:{username.lower()}")
    except Exception:
        log.warning("could not clear failed-login counter (Redis down?)")


def _require_browser_session(request: Request, user: User) -> None:
    """MFA and password changes are browser-only; a leaked API token can't touch them."""
    if request.session.get("user_id") != str(user.id):
        raise HTTPException(403, detail="Use the web interface for this action")


# ── MFA enrollment ────────────────────────────────────────────────────────────

class TotpSetupRequest(BaseModel):
    current_code: str | None = Field(None, max_length=8)


class TotpCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


@router.get("/api/v1/auth/totp/status")
async def totp_status(current_user: User = Depends(get_current_user)):
    return {"totp_enabled": bool(current_user.totp_enabled)}


@router.post("/api/v1/auth/totp/setup")
async def self_totp_setup(
    request: Request,
    body: TotpSetupRequest | None = None,
    current_user: User = Depends(get_current_user),
):
    """Start enrollment. Nothing changes on the account until /verify succeeds."""
    _require_browser_session(request, current_user)
    if current_user.totp_enabled:
        if not body or not body.current_code:
            raise HTTPException(400, detail="Enter your current authenticator code to replace it")
        await local.verify_totp(current_user.username, body.current_code, current_user.totp_secret)
    secret = local.generate_totp_secret()
    request.session["totp_pending"] = encrypt(secret)
    uri = local.totp_provisioning_uri(secret, current_user.username)
    from api.routes.admin import _qr_png_b64
    return {"provisioning_uri": uri, "secret": secret, "qr_png": _qr_png_b64(uri)}


@router.post("/api/v1/auth/totp/verify")
async def self_totp_verify(
    request: Request,
    body: TotpCodeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    import pyotp
    _require_browser_session(request, current_user)
    pending = request.session.get("totp_pending")
    if not pending:
        raise HTTPException(400, detail="Start setup first")
    if not pyotp.TOTP(decrypt(pending)).verify(body.code.strip(), valid_window=1):
        raise HTTPException(400, detail="That code didn't match. Try the next one.")
    # Same storage shape as admin setup: the column encrypts again on write
    current_user.totp_secret = pending
    current_user.totp_enabled = True
    request.session.pop("totp_pending", None)
    await db.commit()
    return {"totp_enabled": True}


# ── Profile ───────────────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[A-Za-z]{2,}$")


class PrefsUpdate(BaseModel):
    theme: str | None = Field(None, pattern="^(system|light|dark)$")
    font_size: str | None = Field(None, pattern="^(small|medium|large|xlarge)$")
    high_contrast: bool | None = None
    reduce_motion: bool | None = None
    dyslexic_font: bool | None = None
    email: str | None = Field(None, max_length=254)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str | None) -> str | None:
        if v is not None and not _EMAIL_RE.match(v.strip()):
            raise ValueError("Enter a valid email address")
        return v.strip() if v else v


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


@router.get("/api/v1/profile/prefs")
async def get_prefs(current_user: User = Depends(get_current_user)):
    """Return the authenticated user's UI preferences."""
    return {"prefs": current_user.ui_prefs or {}, "email": current_user.email}


@router.patch("/api/v1/profile/prefs")
async def update_prefs(
    body: PrefsUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    """Merge preference changes into the user's ui_prefs store."""
    updates = body.model_dump(exclude_unset=True)
    if "email" in updates:
        email_val = updates.pop("email")
        current_user.email = email_val or None
        current_user.email_hash = search_hash(email_val) if email_val else None
    prefs = {**(current_user.ui_prefs or {}), **updates}
    current_user.ui_prefs = prefs
    await db.commit()
    return {"prefs": prefs}


@router.post("/api/v1/profile/password")
async def change_password(
    request: Request,
    body: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    _require_browser_session(request, current_user)
    if not current_user.is_local or not current_user.password_hash:
        raise HTTPException(400, detail="This account signs in through SSO")
    if not local.verify_password(body.current_password, current_user.password_hash):
        raise HTTPException(400, detail="Current password is incorrect")
    current_user.password_hash = local.hash_password(body.new_password)
    await db.commit()
    return {"changed": True}


async def _upsert_oidc_user(info: dict, db: AsyncSession) -> User:
    """Create or update user from OIDC claims."""
    sub = info["sub"]
    result = await db.execute(select(User).where(User.oidc_sub == sub))
    user = result.scalar_one_or_none()

    if user is None:
        user = User(
            username=info.get("username") or sub,
            oidc_sub=sub,
            is_local=False,
        )
        db.add(user)
        await db.flush()
        db.add(UserRole(user_id=user.id, role_name="read_only"))

    if info.get("email"):
        user.email = info["email"]
        user.email_hash = search_hash(info["email"])
    if info.get("display_name"):
        user.display_name = info["display_name"]

    await db.commit()
    return user
