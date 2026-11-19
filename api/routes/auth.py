"""Login, logout, OIDC callback, token refresh, TOTP enrollment."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import local, oidc
from api.auth.middleware import create_access_token, create_refresh_token, get_current_user
from api.core.config import get_settings
from api.core.db import get_session
from api.core.encryption import search_hash
from api.models.user import User, UserRole

router = APIRouter()
_templates = Jinja2Templates(directory="api/web/templates")


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    from api.core.security import generate_csrf_token
    settings = get_settings()
    if settings.auth_mode == "oidc_only":
        redirect_url = await oidc.start_flow(request)
        return RedirectResponse(redirect_url, status_code=302)
    # Generate a session ID for CSRF binding if not set
    if "session_id" not in request.session:
        request.session["session_id"] = secrets.token_hex(16)
    csrf_token = generate_csrf_token(request.session["session_id"])
    return _templates.TemplateResponse("pages/login.html", {
        "request": request, "settings": settings, "csrf_token": csrf_token
    })


@router.get("/auth/sso")
async def sso_redirect(request: Request):
    """Explicit SSO redirect for 'both' mode."""
    redirect_url = await oidc.start_flow(request)
    return RedirectResponse(redirect_url, status_code=302)


@router.get("/auth/callback")
async def oidc_callback(request: Request, code: str, state: str, db: AsyncSession = Depends(get_session)):
    user_info = await oidc.handle_callback(request, code, state)
    user = await _upsert_oidc_user(user_info, db)
    return await _create_session(request, user)



@router.post("/auth/login")
async def browser_login(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    csrf: Annotated[str | None, Form(alias="_csrf")] = None,
    totp_code: Annotated[str | None, Form()] = None,
    db: AsyncSession = Depends(get_session),
):
    from api.core.security import verify_csrf_token
    session_id = request.session.get("session_id", "")
    if not csrf or not verify_csrf_token(csrf, session_id):
        raise HTTPException(403, detail="CSRF validation failed")
    settings = get_settings()
    if settings.auth_mode == "oidc_only":
        raise HTTPException(400, detail="Local auth is disabled")

    result = await db.execute(select(User).where(User.username == username, User.is_local == True))  # noqa: E712
    user = result.scalar_one_or_none()

    if user is None or not user.password_hash or not local.verify_password(password, user.password_hash):
        return _templates.TemplateResponse("pages/login.html", {
            "request": request, "error": "Invalid username or password", "settings": settings
        }, status_code=401)

    if user.is_locked:
        return _templates.TemplateResponse("pages/login.html", {
            "request": request, "error": "Account locked. Contact your administrator.", "settings": settings
        }, status_code=401)

    if user.totp_enabled or settings.mfa_required:
        if not totp_code:
            # Redirect to TOTP step
            request.session["pending_user_id"] = str(user.id)
            return RedirectResponse("/auth/totp", status_code=302)
        if not user.totp_secret:
            return _templates.TemplateResponse("pages/login.html", {
                "request": request, "error": "MFA not configured. Contact admin.", "settings": settings
            }, status_code=401)
        try:
            await local.verify_totp(username, totp_code, user.totp_secret)
        except HTTPException as e:
            return _templates.TemplateResponse("pages/login.html", {
                "request": request, "error": e.detail, "settings": settings
            }, status_code=401)

    return await _create_session(request, user)


@router.get("/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _create_session(request: Request, user: User) -> RedirectResponse:
    access = create_access_token(str(user.id), user.username)
    _, jti = create_refresh_token(str(user.id))
    request.session["access_token"] = access
    request.session["user_id"] = str(user.id)
    user.last_login = datetime.now(timezone.utc)
    return RedirectResponse("/", status_code=302)


async def _upsert_oidc_user(info: dict, db: AsyncSession) -> User:
    """Create or update user from OIDC claims."""
    from api.core.encryption import encrypt, search_hash
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
        # Default to read_only role for new OIDC users
        db.add(UserRole(user_id=user.id, role_name="read_only"))

    if info.get("email"):
        user.email = info["email"]
        user.email_hash = search_hash(info["email"])
    if info.get("display_name"):
        user.display_name = info["display_name"]

    await db.commit()
    return user
