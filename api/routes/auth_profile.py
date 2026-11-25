"""Signed-in self-service: enroll or replace one's own authenticator, profile preferences, change one's password."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import local
from api.auth.middleware import get_current_user
from api.core.db import get_session
from api.core.encryption import decrypt, encrypt, search_hash
from api.models.user import User

router = APIRouter()


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
        await local.verify_totp(current_user.username, body.current_code, current_user.totp_secret, str(current_user.id),
                                current_user.totp_seal)
    secret = local.generate_totp_secret()
    request.session["totp_pending"] = encrypt(secret)
    uri = local.totp_provisioning_uri(secret, current_user.username)
    return {"provisioning_uri": uri, "secret": secret, "qr_png": local.qr_png_b64(uri)}


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
    local.set_totp(current_user, decrypt(pending))   # sealed to this account
    current_user.totp_enabled = True
    from api.auth import account_seal
    await account_seal.reseal(db, current_user, account_seal.loaded_roles(current_user))   # as verified for this request
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
    current_user.password_change_required, current_user.password_expires_at = False, None
    from api.auth import account_seal, sessions
    sessions.new_password(request, current_user)   # every other session of this account ends; this one stays
    await account_seal.reseal(db, current_user, account_seal.loaded_roles(current_user))   # as verified for this request
    await db.commit()
    return {"changed": True}
