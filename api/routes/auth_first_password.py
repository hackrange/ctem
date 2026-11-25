"""A password an admin set is a one-time key (CTE-035): it expires (INITIAL_PASSWORD_HOURS, 72 by default) and the
account's first sign-in replaces it before anything else, MFA enrollment included. Whoever learns it after that, or
after it expires, holds nothing."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import local
from api.core.db import get_session
from api.models.user import User

router = APIRouter()
log = logging.getLogger("open-ctem.auth")
PENDING = "pw_change"
_EXPIRED = "This password has expired. Ask an administrator to set a new one."
_STEP_KEYS = ("pending_user_id", "pending_at", "pending_ms", "totp_enroll", PENDING)


def expired(user: User) -> bool:
    at = user.password_expires_at
    if at is None:
        return False
    return (at if at.tzinfo else at.replace(tzinfo=timezone.utc)) <= datetime.now(timezone.utc)


async def start(request: Request, db: AsyncSession, user: User):
    """After the admin-set password checked out: ask for the person's own one, bound to this account and moment."""
    from api.routes.auth import _render_login
    if expired(user):
        log.info("sign-in by %s refused: its admin-set password expired", user.id)
        return await _render_login(request, db, error=_EXPIRED)
    local.begin_mfa_step(request.session, str(user.id))
    request.session[PENDING] = str(user.id)
    return await _render_login(request, db, pw_change=True)


@router.post("/auth/first-password")
async def first_password(
    request: Request,
    new_password: Annotated[str, Form(max_length=1024)],
    confirm_password: Annotated[str, Form(max_length=1024)],
    csrf: Annotated[str | None, Form(alias="_csrf")] = None,
    db: AsyncSession = Depends(get_session),
):
    from api.models.settings import AuditLog
    from api.routes import auth as a
    if not a._csrf_ok(request, csrf):
        return await a._stale_form(request, db)

    async def over(msg: str):
        for k in _STEP_KEYS:
            request.session.pop(k, None)
        return await a._render_login(request, db, error=msg)

    uid, started = request.session.get("pending_user_id"), int(request.session.get("pending_at", 0))
    if not uid or request.session.get(PENDING) != uid or time.time() - started > a._PENDING_TTL:
        return await over("Sign-in expired. Please start again.")
    user = (await db.execute(select(User).where(User.id == uid))).scalar_one_or_none()
    from api.auth import account_seal
    roles = await account_seal.verified_roles(db, user) if user is not None else None
    if (user is None or not user.is_local or not user.is_active or user.is_locked or not user.password_change_required
            or roles is None):
        return await over(a._LOGIN_FAILED)
    begun = request.session.get("pending_ms")
    if a._predates_cutoff(user, begun if isinstance(begun, int) else started * 1000):
        return await over("Sign-in expired. Please start again.")   # reset or signed out everywhere meanwhile
    if expired(user):
        return await over(_EXPIRED)
    why = None
    if len(new_password) < 12:
        why = "Use at least 12 characters."
    elif new_password != confirm_password:
        why = "The two passwords don't match."
    elif user.password_hash and local.verify_password(new_password, user.password_hash):
        why = "Choose a password different from the one you were given."
    if why:
        return await a._render_login(request, db, error=why, pw_change=True)
    user.password_hash = local.hash_password(new_password)
    user.password_change_required, user.password_expires_at = False, None
    await account_seal.reseal(db, user, roles)
    request.session.pop(PENDING, None)
    db.add(AuditLog(actor_user_id=str(user.id), actor_username=user.username, action="password.first_change",
                    resource_type="user", resource_id=str(user.id), detail="replaced the password an admin set"))
    await db.commit()
    return await a._after_password(request, db, user)
