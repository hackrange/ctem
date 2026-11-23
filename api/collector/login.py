"""Admin username/password (+TOTP) check for collector enrollment. The password is never kept."""
from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.core.accounts import find_login
from api.core.config import get_settings
from api.models.user import User


def _fail() -> HTTPException:
    return HTTPException(401, detail="Invalid credentials")


async def check_admin_password(db: AsyncSession, username: str, password: str) -> User:
    from api.auth import local
    from api.routes.auth import _DUMMY_HASH, _pw_clear, _pw_fail, _pw_locked

    if get_settings().auth_mode == "oidc_only":
        raise HTTPException(403, detail="Password sign-in is disabled; use an enrollment code")
    if await _pw_locked(username):
        local.verify_password(password, _DUMMY_HASH)  # same timing as a real check
        raise HTTPException(429, detail="Too many attempts")
    user = await find_login(db, username, User.is_local == True, options=[selectinload(User.roles)])  # noqa: E712
    ok = local.verify_password(password, user.password_hash if user and user.password_hash else _DUMMY_HASH)
    if not ok or user is None or not user.is_active or user.is_locked:
        if not ok:
            await _pw_fail(username)
        raise _fail()
    await _pw_clear(username)
    if "admin" not in user.role_names:
        raise HTTPException(403, detail="Collector enrollment needs an admin account")
    return user


def mfa_needed(user: User) -> bool:
    return bool(user.totp_enabled or get_settings().mfa_required)


async def check_mfa(user: User, code: str | None) -> None:
    from api.auth import local

    if not mfa_needed(user):
        return
    if not user.totp_enabled or not user.totp_secret:
        # MFA is mandatory but this account never enrolled; do that in the browser first
        raise HTTPException(403, detail="Finish MFA enrollment in the web UI first")
    if not code:
        raise _fail()
    await local.verify_totp(user.username, code, user.totp_secret)
