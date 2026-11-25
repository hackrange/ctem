"""JWT session middleware and current-user dependency."""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt import PyJWTError as JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.core.config import get_settings
from api.core.db import get_session
from api.models.user import ApiToken, User

_bearer = HTTPBearer(auto_error=False)
log = logging.getLogger("open-ctem.auth")

_PUBLIC_PATHS = {"/login", "/auth/callback", "/auth/token", "/health"}


def _settings():
    return get_settings()


# ── Token creation ────────────────────────────────────────────────────────────

def create_access_token(user_id: str, username: str) -> str:
    settings = _settings()
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    return jwt.encode(
        {"sub": user_id, "username": username, "exp": exp, "type": "access"},
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )


def create_refresh_token(user_id: str) -> tuple[str, str]:
    """Return (token_string, jti). JTI is stored in Redis for revocation."""
    settings = _settings()
    jti = str(uuid.uuid4())
    exp = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    token = jwt.encode(
        {"sub": user_id, "jti": jti, "exp": exp, "type": "refresh"},
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return token, jti


def _decode(token: str) -> dict:
    settings = _settings()
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError as e:
        raise HTTPException(401, detail="Invalid or expired token") from e


# ── Dependencies ──────────────────────────────────────────────────────────────

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_session),
) -> User:
    """Extract and validate the authenticated user from JWT or API token."""

    token_str: str | None = None

    from_session = False
    if credentials:
        token_str = credentials.credentials
    else:
        # Fall back to session cookie for browser requests
        token_str = request.session.get("access_token")
        from_session = bool(token_str)

    if not token_str:
        raise HTTPException(401, detail="Not authenticated")

    # Check if it looks like a long-lived API token (hex, 64 chars)
    if len(token_str) == 64 and all(c in "0123456789abcdef" for c in token_str.lower()):
        return await _authenticate_api_token(token_str, request, db)
    if not from_session:
        # A JWT is only ever issued into a browser session, whose sign-out and password checks run below. Replayed
        # as a bearer token (lifted from a copied cookie) it would skip them, so the bearer path takes API tokens only.
        raise HTTPException(401, detail="Invalid API token")

    claims = _decode(token_str)
    if claims.get("type") != "access":
        raise HTTPException(401, detail="Invalid token type")

    user_id = claims.get("sub")
    result = await db.execute(
        select(User).where(User.id == str(user_id)).options(selectinload(User.roles))
    )
    user = result.scalar_one_or_none()

    if user is None or not user.is_active or user.is_locked:
        raise HTTPException(401, detail="User not found or disabled")

    if from_session:
        from api.auth import sessions
        await sessions.check(request, user, db)   # signed out elsewhere, or older than the latest password
        _slide(request, claims, user)
        if request.session.get("acting_as") is not None:   # Admin > Users > View as (api/auth/impersonation.py)
            from api.auth import impersonation
            return await impersonation.resolve(request, user, db)
    return user


def _slide(request: Request, claims: dict, user: User) -> None:
    """A browser session stays signed in while it's being used: once half its time is gone, it gets a fresh token
    (and the cookie a fresh expiry), so it only ends after a stretch of inactivity, never in the middle of work.
    It still ends at the hard limit counted from sign-in (session_max_hours)."""
    import time
    settings = _settings()
    now = int(time.time())
    started = request.session.get("signed_in_at")
    if not isinstance(started, int):
        started = now
        request.session["signed_in_at"] = now   # sessions from before this existed count from now
    if now - started > settings.session_max_hours * 3600:
        request.session.clear()
        raise HTTPException(401, detail="Session ended; sign in again")
    left = int(claims.get("exp", 0)) - now
    if left < settings.access_token_expire_minutes * 60 / 2:
        request.session["access_token"] = create_access_token(str(user.id), user.username)


async def _authenticate_api_token(raw_token: str, request: Request, db: AsyncSession) -> User:
    import ipaddress
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    result = await db.execute(
        select(ApiToken).where(ApiToken.token_hash == token_hash, ApiToken.is_active == True)  # noqa: E712
    )
    api_token = result.scalar_one_or_none()

    # Deliberate: return the same error whether the token is unknown, expired, or IP-blocked.
    # No oracle for which condition failed.
    if api_token is None:
        raise HTTPException(401, detail="Invalid API token")
    exp = api_token.expires_at
    if exp is not None and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)  # sqlite hands back naive timestamps
    if exp and exp < datetime.now(timezone.utc):
        raise HTTPException(401, detail="Invalid API token")

    # IP enforcement -- token only works from its registered addresses
    caller_ip = _client_ip(request)
    if not _ip_allowed(caller_ip, api_token.allowed_ips or []):
        raise HTTPException(401, detail="Invalid API token")

    result2 = await db.execute(
        select(User).where(User.id == str(api_token.user_id)).options(selectinload(User.roles))
    )
    user = result2.scalar_one_or_none()
    if user is None or not user.is_active or user.is_locked:
        raise HTTPException(401, detail="Invalid API token")

    try:
        api_token.last_used = datetime.now(timezone.utc)
        api_token.last_used_ip = caller_ip
        await db.commit()
    except Exception:
        log.warning("could not record token last-used", exc_info=True)

    return user


def _ip_allowed(caller_ip: str, allowed: list[str]) -> bool:
    """Check if caller_ip is in the allowed list (exact IPs or CIDR ranges)."""
    import ipaddress
    if not allowed:
        return False
    try:
        addr = ipaddress.ip_address(caller_ip)
    except ValueError:
        return False
    for entry in allowed:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


def _client_ip(request: Request) -> str:
    from api.core.security import _client_ip as real_ip
    return real_ip(request)
