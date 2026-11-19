"""Local login: Argon2id passwords + TOTP with progressive lockout + admin unlock."""
from __future__ import annotations

import hashlib
import io
import secrets
import time

import pyotp
import qrcode
import redis.asyncio as aioredis
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException

from api.core.config import get_settings
from api.core.encryption import decrypt, encrypt

_ph = PasswordHasher()

# Redis key patterns
_TOTP_FAIL_KEY = "totp_fail:{username}"  # attempt counter
_TOTP_LOCK_KEY = "totp_lock:{username}"  # lockout marker
_TOTP_USED_KEY = "totp_used:{username}:{code}"  # single-use code anti-replay
_IP_FAIL_KEY = "auth_fail_ip:{ip}"


def _redis() -> aioredis.Redis:
    return aioredis.from_url(get_settings().redis_url, decode_responses=True)


# ── Password ──────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, password)
    except VerifyMismatchError:
        return False


# ── TOTP ──────────────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, username: str, app_name: str = "open-ctem") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=app_name)


def totp_qr_png(secret: str, username: str) -> bytes:
    """Return QR code PNG bytes for TOTP enrollment."""
    uri = totp_provisioning_uri(secret, username)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


async def verify_totp(username: str, code: str, secret_encrypted: str) -> None:
    """Verify TOTP code. Raises HTTPException on failure, lockout, or replay."""
    settings = get_settings()
    r = _redis()

    lock_key = _TOTP_LOCK_KEY.format(username=username)
    if await r.exists(lock_key):
        ttl = await r.ttl(lock_key)
        raise HTTPException(429, detail=f"Account locked. Try again in {ttl} seconds.")

    fail_key = _TOTP_FAIL_KEY.format(username=username)
    fail_count = int(await r.get(fail_key) or 0)

    # Replay check -- codes are single-use within their window
    used_key = _TOTP_USED_KEY.format(username=username, code=code)
    if await r.exists(used_key):
        raise HTTPException(401, detail="Code already used")

    secret = decrypt(secret_encrypted)
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        # Increment failure counter with appropriate lockout
        new_count = fail_count + 1
        await r.incr(fail_key)
        await r.expire(fail_key, 3600)

        if new_count >= settings.totp_lockout_threshold_3:
            # Hard lock -- requires admin to clear
            await r.set(lock_key, "hard", ex=86400 * 30)  # 30 days, admin must unlock
            await _flag_hard_lockout(username)
            raise HTTPException(401, detail="Account locked due to repeated failures. Contact admin.")
        elif new_count >= settings.totp_lockout_threshold_2:
            await r.set(lock_key, "soft", ex=settings.totp_lockout_minutes_2 * 60)
            raise HTTPException(429, detail=f"Too many failures. Locked for {settings.totp_lockout_minutes_2} minutes.")
        elif new_count >= settings.totp_lockout_threshold_1:
            await r.set(lock_key, "soft", ex=settings.totp_lockout_minutes_1 * 60)
            raise HTTPException(429, detail=f"Too many failures. Locked for {settings.totp_lockout_minutes_1} minutes.")

        raise HTTPException(401, detail="Invalid TOTP code")

    # Success -- clear failure counter, mark code as used
    await r.delete(fail_key)
    await r.set(used_key, "1", ex=90)  # 90s covers the ±30s valid_window


async def _flag_hard_lockout(username: str) -> None:
    """Mark the user record as hard-locked in DB (admin must unlock from UI)."""
    from api.core import db as core_db
    from api.models.user import User
    from sqlalchemy import select
    async with core_db._session_factory() as db:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        if user:
            user.is_locked = True
            user.locked_reason = "Excessive TOTP failures"
            await db.commit()


async def admin_unlock_user(username: str) -> None:
    """Admin unlocks a user -- clears Redis lockout AND DB flag."""
    r = _redis()
    await r.delete(_TOTP_LOCK_KEY.format(username=username))
    await r.delete(_TOTP_FAIL_KEY.format(username=username))
    await r.delete(f"pw_fail:{username.lower()}", f"pw_lock:{username.lower()}")

    from api.core import db as core_db
    from api.models.user import User
    from sqlalchemy import select
    async with core_db._session_factory() as db:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        if user:
            user.is_locked = False
            user.locked_reason = None
            await db.commit()


# ── Recovery codes ────────────────────────────────────────────────────────────

def generate_recovery_codes(count: int = 10) -> list[str]:
    """Plain-text codes to give the user at enrollment. Store hashed."""
    return [secrets.token_hex(10) for _ in range(count)]


def hash_recovery_codes(codes: list[str]) -> list[str]:
    return [hashlib.sha256(c.encode()).hexdigest() for c in codes]


def verify_recovery_code(code: str, hashed_codes: list[str]) -> bool:
    h = hashlib.sha256(code.strip().lower().encode()).hexdigest()
    return any(secrets.compare_digest(h, stored) for stored in hashed_codes)
