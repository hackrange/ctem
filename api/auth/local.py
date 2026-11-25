"""Local login: Argon2id passwords + TOTP with progressive lockout + admin unlock."""
from __future__ import annotations

import hashlib
import io
import re
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

def totp_seal(user_id: str, stored: str) -> str:
    """A keyed seal over this account's id and its stored authenticator secret (users.totp_seal). The secret itself
    stays as older versions read it, so a rollback keeps working; a secret copied in from another row, or the
    unbound form enrollment puts in a session cookie, has no valid seal for this account."""
    import hmac as _hmac

    from api.auth.account_seal import derived_key
    return _hmac.new(derived_key(b"open-ctem|totp-seal|v2"), f"{user_id}|{stored}".encode(), hashlib.sha256).hexdigest()


def set_totp(user, secret: str) -> None:
    """Store an authenticator secret for this account, sealed to it."""
    user.totp_secret = encrypt(secret)
    user.totp_seal = totp_seal(str(user.id), user.totp_secret)


def open_totp(user_id: str, stored: str | None, seal: str | None) -> str:
    """This account's authenticator secret. Raises when its seal doesn't match the account and the stored value."""
    import hmac as _hmac
    if not stored or not seal or not _hmac.compare_digest(seal, totp_seal(str(user_id), stored)):
        raise ValueError("authenticator secret isn't sealed to this account")
    return decrypt(stored)


def one_time_password(user) -> None:
    """A password an admin sets is replaced at the account's first sign-in, and expires if that doesn't come."""
    from datetime import datetime, timedelta, timezone
    user.password_change_required = True
    user.password_expires_at = datetime.now(timezone.utc) + timedelta(hours=max(1, get_settings().initial_password_hours))


def begin_mfa_step(session, user_id: str) -> None:
    """The authenticator step after a first factor (password or SSO): bound to the account and to when it began."""
    session.pop("totp_enroll", None)
    session.pop("pw_change", None)   # another account's "choose your password" step never carries over
    session["pending_user_id"] = user_id
    session["pending_at"] = int(time.time())
    session["pending_ms"] = time.time_ns() // 1_000_000   # compared with sessions_valid_after


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


async def verify_totp(username: str, code: str, secret_encrypted: str, user_id: str, seal: str | None) -> None:
    """Verify TOTP code. Raises HTTPException on failure, lockout, or replay."""
    settings = get_settings()
    # ASCII digits only: the code check normalizes full-width and other Unicode digits to the same code, so each
    # spelling would get its own single-use key and one code could be replayed in many forms
    if not re.fullmatch(r"[0-9]{6}", code or ""):
        raise HTTPException(401, detail="Invalid TOTP code")
    r = _redis()

    lock_key = _TOTP_LOCK_KEY.format(username=username)
    if await r.exists(lock_key):
        ttl = await r.ttl(lock_key)
        raise HTTPException(429, detail=f"Account locked. Try again in {ttl} seconds.")

    fail_key = _TOTP_FAIL_KEY.format(username=username)

    # Replay check -- codes are single-use within their window
    used_key = _TOTP_USED_KEY.format(username=username, code=code)
    if await r.exists(used_key):
        raise HTTPException(401, detail="Code already used")

    # Count the attempt before checking it, with INCR's own answer: parallel guesses each get their own number, so a
    # burst can't all read the same old count and slip past the lock (a success clears the count below)
    new_count = int(await r.incr(fail_key))
    await r.expire(fail_key, 3600)
    if new_count > settings.totp_lockout_threshold_3:
        raise HTTPException(429, detail="Account locked due to repeated failures. Contact admin.")

    try:
        secret = open_totp(user_id, secret_encrypted, seal)
    except Exception:  # noqa: BLE001 -- sealed to another account, or not bound: it never verifies
        import logging
        logging.getLogger("open-ctem.auth").warning("authenticator secret for %s refused: not bound to the account", user_id)
        secret = None
    totp = pyotp.TOTP(secret) if secret else None
    if totp is None or not totp.verify(code, valid_window=1):

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

    # Success -- claim the code atomically (SET NX), so two requests racing with one code can't both pass
    if not await r.set(used_key, "1", ex=90, nx=True):  # 90s covers the ±30s valid_window
        raise HTTPException(401, detail="Code already used")
    await r.delete(fail_key)


async def _flag_hard_lockout(username: str) -> None:
    """Mark the user record as hard-locked in DB (admin must unlock from UI)."""
    from api.core import db as core_db
    from api.models.user import User
    from sqlalchemy import select
    async with core_db._session_factory() as db:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        if user:
            from api.auth.account_seal import reseal, verified_roles
            roles = await verified_roles(db, user)
            user.is_locked = True
            user.locked_reason = "Excessive TOTP failures"
            if roles is not None:   # a tampered account is refused anyway; it's never sealed from here
                await reseal(db, user, roles)
            await db.commit()


async def admin_unlock_user(username: str, db_flag: bool = False) -> None:
    """Clears the Redis lockout counters; the caller clears the DB flag and re-seals (api/routes/admin_repair.py)."""
    r = _redis()
    await r.delete(_TOTP_LOCK_KEY.format(username=username))
    await r.delete(_TOTP_FAIL_KEY.format(username=username))
    await r.delete(f"pw_fail:{username.lower()}", f"pw_lock:{username.lower()}")


# ── Recovery codes ────────────────────────────────────────────────────────────

def generate_recovery_codes(count: int = 10) -> list[str]:
    """Plain-text codes to give the user at enrollment. Store hashed."""
    return [secrets.token_hex(10) for _ in range(count)]


def hash_recovery_codes(codes: list[str]) -> list[str]:
    return [hashlib.sha256(c.encode()).hexdigest() for c in codes]


def verify_recovery_code(code: str, hashed_codes: list[str]) -> bool:
    h = hashlib.sha256(code.strip().lower().encode()).hexdigest()
    return any(secrets.compare_digest(h, stored) for stored in hashed_codes)


def qr_png_b64(uri: str) -> str:
    """A QR code PNG as a base64 data URI, no CDN needed."""
    import base64
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
