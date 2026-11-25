"""Step-up: prove it's still you before a backup leaves the server or a restore replaces it, and before an admin
grants the admin role, sets another account's password or replaces or removes its authenticator.

Local accounts re-enter their password (and TOTP code when enrolled). SSO-only accounts without TOTP must have
signed in within the last 10 minutes. A pass lasts 10 minutes and lives in the signed session cookie, bound to the
user id. API tokens never qualify: these actions need a person at a browser.
"""
from __future__ import annotations

import logging
import re
import time

from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

from api.auth.local import _redis, verify_password, verify_totp
from api.models.user import User

log = logging.getLogger("open-ctem.step_up")
STEP_UP_SECONDS = 600
SSO_FRESH_SECONDS = 600
FAIL_LIMIT = 5
FAIL_WINDOW = 900


def browser_only(request: Request) -> None:
    if request.headers.get("authorization", "").lower().startswith("bearer "):
        raise HTTPException(403, detail="This needs a signed-in browser session, not an API token.")


def needs(user: User) -> list[str]:
    out = []
    if user.password_hash:
        out.append("password")
    if user.totp_enabled and user.totp_secret:
        out.append("code")
    return out


def active_until(request: Request, user: User) -> int | None:
    v = request.session.get("step_up")
    if isinstance(v, dict) and v.get("uid") == str(user.id) and isinstance(v.get("until"), int) and v["until"] > time.time():
        return v["until"]
    return None


def require(request: Request, user: User) -> None:
    browser_only(request)
    if active_until(request, user) is None:
        raise HTTPException(403, detail="Confirm it's you first.",
                            headers={"X-Step-Up": "required", "X-Step-Up-Needs": ",".join(needs(user)) or "sso"})


async def _failures(key: str, add: bool = False) -> int:
    # The per-IP limiter on this path still applies if Redis is down; this one is per account
    try:
        r = _redis()
        if add:
            n = int(await r.incr(key))
            await r.expire(key, FAIL_WINDOW)
            return n
        return int(await r.get(key) or 0)
    except Exception:  # noqa: BLE001
        log.warning("step-up failure counter unavailable (Redis)")
        return 0


async def _clear(key: str) -> None:
    try:
        await _redis().delete(key)
    except Exception:  # noqa: BLE001
        log.warning("could not clear the step-up failure counter (Redis)")


async def verify(request: Request, user: User, password: object, code: object) -> int:
    """Check the second look; on success return when the pass expires."""
    browser_only(request)
    key = f"stepup_fail:{user.id}"
    if await _failures(key) >= FAIL_LIMIT:
        raise HTTPException(429, detail="Too many tries. Wait 15 minutes and try again.")
    fields = needs(user)
    if not fields:
        signed = request.session.get("signed_in_at")
        if not isinstance(signed, int) or time.time() - signed > SSO_FRESH_SECONDS:
            raise HTTPException(403, detail="Sign out and back in, then try again within 10 minutes.")
    if "password" in fields:
        pw = password if isinstance(password, str) and len(password) <= 1024 else ""
        if not pw or not await run_in_threadpool(verify_password, pw, user.password_hash):
            await _failures(key, add=True)
            raise HTTPException(401, detail="That password is not right.")
    if "code" in fields:
        c = code.strip() if isinstance(code, str) else ""
        if not re.fullmatch(r"[0-9]{6}", c):   # \d would also take Unicode digits
            await _failures(key, add=True)
            raise HTTPException(401, detail="Enter the 6-digit code from your authenticator app.")
        await verify_totp(user.username, c, user.totp_secret)   # its own lockout and replay guard
    await _clear(key)
    until = int(time.time()) + STEP_UP_SECONDS
    request.session["step_up"] = {"uid": str(user.id), "until": until}
    return until
