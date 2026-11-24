"""Ending browser sessions on the server, not just in the browser that asked.

  - signing out ends that session for good: its id is remembered (Redis) until it would have expired anyway, so a
    copy of the cookie stops working too
  - a new password (changed by its owner or reset by an admin) ends every other session of that account: each
    session carries when it signed in, and one from before users.sessions_valid_after no longer counts
Without Redis, sign-out still clears the browser's cookie and a new password still ends the other sessions."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from fastapi import HTTPException, Request

log = logging.getLogger("open-ctem.auth.sessions")
EPOCH = "auth_ms"   # when this session's credentials were proven, in milliseconds


def _ms() -> int:
    return time.time_ns() // 1_000_000


def started(request: Request) -> None:
    """At sign-in: when this session's credentials were proven."""
    request.session[EPOCH] = _ms()


def new_password(request: Request, user) -> None:
    """A new password ends this account's other sessions; the one that changed it (if it's theirs) stays."""
    now = _ms()
    user.sessions_valid_after = datetime.fromtimestamp(now / 1000, timezone.utc)
    if request.session.get("user_id") == str(user.id):
        request.session[EPOCH] = now


def _key(sid: str) -> str:
    return f"session_ended:{sid}"


async def end(request: Request) -> None:
    """Sign-out: this session can't be used again, from this browser or any copy of its cookie."""
    from api.auth.local import _redis
    from api.core.config import get_settings
    sid = request.session.get("session_id")
    if isinstance(sid, str) and sid:
        try:
            await _redis().set(_key(sid), "1", ex=max(get_settings().session_max_hours, 1) * 3600)
        except Exception:  # noqa: BLE001 -- the cookie is still cleared below
            log.warning("signed-out session not recorded (Redis); the browser's cookie is cleared")
    request.session.clear()


async def check(request: Request, user) -> None:
    """For a browser session: refuse one that was signed out or predates the account's latest password."""
    epoch = request.session.get(EPOCH)
    if not isinstance(epoch, int) and isinstance(request.session.get("signed_in_at"), int):
        epoch = request.session["signed_in_at"] * 1000   # a session from before this was kept
    after = user.sessions_valid_after
    if after is not None:
        after = after if after.tzinfo else after.replace(tzinfo=timezone.utc)
        if not isinstance(epoch, int) or epoch < round(after.timestamp() * 1000):
            request.session.clear()
            raise HTTPException(401, detail="Session ended; sign in again")
    sid = request.session.get("session_id")
    if isinstance(sid, str) and sid:
        from api.auth.local import _redis
        try:
            ended = await _redis().exists(_key(sid))
        except Exception:  # noqa: BLE001 -- fail open: signing in must not depend on Redis
            log.warning("signed-out sessions not checked (Redis)")
            return
        if ended:
            request.session.clear()
            raise HTTPException(401, detail="Session ended; sign in again")
