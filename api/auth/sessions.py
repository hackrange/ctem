"""Ending browser sessions on the server, not just in the browser that asked.

  - signing out ends that session for good: its id is remembered (Redis) until it would have expired anyway, so a
    copy of the cookie stops working too
  - a new password (changed by its owner or reset by an admin) ends every other session of that account: each
    session carries when it signed in, and one from before users.sessions_valid_after no longer counts
Every sign-out is also written to the database (ended_sessions), read only when Redis can't be, so a signed-out
cookie stays dead through a Redis outage that starts later. Without Redis at sign-out, the browser's cookie is still
cleared, the ended id is kept in this process too, and the account's sessions_valid_after moves to now, so a copy of
the cookie stops working in every process even once Redis is back (the account's other sessions end with it: signing
in again is the cost, never a replayable session). A new password still ends the other sessions."""
from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request

log = logging.getLogger("open-ctem.auth.sessions")
EPOCH = "auth_ms"   # when this session's credentials were proven, in milliseconds
_LOCAL_MAX = 20_000   # ended session ids kept in this process (oldest dropped first)
_local_ended: dict[str, float] = {}   # session id -> monotonic time it stops mattering


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


def _remember(sid: str, ttl: float) -> None:
    now = time.monotonic()
    for k in [k for k, until in _local_ended.items() if until <= now]:
        del _local_ended[k]
    while len(_local_ended) >= _LOCAL_MAX:
        del _local_ended[next(iter(_local_ended))]
    _local_ended[sid] = now + ttl


def _ended_here(sid: str) -> bool:
    until = _local_ended.get(sid)
    return until is not None and until > time.monotonic()


async def _end_all_in_db(request: Request, db) -> None:
    """Redis is down: end this account's sessions through the database, which every process reads."""
    from api.models.user import User
    uid = request.session.get("user_id")
    if db is None or not isinstance(uid, str) or not uid:
        return
    try:
        user = await db.get(User, uid)
        if user is not None:
            user.sessions_valid_after = datetime.fromtimestamp(_ms() / 1000, timezone.utc)
            await db.commit()
    except Exception:  # noqa: BLE001 -- the cookie is still cleared, and this process still refuses the id
        log.warning("signed-out session not recorded in the database either", exc_info=True)


def _sid_hash(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def _record_in_db(sid: str, ttl: int, db) -> None:
    """Durable copy of the sign-out, for when Redis can't be read later. Expired ones are cleared as we go."""
    from sqlalchemy import delete
    from api.models.user import EndedSession
    if db is None:
        return
    try:
        now = _utcnow()
        await db.execute(delete(EndedSession).where(EndedSession.until < now))
        await db.merge(EndedSession(sid_hash=_sid_hash(sid), until=now + timedelta(seconds=ttl)))
        await db.commit()
    except Exception:  # noqa: BLE001 -- Redis (or the fallback below) still records it
        log.warning("signed-out session not recorded in the database", exc_info=True)
        try:
            await db.rollback()
        except Exception:  # noqa: BLE001
            log.debug("rollback after the failed sign-out record also failed", exc_info=True)


async def _ended_in_db(sid: str, db) -> bool:
    """Redis is unreadable: was this session signed out? Unknown (no database handle, or the query failed) counts
    as signed in, as before; a request that got this far has just read its account from the database."""
    from sqlalchemy import select
    from api.models.user import EndedSession
    if db is None:
        return False
    try:
        row = (await db.execute(select(EndedSession.until).where(EndedSession.sid_hash == _sid_hash(sid)))).first()
    except Exception:  # noqa: BLE001
        log.warning("signed-out sessions not checked (Redis and database)", exc_info=True)
        return False
    return row is not None and row[0] > _utcnow()


async def end(request: Request, db=None) -> None:
    """Sign-out: this session can't be used again, from this browser or any copy of its cookie."""
    from api.auth.local import _redis
    from api.core.config import get_settings
    sid = request.session.get("session_id")
    if isinstance(sid, str) and sid:
        ttl = max(get_settings().session_max_hours, 1) * 3600
        _remember(sid, ttl)
        await _record_in_db(sid, ttl, db)
        try:
            await _redis().set(_key(sid), "1", ex=ttl)
        except Exception:  # noqa: BLE001 -- the cookie is still cleared below
            log.warning("signed-out session not recorded (Redis); ending the account's sessions in the database")
            await _end_all_in_db(request, db)
    request.session.clear()


async def check(request: Request, user, db=None) -> None:
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
        if _ended_here(sid):
            request.session.clear()
            raise HTTPException(401, detail="Session ended; sign in again")
        from api.auth.local import _redis
        try:
            ended = await _redis().exists(_key(sid))
        except Exception:  # noqa: BLE001 -- signing in must not depend on Redis; the database copy answers instead
            log.warning("signed-out sessions checked in the database (Redis unreadable)")
            ended = await _ended_in_db(sid, db)
        if ended:
            request.session.clear()
            raise HTTPException(401, detail="Session ended; sign in again")
