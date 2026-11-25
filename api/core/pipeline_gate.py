"""One post-sync pipeline at a time. Each sync used to start its own, so three ran at once over the same devices:
the same work three times, fighting over the same rows, and never an idle moment for a deploy. A sync that ends
while one runs leaves its window here instead; the running pipeline takes it up when it finishes (the earliest
start wins, and a full rescore wins over any window). Without Redis each run just goes ahead, as before."""
from __future__ import annotations

import logging
import secrets

RUNNING, PENDING = "pipeline:running", "pipeline:pending"
FULL = "full"
TAKE_UP = "__pending__"   # the task argument that means "whatever is waiting"
TTL = 4 * 3600

# queue: keep the earliest window; "full" beats any window
_QUEUE = """
local cur = redis.call('GET', KEYS[1])
local new = ARGV[1]
if cur == 'full' then redis.call('EXPIRE', KEYS[1], ARGV[2]) return 0 end
if new == 'full' or (not cur) or new < cur then redis.call('SET', KEYS[1], new, 'EX', ARGV[2])
else redis.call('EXPIRE', KEYS[1], ARGV[2]) end   -- a later window folds in and keeps the wait alive
return 1
"""
_RELEASE = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0"


def client():
    try:
        import redis

        from api.core.config import get_settings
        r = redis.from_url(get_settings().redis_url, decode_responses=True, socket_timeout=5)
        r.ping()
        return r
    except Exception:  # noqa: BLE001 -- no gate without Redis: run as before
        return None


def acquire(r) -> str | None:
    token = secrets.token_hex(8)
    return token if r.set(RUNNING, token, nx=True, ex=TTL) else None


def queue(r, since: str | None) -> None:
    r.eval(_QUEUE, 1, PENDING, since or FULL, TTL)


def take(r) -> tuple[bool, str | None]:
    """(something was waiting, its window; None = full rescore)."""
    v = r.getdel(PENDING)
    if v is None:
        return False, None
    return True, None if v == FULL else v


def release(r, token: str) -> None:
    r.eval(_RELEASE, 1, RUNNING, token)


def refresh(r) -> None:
    r.expire(RUNNING, TTL)


def _heartbeat(r):
    """Keep the running mark alive through a long run (a full rescore of millions of findings outlasts its TTL)."""
    import threading
    stop = threading.Event()

    def beat():
        while not stop.wait(600):
            try:
                r.expire(RUNNING, TTL)
            except Exception:  # noqa: BLE001 -- Redis blipped; the next beat tries again
                logging.getLogger("open-ctem.tasks").warning("pipeline heartbeat missed (Redis?)")
    threading.Thread(target=beat, daemon=True, name="pipeline-heartbeat").start()
    return stop


def run_gated(since: str | None, run, requeue) -> None:
    """Run the pipeline now, or leave its window for the one that's running; keep going while windows wait.
    requeue(delay) starts another run later; a run that fails puts its window back first, so nothing is lost."""
    r = client()
    if r is None:
        return run(since)
    if since == TAKE_UP:
        waiting, since = take(r)
        if not waiting:
            return None
    token = acquire(r)
    if token is None:
        queue(r, since)
        return None
    stop, failed = _heartbeat(r), False
    try:
        while True:
            try:
                run(since)
            except Exception:
                failed = True
                queue(r, since)   # its window waits for the next run instead of vanishing
                raise
            waiting, since = take(r)
            if not waiting:
                break
            refresh(r)
    finally:
        stop.set()
        release(r, token)
        if r.exists(PENDING):   # queued meanwhile, or put back by a failed run (then after a pause, not in a spin)
            requeue(300 if failed else 0)
    return None


async def recalculate_changed(since: str):
    """The rescore a post-sync run does: devices whose score inputs changed since the sync began."""
    from datetime import datetime

    from api.core.db import get_session
    from api.scoring.engine import recalculate_changed
    async for db in get_session():
        await recalculate_changed(db, datetime.fromisoformat(since))
