"""The Vulnerability Dashboard's built views (api/core/vuln_dashboard.py builds them), kept in Redis.

Each filter combination is built once and kept for a week: every visit answers from the last build at once, and a
build older than CACHE_SECONDS or than the data is redone in the background. A view nobody has built yet is built
once however many people ask at the same moment, and a page request waits at most WAIT_SECONDS for it (the page asks
again), so no request is cut off by a proxy timeout and a hundred visitors never run a hundred builds."""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.vuln_dashboard")

CACHE_SECONDS = 1800   # a view older than this is rebuilt in the background while it is still shown
KEEP_SECONDS = 7 * 86400   # how long a built view is kept to answer from at once (a view nobody opens expires)
WAIT_SECONDS = 20   # how long a page request waits for a view being built before saying "still building"
_BUILDS: set = set()   # views being built in this process, kept referenced until done
_AT_ONCE = 2   # builds one app process runs at the same time; more wait their turn (each is a heavy query)
_slots = None


async def forget_cached() -> int:
    """After a sync changes the data: mark every cached Vulnerability Dashboard view out of date (the next visit gets
    it at once and a fresh one is rebuilt in the background, see cached()), and drop the custom dashboards' widget
    cache. Wiping the views instead made the next visitor wait for a full rebuild, up to 20 seconds."""
    import redis.asyncio as aioredis

    from api.core.config import get_settings
    r = aioredis.from_url(get_settings().redis_url)
    n = 0
    try:
        await r.set(vd.DIRTY_KEY, str(vd._now().timestamp()))
        async for key in r.scan_iter(match="dashw:*", count=500):
            n += await r.delete(key)
    except Exception:  # noqa: BLE001 -- a stale view for a few more minutes is the worst case
        log.warning("dashboard cache not cleared")
    finally:
        await r.aclose()
    return n


def _rebuild_later(source, device_type, kind, viewer, code=None) -> None:
    try:
        from api.core.tasks import refresh_vuln_view
        refresh_vuln_view.delay(source, device_type, kind, viewer, code)
    except Exception:  # noqa: BLE001 -- the view runs out within CACHE_SECONDS anyway
        log.warning("vuln dashboard rebuild not queued")


def sliced(out: dict, range_key: str) -> dict:
    """The trend cut to the chosen range."""
    days = vd.RANGES.get(range_key)
    tr = out["trend"]
    if days and len(tr["days"]) > days:
        tr = {k: v[-days:] for k, v in tr.items()}
    return {**out, "trend": tr, "range": range_key}


async def cached(db: AsyncSession, range_key: str, source: str | None, device_type: str | None, fresh: bool = False,
                 scope=None, viewer: str | None = None, kind: str = "all", code: dict | None = None, access: str = "",
                 wait: float | None = None) -> dict | None:
    """Each filter combination is built once and kept: a visit answers from the last build at once, and a build
    older than CACHE_SECONDS (or than the data) is redone in the background. When nothing is built yet, one build
    runs no matter how many people ask. wait: a page request waits that long for it and gets None if it isn't done
    (the page asks again); None builds here and waits for it (dashboard widgets, the scheduler)."""
    import redis.asyncio as aioredis

    from api.core.config import get_settings
    # a scoped viewer's numbers are theirs alone, so their cache entry is too
    kind = kind if kind in vd.KINDS else "all"
    code = {k: v for k, v in (code or {}).items() if v} if kind == "code" else {}
    code_key = "-"
    if code:   # names can be long and hold ":"; a digest keeps the key short and unambiguous
        import hashlib
        code_key = hashlib.sha256(json.dumps(code, sort_keys=True, default=sorted).encode()).hexdigest()[:24]
    # a scoped viewer's entry also carries what they may see now, so losing access is never answered from a cache
    key = f"vulndash:v5:{kind}:{source or '-'}:{device_type or '-'}:{f'{viewer}.{access}' if scope is not None else 'all'}"
    if code:
        key += f":c:{code_key}"
    args = (source, device_type, scope, kind, code or None)
    r = aioredis.from_url(get_settings().redis_url)
    try:
        try:
            if scope is not None and viewer and not fresh and not source and not device_type and not code:
                await r.zadd(vd.VIEWERS_KEY, {viewer: time.time()})   # warmed by warm() while they keep coming back
            hit = None if fresh else await r.get(key)
            if hit:
                out = json.loads(hit)
                built = datetime.fromisoformat(out["generated_at"]).timestamp()
                dirty = await r.get(vd.DIRTY_KEY)
                if (dirty and built < float(dirty)) or time.time() - built > CACHE_SECONDS:
                    # out of date: answer now with it, and rebuild once in the background
                    if await r.set(f"vulndash:rebuilding:{key}", "1", nx=True, ex=600):
                        vd._rebuild_later(source, device_type, kind, viewer if scope is not None else None, code or None)
                return sliced(out, range_key)
            if not fresh:
                got, mine = await _shared_build(r, key, args, wait)
                if got is not None or wait is not None:
                    return sliced(got, range_key) if got is not None else None
                if mine:   # the scheduler or a widget: build it here, and let anyone waiting have it
                    try:
                        out = await vd.build(db, *args)
                        await _store(r, key, out)
                        return sliced(out, range_key)
                    finally:
                        await r.delete(f"vulndash:building:{key}")
        except Exception:  # noqa: BLE001 -- no Redis means no cache, not no dashboard
            log.warning("vuln dashboard cache unavailable")
        out = await vd.build(db, *args)
        await _store(r, key, out)
        return sliced(out, range_key)
    finally:
        await r.aclose()


async def _store(r, key: str, out: dict) -> None:
    try:
        await r.set(key, json.dumps(out, default=str), ex=KEEP_SECONDS)
    except Exception:  # noqa: BLE001 -- the answer is still good, it just won't be cached
        log.warning("vuln dashboard result not cached")


async def _shared_build(r, key: str, args: tuple, wait: float | None) -> tuple[dict | None, bool]:
    """A view nobody has built yet: one build at a time per view, and everyone asking waits on its result.
    (result, mine): mine when the caller (wait None) holds the build and should run it itself. A page request's
    build runs in the background of this process, so the request isn't cut off by a proxy timeout; the result is
    None when it isn't done within `wait` (the page asks again)."""
    import asyncio
    lock = f"vulndash:building:{key}"
    if await r.set(lock, "1", nx=True, ex=300):
        if wait is None:
            return None, True
        task = asyncio.create_task(_build_and_store(key, lock, args))
        _BUILDS.add(task)
        task.add_done_callback(_BUILDS.discard)
    end = time.monotonic() + (wait if wait is not None else 300)
    while time.monotonic() < end:
        await asyncio.sleep(0.5)
        hit = await r.get(key)
        if hit:
            return json.loads(hit), False
        if not await r.exists(lock):   # the build ended without a result: it failed
            return None, False
    return None, False


async def _build_and_store(key: str, lock: str, args: tuple) -> None:
    import redis.asyncio as aioredis

    from api.core.config import get_settings
    from api.core.db import get_session
    global _slots
    import asyncio
    _slots = _slots or asyncio.Semaphore(_AT_ONCE)
    r = aioredis.from_url(get_settings().redis_url)
    try:
        async with _slots:
            async for db in get_session():
                await _store(r, key, await vd.build(db, *args))
                break
    except Exception:  # noqa: BLE001 -- logged; the next visit tries again
        log.exception("vuln dashboard view not built")
    finally:
        try:
            await r.delete(lock)
        finally:
            await r.aclose()


async def warm(db: AsyncSession, refresh) -> None:
    """Every 15 minutes: the unfiltered views, then the tabs of each person with scoped access who opened the
    dashboard in the last week, so their first click doesn't wait for a build (about 12s on a large fleet)."""
    import redis.asyncio as aioredis

    from api.core.config import get_settings
    await cached(db, "90d", None, None, fresh=True)                  # dashboards' widgets: every finding
    for kind in ("infra", "code", "web", "cloud"):                  # the Vulnerability Dashboard's tabs
        await cached(db, "90d", None, None, fresh=True, kind=kind)
    r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        await r.zremrangebyscore(vd.VIEWERS_KEY, 0, time.time() - vd.VIEWER_DAYS * 86400)
        viewers = await r.zrevrange(vd.VIEWERS_KEY, 0, vd.MAX_WARM_VIEWERS - 1)
    except Exception:  # noqa: BLE001 -- no Redis, no warming; the page still builds on demand
        log.warning("scoped dashboard viewers not read")
        return
    finally:
        await r.aclose()
    for v in viewers:
        for kind in ("infra", "code", "web", "cloud"):
            try:
                await refresh(None, None, kind, v)
            except Exception:  # noqa: BLE001 -- one person's view failing doesn't stop the rest
                log.exception("scoped dashboard view not warmed")


from api.core import vuln_dashboard as vd  # noqa: E402 -- last, so either module can be imported first
