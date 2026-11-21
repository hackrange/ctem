"""Server utilization: CPU, memory and disk, live and over time, plus where CTEM's storage goes.

Host numbers come from /proc and the filesystem (a container shares the host's /proc/stat, /proc/meminfo and,
on the same disk, its free space), so no Docker socket is ever needed: that would hand the app the host.
A beat job records a row a minute (kept 2 days) and rolls them into hours (kept 400 days)."""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.utilization")
KEEP = {"m": timedelta(days=2), "h": timedelta(days=400)}
RANGES = {"1h": (timedelta(hours=1), "m"), "24h": (timedelta(days=1), "m"), "7d": (timedelta(days=7), "h"),
          "30d": (timedelta(days=30), "h"), "365d": (timedelta(days=365), "h")}
DISK_PATH = os.environ.get("CTEM_UTIL_DISK_PATH", "/")
WARN_PCT, BAD_PCT = 80, 90


def _read(path: str) -> str:
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return ""


def parse_stat(textv: str) -> tuple[int, int] | None:
    """(total, idle) jiffies from the first line of /proc/stat."""
    line = next((ln for ln in textv.splitlines() if ln.startswith("cpu ")), None)
    if not line:
        return None
    try:
        n = [int(x) for x in line.split()[1:9]]
    except ValueError:
        return None
    if len(n) < 4:
        return None
    return sum(n), n[3] + (n[4] if len(n) > 4 else 0)


def cpu_percent(a, b) -> float | None:
    if not a or not b or b[0] <= a[0]:
        return None
    total = b[0] - a[0]
    return round(max(0.0, min(100.0, 100.0 * (total - (b[1] - a[1])) / total)), 2)


def parse_meminfo(textv: str) -> tuple[int, int] | None:
    """(used, total) bytes: total minus what the kernel could hand back (MemAvailable)."""
    vals = {}
    for ln in textv.splitlines():
        k, _, rest = ln.partition(":")
        if k in ("MemTotal", "MemAvailable"):
            try:
                vals[k] = int(rest.split()[0]) * 1024
            except (ValueError, IndexError):
                pass
    if "MemTotal" not in vals or "MemAvailable" not in vals:
        return None
    return max(0, vals["MemTotal"] - vals["MemAvailable"]), vals["MemTotal"]


def disk(path: str = DISK_PATH) -> tuple[int, int]:
    """(used, usable size) bytes of the filesystem holding `path`, the way df counts them: the blocks reserved
    for root are left out, because PostgreSQL can't write to them, so 100% is when it stops."""
    try:
        s = os.statvfs(path)
    except OSError:
        return 0, 0
    used = (s.f_blocks - s.f_bfree) * s.f_frsize
    return used, used + s.f_bavail * s.f_frsize


def sample(window: float = 0.5) -> dict:
    """CPU over a short window, memory and disk right now. Blocking; call it in a thread."""
    a = parse_stat(_read("/proc/stat"))
    time.sleep(window)
    b = parse_stat(_read("/proc/stat"))
    mem = parse_meminfo(_read("/proc/meminfo")) or (None, None)
    du, dt = disk()
    return {"at": datetime.now(timezone.utc).isoformat(), "cpu": cpu_percent(a, b), "cpus": os.cpu_count() or 1,
            "mem_used": mem[0], "mem_total": mem[1], "disk_used": du, "disk_total": dt,
            "load": list(os.getloadavg()) if hasattr(os, "getloadavg") else None}


async def _scalar(db: AsyncSession, sql: str):
    """One number from a read-only catalog query; None if this role may not ask (it never aborts the session)."""
    try:
        async with db.begin_nested():
            return (await db.execute(text(sql))).scalar()
    except Exception:
        return None


async def redis_bytes() -> tuple[int | None, int | None]:
    try:
        import redis.asyncio as aioredis

        from api.core.config import get_settings
        r = aioredis.from_url(get_settings().redis_url)
        info = await r.info("memory")
        await r.aclose()
        return int(info.get("used_memory") or 0), int(info.get("maxmemory") or 0) or None
    except Exception:
        return None, None


async def storage(db: AsyncSession) -> dict:
    """Where the space goes: the disk, every database on the server, CTEM's biggest tables, its WAL, Redis."""
    du, dt = disk()
    dbs = []
    try:
        async with db.begin_nested():
            dbs = [{"name": n, "bytes": int(b)} for n, b in (await db.execute(text(
                "SELECT datname, pg_database_size(datname) FROM pg_database WHERE NOT datistemplate "
                "ORDER BY 2 DESC LIMIT 20"))).all()]
    except Exception as e:   # this role may not list every database; the rest of the page still works
        log.debug("database sizes unavailable: %s", type(e).__name__)
    tables = []
    try:
        async with db.begin_nested():
            tables = [{"name": n, "bytes": int(t), "data": int(d), "indexes": int(i), "rows": max(0, int(r or 0))}
                      for n, t, d, i, r in (await db.execute(text(
                          "SELECT c.relname, pg_total_relation_size(c.oid), pg_relation_size(c.oid), pg_indexes_size(c.oid), "
                          "c.reltuples::bigint FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                          "WHERE c.relkind IN ('r', 'p') AND n.nspname = 'public' "
                          "ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 12"))).all()]
    except Exception as e:
        log.debug("table sizes unavailable: %s", type(e).__name__)
    rb, rmax = await redis_bytes()
    return {"disk": {"path": DISK_PATH, "used": du, "total": dt, "pct": round(100 * du / dt, 1) if dt else None,
                     "free": dt - du if dt else None},
            "database": {"bytes": await _scalar(db, "SELECT pg_database_size(current_database())"),
                         "wal_bytes": await _scalar(db, "SELECT COALESCE(SUM(size), 0) FROM pg_ls_waldir()"),
                         "all": dbs, "tables": tables},
            "redis": {"bytes": rb, "max": rmax}, "warn_pct": WARN_PCT, "bad_pct": BAD_PCT}


async def record(db: AsyncSession) -> None:
    """The beat job: one minute row, then the hour rollup and the purge."""
    import asyncio

    from api.models.utilization import UtilSample
    s = await asyncio.to_thread(sample, 1.0)
    rb, _ = await redis_bytes()
    dbb = await _scalar(db, "SELECT pg_database_size(current_database())")
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    await db.merge(UtilSample(tier="m", ts=now, host_cpu=s["cpu"], host_cpu_max=s["cpu"], mem_used=s["mem_used"],
                              mem_total=s["mem_total"], disk_used=s["disk_used"], disk_total=s["disk_total"],
                              db_bytes=dbb, redis_bytes=rb))
    await db.commit()
    await rollup(db, now)


async def rollup(db: AsyncSession, now: datetime) -> None:
    """Average the last two hours of minutes into hour rows (rerunning just rewrites them), then purge."""
    from api.models.utilization import UtilSample as U
    for h in range(2):
        start = now.replace(minute=0) - timedelta(hours=h)
        rows = (await db.execute(select(func.avg(U.host_cpu), func.max(U.host_cpu_max), func.avg(U.mem_used),
                                        func.max(U.mem_total), func.avg(U.disk_used), func.max(U.disk_total),
                                        func.avg(U.db_bytes), func.avg(U.redis_bytes), func.count())
                                 .where(U.tier == "m", U.ts >= start, U.ts < start + timedelta(hours=1)))).one()
        if not rows[-1]:
            continue
        num = lambda v: int(v) if v is not None else None  # noqa: E731
        await db.merge(U(tier="h", ts=start, host_cpu=round(float(rows[0]), 2) if rows[0] is not None else None,
                         host_cpu_max=rows[1], mem_used=num(rows[2]), mem_total=num(rows[3]), disk_used=num(rows[4]),
                         disk_total=num(rows[5]), db_bytes=num(rows[6]), redis_bytes=num(rows[7])))
    for tier, keep in KEEP.items():
        await db.execute(delete(U).where(U.tier == tier, U.ts < now - keep))
    await db.commit()


def days_until_full(points: list[dict]) -> float | None:
    """Least-squares trend of disk use over the points; None if flat, shrinking or too little history."""
    pts = [(datetime.fromisoformat(p["t"]).timestamp(), p["disk_used"], p["disk_total"]) for p in points
           if p.get("disk_used") and p.get("disk_total")]
    if len(pts) < 6 or pts[-1][0] - pts[0][0] < 6 * 3600:
        return None
    n = len(pts)
    mx, my = sum(p[0] for p in pts) / n, sum(p[1] for p in pts) / n
    var = sum((p[0] - mx) ** 2 for p in pts)
    if not var:
        return None
    slope = sum((p[0] - mx) * (p[1] - my) for p in pts) / var   # bytes per second
    if slope <= 0:
        return None
    left = pts[-1][2] - pts[-1][1]
    return round(left / slope / 86400, 1)


async def history(db: AsyncSession, range_key: str) -> dict:
    from api.models.utilization import UtilSample as U
    span, tier = RANGES[range_key]
    since = datetime.now(timezone.utc) - span
    rows = (await db.execute(select(U).where(U.tier == tier, U.ts >= since).order_by(U.ts))).scalars().all()
    if tier == "h" and len(rows) < 3:   # young install: fall back to minutes until hours accumulate
        rows = (await db.execute(select(U).where(U.tier == "m", U.ts >= since).order_by(U.ts))).scalars().all()
    pts = [{"t": r.ts.isoformat(), "cpu": r.host_cpu, "cpu_max": r.host_cpu_max, "mem_used": r.mem_used,
            "mem_total": r.mem_total, "disk_used": r.disk_used, "disk_total": r.disk_total, "db_bytes": r.db_bytes,
            "redis_bytes": r.redis_bytes} for r in rows]
    trend = pts
    if range_key in ("1h", "24h"):   # project from a week when there is one
        week = (await db.execute(select(U).where(U.tier == "h", U.ts >= datetime.now(timezone.utc) - timedelta(days=7))
                                 .order_by(U.ts))).scalars().all()
        if len(week) >= 6:
            trend = [{"t": r.ts.isoformat(), "disk_used": r.disk_used, "disk_total": r.disk_total} for r in week]
    return {"range": range_key, "points": pts, "days_until_full": days_until_full(trend)}
