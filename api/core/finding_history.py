"""Keep what findings tell us over time without keeping every finding (Admin > Data retention).

Daily, before anything is removed:
- each device's open, critical and high counts are written when they changed (DeviceDailyCount), so its trend line
  reaches back a year. The first run fills that year in from the findings as they stand (backfill).
- remediated findings last seen more than `remediated_days` ago (90 by default) are added to FindingRollup, by day
  found and day fixed, source, kind of work, severity and KEV, and then removed. The org-wide trend, fix counts
  and mean time to remediate read the rollup for those days, so their history stays whole. Views filtered to a
  device type, a tag scope or a repository have only the retention window, since the rollup doesn't know devices.
- risk score history older than a year keeps one entry per entity per week (the week's last).

Device trend and dashboards treat a day as UTC."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import delete, func, select, tuple_

log = logging.getLogger("open-ctem.finding_history")
BATCH = 5000            # findings removed per transaction
MAX_BATCHES = 1000      # per run, so a first run on a big install ends; the next day carries on
SCORE_KEEP_DAYS = 365
STATE_KEY = "finding_history"   # app setting: {"backfilled": "YYYY-MM-DD"}


def sev_of(cvss) -> str:
    c = cvss or 0
    return "critical" if c >= 9 else "high" if c >= 7 else "medium" if c >= 4 else "low"


def _day(dt) -> date | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).date()


def _today() -> date:
    return datetime.now(timezone.utc).date()


async def state(db) -> dict:
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == STATE_KEY))).scalar_one_or_none()
    try:
        return json.loads(row.value) if row and row.value else {}
    except ValueError:
        return {}


async def _set_state(db, **kw) -> None:
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == STATE_KEY))).scalar_one_or_none()
    val = json.dumps({**(await state(db)), **kw})
    if row is None:
        db.add(AppSetting(key=STATE_KEY, value=val))
    else:
        row.value = val


# ── Device counts ─────────────────────────────────────────────────────────────

async def _write_changes(db, day: date, now: dict, before: dict) -> int:
    from api.models.finding_history import DeviceDailyCount
    rows = [{"device_id": d, "day": day, "open": v[0], "critical": v[1], "high": v[2]}
            for d, v in now.items() if v != before.get(d, (0, 0, 0))]
    rows += [{"device_id": d, "day": day, "open": 0, "critical": 0, "high": 0}
             for d, v in before.items() if d not in now and v != (0, 0, 0)]
    for i in range(0, len(rows), 1000):
        await db.execute(DeviceDailyCount.__table__.insert(), rows[i:i + 1000])
    return len(rows)


async def snapshot_devices(db, day: date | None = None) -> int:
    """Today's counts for every device whose counts changed since its last row. Running twice a day rewrites the day."""
    from api.models.finding_history import DeviceDailyCount as C
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    day = day or _today()
    cv = Vulnerability.cvss_base
    cur = (await db.execute(
        select(Finding.device_id, func.count(), func.count().filter(cv >= 9), func.count().filter(cv >= 7, cv < 9))
        .join(Vulnerability, Vulnerability.id == Finding.vuln_id)
        .where(Finding.status.in_((FindingStatus.open, FindingStatus.in_progress)), Finding.first_detected.is_not(None))
        .group_by(Finding.device_id))).all()
    last = select(C.device_id, func.max(C.day).label("d")).where(C.day < day).group_by(C.device_id).subquery()
    prev = (await db.execute(select(C.device_id, C.open, C.critical, C.high)
                             .join(last, (last.c.device_id == C.device_id) & (last.c.d == C.day)))).all()
    await db.execute(delete(C).where(C.day == day))
    return await _write_changes(db, day, {d: (o, c, h) for d, o, c, h in cur}, {d: (o, c, h) for d, o, c, h in prev})


async def backfill_devices(db, days: int = 365) -> int:
    """Once, before the first removal: a year of each device's counts, rebuilt from its findings, as change rows."""
    from api.models.finding_history import DeviceDailyCount as C
    from api.models.vuln import Finding, Vulnerability
    from api.routes.device_trend import series
    end = _today() - timedelta(days=1)
    start = end - timedelta(days=days - 1)
    await db.execute(delete(C).where(C.day <= end))
    devices = (await db.execute(select(Finding.device_id).where(Finding.first_detected.is_not(None))
                                .group_by(Finding.device_id))).scalars().all()
    written = 0
    for i in range(0, len(devices), 500):
        part = devices[i:i + 500]
        per: dict = {}
        for d_id, first, last, status, cvss in (await db.execute(
                select(Finding.device_id, Finding.first_detected, Finding.last_seen, Finding.status, Vulnerability.cvss_base)
                .join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                .where(Finding.device_id.in_(part), Finding.first_detected.is_not(None)))).all():
            per.setdefault(d_id, []).append((first, last, status, cvss))
        out = []
        for d_id, rows in per.items():
            s, was = series(rows, start, end), (0, 0, 0)
            for j, d in enumerate(s["days"]):
                v = (s["open"][j], s["critical"][j], s["high"][j])
                if v != was:
                    out.append({"device_id": d_id, "day": date.fromisoformat(d), "open": v[0], "critical": v[1], "high": v[2]})
                    was = v
        for j in range(0, len(out), 1000):
            await db.execute(C.__table__.insert(), out[j:j + 1000])
        written += len(out)
    return written


async def device_counts(db, device_id: str, start: date, end: date) -> list[tuple[int, int, int]]:
    """Counts per day from the change rows: a day with no row carries the row before it (none before means 0)."""
    from api.models.finding_history import DeviceDailyCount as C
    base = (await db.execute(select(C.open, C.critical, C.high).where(C.device_id == device_id, C.day < start)
                             .order_by(C.day.desc()).limit(1))).first()
    rows = {d: (o, c, h) for d, o, c, h in (await db.execute(
        select(C.day, C.open, C.critical, C.high).where(C.device_id == device_id, C.day >= start, C.day <= end))).all()}
    cur, out, d = tuple(base) if base else (0, 0, 0), [], start
    while d <= end:
        cur = rows.get(d, cur)
        out.append(cur)
        d += timedelta(days=1)
    return out


# ── Removing remediated findings ──────────────────────────────────────────────

async def _add_rollup(db, agg: dict) -> None:
    from api.models.finding_history import FindingRollup as R
    days = {k[1] for k in agg}
    have = {(r.kind, r.day, r.source, r.domain, r.severity, r.kev): r
            for r in (await db.execute(select(R).where(R.day.in_(days)))).scalars()}
    for k, (n, timed, took) in agg.items():
        r = have.get(k)
        if r is None:
            db.add(R(kind=k[0], day=k[1], source=k[2], domain=k[3], severity=k[4], kev=k[5], n=n, timed=timed, fix_days=took))
        else:
            r.n, r.timed, r.fix_days = r.n + n, r.timed + timed, r.fix_days + took


async def purge_remediated(db, keep_days: int) -> int:
    """Roll up, then remove, remediated findings last seen before the window. Each batch is one transaction."""
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    if not (await state(db)).get("backfilled"):
        n = await backfill_devices(db)
        await _set_state(db, backfilled=_today().isoformat())
        await db.commit()
        log.info("device count history filled in: %d rows", n)
    cut = datetime.now(timezone.utc) - timedelta(days=keep_days)
    removed = 0
    for _ in range(MAX_BATCHES):
        rows = (await db.execute(
            select(Finding.id, Finding.source, Finding.domain, Finding.first_detected, Finding.last_seen,
                   Vulnerability.cvss_base, Vulnerability.is_kev)
            .join(Vulnerability, Vulnerability.id == Finding.vuln_id)
            .where(Finding.status == FindingStatus.remediated, Finding.last_seen < cut).limit(BATCH))).all()
        if not rows:
            break
        agg: dict = {}
        for _id, src, dom, first, last, cvss, kev in rows:
            dims = (str(src or ""), dom or "", sev_of(cvss), bool(kev))
            if first is not None:
                k = ("new", _day(first), *dims)
                agg[k] = (agg.get(k, (0, 0, 0.0))[0] + 1, 0, 0.0)
            k = ("fixed", _day(last), *dims)
            n, timed, took = agg.get(k, (0, 0, 0.0))
            if first is not None:
                timed, took = timed + 1, took + max((last - first).total_seconds(), 0) / 86400
            agg[k] = (n + 1, timed, took)
        await _add_rollup(db, agg)
        ids = [r[0] for r in rows]
        for i in range(0, len(ids), 500):
            await db.execute(delete(Finding).where(Finding.id.in_(ids[i:i + 500])))
        await db.commit()
        removed += len(ids)
    return removed


async def thin_score_history(db, keep_days: int = SCORE_KEEP_DAYS) -> int:
    """Entries older than the window keep one per entity per week (the week's last); the rest are removed."""
    from api.models.risk import RiskScoreHistory as H
    cut = datetime.now(timezone.utc) - timedelta(days=keep_days)
    rows = (await db.execute(select(H.entity_type, H.entity_id, H.recorded_at).where(H.recorded_at < cut)
                             .order_by(H.recorded_at).limit(500_000))).all()
    last: dict = {}
    for t, i, at in rows:                                   # ordered by time, so each week ends on its last entry
        last[(t, i, _day(at).isocalendar()[:2])] = at
    drop = [(t, i, at) for t, i, at in rows if last[(t, i, _day(at).isocalendar()[:2])] != at]
    for j in range(0, len(drop), 500):
        await db.execute(delete(H).where(tuple_(H.entity_type, H.entity_id, H.recorded_at).in_(drop[j:j + 500])))
    return len(drop)


# ── Reading the rollup ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Roll:
    """Which rolled-up findings a view covers: its sources, kind of work, severities and KEV filter."""
    sources: tuple = ()
    domain: str | None = None
    severities: tuple = ()
    kev_only: bool = False


SEV_PICKS = {"critical": ("critical",), "high": ("high",), "medium": ("medium",), "low": ("low",),
             "critical_high": ("critical", "high")}


def roll_for(sources=None, device_type=None, scope=None, kind: str = "all", code=None, severity: str = "any",
             kev_only: bool = False) -> Roll | None:
    """The rollup a view may add, or None when it is filtered by something the rollup doesn't record."""
    if scope is not None or device_type not in (None, "any") or (code and any(code.values())):
        return None
    srcs = (sources,) if isinstance(sources, str) else tuple(sources or ())
    return Roll(sources=tuple(s for s in srcs if s and s != "any"), domain=kind if kind in ("infra", "code", "web", "cloud") else None,
                severities=SEV_PICKS.get(severity, ()), kev_only=bool(kev_only))


def _w(roll: Roll, kind: str, a=None, b=None) -> list:
    from api.models.finding_history import FindingRollup as R
    w = [R.kind == kind]
    if roll.sources:
        w.append(R.source.in_(roll.sources))
    if roll.domain:
        w.append(R.domain == roll.domain)
    if roll.severities:
        w.append(R.severity.in_(roll.severities))
    if roll.kev_only:
        w.append(R.kev == True)  # noqa: E712
    if a is not None:
        w.append(R.day >= (a.date() if isinstance(a, datetime) else a))
    if b is not None:
        w.append(R.day < (b.date() if isinstance(b, datetime) else b))
    return w


async def by_day(db, roll: Roll, kind: str) -> list:
    """(day, severity, kev, count) rows, as the dashboard trend builds them."""
    from api.models.finding_history import FindingRollup as R
    return (await db.execute(select(R.day, R.severity, R.kev, func.sum(R.n)).where(*_w(roll, kind))
                             .group_by(R.day, R.severity, R.kev))).all()


async def count(db, roll: Roll, kind: str, a=None, b=None) -> int:
    from api.models.finding_history import FindingRollup as R
    return int((await db.execute(select(func.coalesce(func.sum(R.n), 0)).where(*_w(roll, kind, a, b)))).scalar_one())


async def fix_time(db, roll: Roll, a=None, b=None) -> tuple[int, float]:
    """How many rolled-up fixes in [a, b) had a found date, and their total days to fix."""
    from api.models.finding_history import FindingRollup as R
    n, took = (await db.execute(select(func.coalesce(func.sum(R.timed), 0), func.coalesce(func.sum(R.fix_days), 0.0))
                                .where(*_w(roll, "fixed", a, b)))).one()
    return int(n), float(took)


async def fix_time_by_month(db, roll: Roll, since) -> dict:
    """{(first of month, severity): (timed, days)} for rolled-up fixes since a date."""
    from api.models.finding_history import FindingRollup as R
    out: dict = {}
    for d, s, n, took in (await db.execute(select(R.day, R.severity, R.timed, R.fix_days).where(*_w(roll, "fixed", since)))).all():
        k = (d.replace(day=1), s)
        a, b = out.get(k, (0, 0.0))
        out[k] = (a + n, b + took)
    return out


async def first_fix(db, roll: Roll) -> date | None:
    from api.models.finding_history import FindingRollup as R
    return (await db.execute(select(func.min(R.day)).where(*_w(roll, "fixed")))).scalar_one()
