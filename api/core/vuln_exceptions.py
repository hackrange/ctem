"""Vulnerability exceptions: which findings an exception covers, and keeping findings in step with it.

An approved exception marks its open findings risk_accepted and links them (Finding.exception_id), so every
count that already ignores accepted risk (device risk, open findings, SLA, KEV and exposure checks) leaves them
out with no other change. When the exception ends, those findings go back to open. Scans keep adding findings,
so sync_all() runs after every sync and covers new ones for the "all" and "tag" scopes too.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.vuln import ExceptionScope, ExceptionStatus, Finding, FindingStatus, VulnException

log = logging.getLogger("open-ctem.exceptions")

MAX_DAYS = 365
MAX_DEVICES = 500
OPEN = (FindingStatus.open, FindingStatus.in_progress)


def now() -> datetime:
    return datetime.now(timezone.utc)


def end_of_day(d) -> datetime:
    """An exception 'until 2026-12-31' lasts through that whole day (UTC)."""
    return datetime(d.year, d.month, d.day, tzinfo=timezone.utc) + timedelta(days=1) - timedelta(microseconds=1)


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_active(exc: VulnException) -> bool:
    return exc.status == ExceptionStatus.approved and _aware(exc.expires_at) > now()


def covers(exc: VulnException):
    """SQL condition on Finding: the findings this exception is about (any status)."""
    from api.models.device import DeviceTag
    cond = Finding.vuln_id == exc.vuln_id
    if exc.scope in (ExceptionScope.finding, ExceptionScope.devices):
        return and_(cond, Finding.device_id.in_([str(d) for d in (exc.device_ids or [])][:MAX_DEVICES]))
    if exc.scope == ExceptionScope.tag:
        return and_(cond, Finding.device_id.in_(select(DeviceTag.device_id).where(DeviceTag.tag_id == exc.tag_id)))
    return cond


async def apply(db: AsyncSession, exc: VulnException) -> list[str]:
    """Cover this exception's open findings. Returns the devices to rescore."""
    if not is_active(exc):
        return []
    todo = and_(covers(exc), Finding.status.in_(OPEN), Finding.exception_id.is_(None))
    ids = [r[0] for r in (await db.execute(select(Finding.device_id).where(todo).distinct())).all()]
    if ids:
        await db.execute(update(Finding).where(todo).values(status=FindingStatus.risk_accepted, exception_id=exc.id)
                         .execution_options(synchronize_session=False))
    exc.findings_covered = (await db.execute(
        select(func.count()).select_from(Finding).where(Finding.exception_id == exc.id))).scalar_one()
    return [str(i) for i in ids]


async def release(db: AsyncSession, exc: VulnException) -> list[str]:
    """The exception ended: its findings count again. Returns the devices to rescore."""
    mine = Finding.exception_id == exc.id
    ids = [r[0] for r in (await db.execute(select(Finding.device_id).where(mine).distinct())).all()]
    await db.execute(update(Finding).where(mine, Finding.status == FindingStatus.risk_accepted)
                     .values(status=FindingStatus.open, exception_id=None).execution_options(synchronize_session=False))
    await db.execute(update(Finding).where(mine).values(exception_id=None).execution_options(synchronize_session=False))
    return [str(i) for i in ids]


async def sync_all(db: AsyncSession) -> list[str]:
    """Expire what has run out, then cover new findings for everything still approved. Returns devices to rescore."""
    from api.models.settings import AuditLog
    ids: list[str] = []
    due = (await db.execute(select(VulnException).where(
        VulnException.status == ExceptionStatus.approved, VulnException.expires_at <= now()))).scalars().all()
    for exc in due:
        exc.status = ExceptionStatus.expired
        ids += await release(db, exc)
        db.add(AuditLog(actor_username="system", action="exception.expired", resource_type="vuln_exception",
                        resource_id=str(exc.id), detail=f"ended {exc.expires_at.date().isoformat()}"))
    live = (await db.execute(select(VulnException).where(
        VulnException.status == ExceptionStatus.approved, VulnException.expires_at > now()))).scalars().all()
    for exc in live:
        try:
            ids += await apply(db, exc)
        except Exception:
            log.exception("could not apply exception %s", exc.id)
    await db.commit()
    return list(dict.fromkeys(ids))


async def rescore(db: AsyncSession, device_ids: list[str]) -> None:
    """Rescore the devices an exception touched now when few; leave a big batch to the background pipeline."""
    from api.models.device import Device
    from api.scoring.engine import recalculate_device, refresh_affected_counts
    if len(device_ids) > 300:
        from api.core.tasks import post_sync_pipeline
        post_sync_pipeline.delay((now() - timedelta(minutes=5)).isoformat())
        return
    for i in range(0, len(device_ids), 100):
        for dev in (await db.execute(select(Device).where(Device.id.in_(device_ids[i:i + 100])))).scalars():
            try:
                await recalculate_device(dev, db)
            except Exception:
                log.exception("rescore after exception failed for %s", dev.id)
    await refresh_affected_counts(db)
