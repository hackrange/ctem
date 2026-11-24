"""Daily: a host no tool has seen in N days (30 by default, STALE_HOST_DAYS) that doesn't answer the network probe
either is gone, so its vulnerabilities are removed, not kept as history. "Seen" is any sign of life from any tool:
a scan, an EDR check-in, a directory logon, a finding a tool still reports, a cloud inventory row, a probe answer.
Its asset record stays (the stale-record checks list it for retiring in those tools); one only the network probe
ever knew, with no answer in that time, is removed too. A scanner reporting the host again brings its findings back."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, delete, exists, or_, select, update

log = logging.getLogger("open-ctem.stale_hosts")


def _quiet(col, cut):
    return or_(col.is_(None), col < cut)


async def prune(db, days: int | None = None) -> dict:
    from api.core.config import get_settings
    from api.models.cloud import CloudAsset
    from api.models.device import Device, NON_HOST_TYPES
    from api.models.vuln import Finding
    cut = datetime.now(timezone.utc) - timedelta(days=int(days or get_settings().stale_host_days))
    recent_finding = exists(select(Finding.id).where(Finding.device_id == Device.id, Finding.last_seen >= cut))
    recent_cloud = exists(select(CloudAsset.id).where(CloudAsset.device_id == Device.id, CloudAsset.seen_at >= cut))
    gone = and_(Device.device_type.not_in(NON_HOST_TYPES),
                *(_quiet(c, cut) for c in (Device.last_seen, Device.edr_last_seen, Device.ad_last_logon, Device.alive_at)),
                ~recent_finding, ~recent_cloud)
    ids = (await db.execute(select(Device.id).where(gone, exists(select(Finding.id).where(Finding.device_id == Device.id)))
                            .limit(100_000))).scalars().all()
    removed = 0
    for i in range(0, len(ids), 500):
        part = ids[i:i + 500]
        removed += (await db.execute(delete(Finding).where(Finding.device_id.in_(part)))).rowcount or 0
        await db.execute(update(Device).where(Device.id.in_(part)).values(open_findings=0, kev_findings=0))
    # A device only the probe ever saw, silent for that long: there's nothing left to say about it
    ghosts = (await db.execute(select(Device.id).where(Device.sources == ",netprobe,", _quiet(Device.alive_at, cut)))).scalars().all()
    for i in range(0, len(ghosts), 500):
        await db.execute(delete(Device).where(Device.id.in_(ghosts[i:i + 500])))
    await db.commit()
    if ids or ghosts:
        log.info("stale hosts: %d findings removed from %d hosts unseen since %s; %d silent probe-only devices removed",
                 removed, len(ids), cut.date(), len(ghosts))
    return {"hosts": len(ids), "findings": removed, "probe_only": len(ghosts)}
