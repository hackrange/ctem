"""Daily: a host that's gone loses its vulnerabilities; they're removed, not kept as history (Admin > Data retention).

Gone means both: no tool has seen it in N days (no scan, EDR check-in, directory logon, finding a tool still reports,
cloud inventory row or network probe answer), AND the network probe tried it in the last few days and got no answer
(no ping reply, nothing on the common ports). Every such host is put on the probe's list (api/core/netprobe.py), so
nothing is removed on a guess: a host the probe hasn't tried, or one with no internal address to try, keeps its
findings. Its asset record stays for the stale-record checks; one only the probe ever knew, silent all that time, is
removed too. A scanner reporting the host again brings its findings back."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, delete, exists, or_, select, update

log = logging.getLogger("open-ctem.stale_hosts")


def _quiet(col, cut):
    return or_(col.is_(None), col < cut)


def unseen(cut):
    """No tool has seen it since `cut`: the first half of "gone" (the probe's silence is the second)."""
    from api.models.cloud import CloudAsset
    from api.models.device import Device, NON_HOST_TYPES
    from api.models.vuln import Finding
    return and_(Device.device_type.not_in(NON_HOST_TYPES),
                *(_quiet(c, cut) for c in (Device.last_seen, Device.edr_last_seen, Device.ad_last_logon, Device.alive_at)),
                ~exists(select(Finding.id).where(Finding.device_id == Device.id, Finding.last_seen >= cut)),
                ~exists(select(CloudAsset.id).where(CloudAsset.device_id == Device.id, CloudAsset.seen_at >= cut)))


async def prune(db, days: int | None = None) -> dict:
    from api.core import retention
    from api.models.device import Device
    from api.models.vuln import Finding
    cfg = await retention.load(db)
    if not cfg["enabled"]:
        return {"hosts": 0, "findings": 0, "probe_only": 0, "disabled": True}
    now = datetime.now(timezone.utc)
    cut = now - timedelta(days=int(days or cfg["stale_host_days"]))
    tried = now - timedelta(days=cfg["probe_within_days"])
    # Confirmed not live: the probe tried it recently and it didn't answer
    confirmed = and_(Device.probed_at.is_not(None), Device.probed_at >= tried, _quiet(Device.alive_at, cut))   # never NULL
    ids = (await db.execute(select(Device.id).where(unseen(cut), confirmed, exists(select(Finding.id).where(Finding.device_id == Device.id)))
                            .limit(100_000))).scalars().all()
    removed = 0
    for i in range(0, len(ids), 500):
        part = ids[i:i + 500]
        removed += (await db.execute(delete(Finding).where(Finding.device_id.in_(part)))).rowcount or 0
        await db.execute(update(Device).where(Device.id.in_(part)).values(open_findings=0, kev_findings=0))
    ghosts = (await db.execute(select(Device.id).where(Device.sources == ",netprobe,", _quiet(Device.alive_at, cut), confirmed))).scalars().all()
    for i in range(0, len(ghosts), 500):
        await db.execute(delete(Device).where(Device.id.in_(ghosts[i:i + 500])))
    waiting = (await db.execute(select(Device.id).where(unseen(cut), ~confirmed,
                                                        exists(select(Finding.id).where(Finding.device_id == Device.id))).limit(100_000))).scalars().all()
    await db.commit()
    log.info("stale hosts: %d findings removed from %d hosts confirmed offline; %d silent probe-only devices removed; "
             "%d unseen hosts kept until the probe confirms them", removed, len(ids), len(ghosts), len(waiting))
    return {"hosts": len(ids), "findings": removed, "probe_only": len(ghosts), "waiting_for_probe": len(waiting)}


async def candidates(db, limit: int = 20000) -> list[str]:
    """Internal addresses of unseen hosts with findings that the probe should try, so they can be confirmed gone."""
    from api.core import retention
    from api.core.location import subnet_of
    from api.models.device import Device
    from api.models.vuln import Finding
    cfg = await retention.load(db)
    if not cfg["enabled"]:
        return []
    cut = datetime.now(timezone.utc) - timedelta(days=cfg["stale_host_days"])
    rows = (await db.execute(select(Device.ip).where(unseen(cut), Device.subnet_hash.is_not(None),
                                                    exists(select(Finding.id).where(Finding.device_id == Device.id))).limit(limit))).scalars().all()
    return sorted({str(ip).strip() for ip in rows if subnet_of(ip)})
