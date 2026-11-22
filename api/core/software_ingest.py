"""Store reported software: normalize each product to its title, match its hosts to assets, record each install.

items: [{vendor, product, family, version, type, cpe, publisher?, install_path?, sha256?, md5?, hosts: [...]}] from any source (the
InsightVM console through the shipper today). Installs keep the version and the name as reported; titles keep the
review decision. An install counts while its source keeps reporting it (STALE_DAYS)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.core import software_norm

STALE_DAYS = 30   # an install its source stopped reporting this long ago no longer counts (and is pruned)


async def upsert(db: AsyncSession, items: list[dict], source: str, host_cache: dict | None = None) -> int:
    from api.core.device_match import find_device
    from api.models.software import SoftwareInstall, SoftwareTitle
    now = datetime.now(timezone.utc)
    hosts = host_cache if host_cache is not None else {}
    titles: dict[str, SoftwareTitle] = {}
    count = 0
    for it in items:
        n = software_norm.normalize(it.get("vendor"), it.get("product"), it.get("family"), it.get("type"), it.get("cpe"))
        if n is None:
            continue
        t = titles.get(n["key"])
        if t is None:
            t = (await db.execute(select(SoftwareTitle).where(SoftwareTitle.key == n["key"]))).scalar_one_or_none()
            if t is None:
                t = SoftwareTitle(key=n["key"], vendor=n["vendor"], title=n["title"], system=n["system"], first_seen=now)
                db.add(t)
                await db.flush()
            titles[n["key"]] = t
        t.last_seen = now
        dev_ids = []
        for h in it.get("hosts") or []:
            h = str(h).strip()[:253]
            if not h:
                continue
            if h not in hosts:
                d = await find_device(db, h)
                hosts[h] = str(d.id) if d else None
            if hosts[h]:
                dev_ids.append(hosts[h])
        if not dev_ids:
            continue
        version = str(it.get("version") or "").strip()[:128]
        files = _files(it) | _reported(it)
        have = {r.device_id: r for r in (await db.execute(select(SoftwareInstall).where(
            SoftwareInstall.title_id == t.id, SoftwareInstall.version == version, SoftwareInstall.source == source,
            SoftwareInstall.device_id.in_(dev_ids)))).scalars()}
        for dev in dict.fromkeys(dev_ids):
            row = have.get(dev)
            if row is None:
                db.add(SoftwareInstall(title_id=t.id, device_id=dev, version=version, source=source,
                                       product=str(it.get("product") or "")[:256] or None, first_seen=now, last_seen=now, **files))
            else:
                row.last_seen = now
                for k, v in files.items():   # what the source tells us now; nothing it didn't send is wiped
                    setattr(row, k, v)
            count += 1
    await db.commit()
    return count


def _reported(it: dict) -> dict:
    """The names as reported, kept for a later regroup (api/maintenance/renormalize_software.py)."""
    out = {}
    for k, src, n in (("vendor_raw", "vendor", 256), ("family", "family", 256), ("kind", "type", 64), ("cpe", "cpe", 256)):
        v = str(it.get(src) or "").strip()[:n]
        if v:
            out[k] = v
    return out


def _files(it: dict) -> dict:
    """Publisher, install path and hashes when the source sent them (hashes checked and kept lowercase)."""
    import re
    out = {}
    for k, n in (("publisher", 256), ("install_path", 512)):
        v = str(it.get(k) or "").strip()[:n]
        if v:
            out[k] = v
    for k, size in (("sha256", 64), ("md5", 32)):
        v = str(it.get(k) or "").strip().lower()
        if re.fullmatch(rf"[a-f0-9]{{{size}}}", v):
            out[k] = v
    return out


async def prune(db: AsyncSession) -> int:
    """Drop installs no source has reported for STALE_DAYS."""
    from sqlalchemy import delete

    from api.models.software import SoftwareInstall
    cut = datetime.now(timezone.utc) - timedelta(days=STALE_DAYS)
    r = await db.execute(delete(SoftwareInstall).where(SoftwareInstall.last_seen < cut))
    await db.commit()
    return r.rowcount or 0


async def prune_run(db: AsyncSession, source: str, started) -> int | None:
    """After a run that reported software, drop that source's installs it no longer reports (uninstalled, or
    named differently now) and return how many. A run that sent no software changes nothing (None)."""
    from sqlalchemy import delete, exists

    from api.models.software import SoftwareInstall
    sent = (await db.execute(select(exists().where(SoftwareInstall.source == source,
                                                   SoftwareInstall.last_seen >= started)))).scalar()
    if not sent:
        return None
    r = await db.execute(delete(SoftwareInstall).where(SoftwareInstall.source == source, SoftwareInstall.last_seen < started)
                         .execution_options(synchronize_session=False))
    return r.rowcount or 0
