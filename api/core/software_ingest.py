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
    named = [(it, software_norm.normalize(it.get("vendor"), it.get("product"), it.get("family"), it.get("type"), it.get("cpe")))
             for it in items]
    titles = await _titles(db, {n["key"] for _, n in named if n}, {n["key"] for _, n in named if n and not n["vendor"]})
    count = 0
    for it, n in named:
        if n is None:
            continue
        t = titles.get(n["key"])
        if t is None:
            t = SoftwareTitle(key=n["key"], vendor=n["vendor"], title=n["title"], system=n["system"], first_seen=now)
            db.add(t)
            await db.flush()
            titles[n["key"]] = t
        elif n["vendor"] and not t.vendor:   # a tool that names the vendor fills it in
            t.vendor = n["vendor"]
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


async def _titles(db: AsyncSession, keys: set[str], vendorless: set[str]) -> dict:
    """{key: SoftwareTitle} for these keys. A name sent without its vendor ("Teams Machine-Wide Installer", from a
    tool like Tanium) that has no title of its own goes to the one title that is that name led by its vendor
    ("Microsoft Teams Machine-Wide Installer"), when exactly one is."""
    from sqlalchemy import func

    from api.models.software import SoftwareTitle
    out: dict = {}
    ks = sorted(keys)
    for i in range(0, len(ks), 500):
        for t in (await db.execute(select(SoftwareTitle).where(SoftwareTitle.key.in_(ks[i:i + 500])))).scalars():
            out[t.key] = t
    want = sorted(k for k in vendorless if k not in out)
    if want:
        tail = func.substr(func.lower(SoftwareTitle.title), func.length(SoftwareTitle.vendor) + 2)
        hits: dict = {}
        for i in range(0, len(want), 500):
            for t in (await db.execute(select(SoftwareTitle).where(
                    SoftwareTitle.vendor != "", tail.in_(want[i:i + 500]),
                    func.lower(SoftwareTitle.title).startswith(func.lower(SoftwareTitle.vendor) + " ")))).scalars():
                b = software_norm.bare(t.vendor, t.title)
                if b:
                    hits.setdefault(b, []).append(t)
        out.update({k: ts[0] for k, ts in hits.items() if len(ts) == 1})
    return out


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
