"""Regroup installed software after the name rules change (api/core/software_norm.py).
# python -m api.maintenance.renormalize_software     safe to re-run

Each install moves to the title its reported name gives now; a title left with no installs is removed unless
someone reviewed it. Exceptions follow their title when they can."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, delete, exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.core import software_norm


_RANK = {"unauthorized": 2, "approved": 1, "unreviewed": 0}   # when titles merge, the strictest decision stays


async def _merge(db: AsyncSession, old, new) -> None:
    """One title into another: its installs, exceptions and the stricter review decision, and its vendor when the
    other has none."""
    from sqlalchemy import update

    from api.models.software import SoftwareException, SoftwareInstall, SoftwareTitle
    if _RANK.get(old.status, 0) > _RANK.get(new.status, 0):
        new.status, new.status_note, new.decided_by, new.decided_at = old.status, old.status_note, old.decided_by, old.decided_at
    if old.vendor and not new.vendor:
        new.vendor = old.vendor
    await db.flush()
    from sqlalchemy.orm import aliased
    o = aliased(SoftwareInstall)
    same = (o.title_id == old.id) & (o.device_id == SoftwareInstall.device_id) & (o.version == SoftwareInstall.version) \
        & (o.source == SoftwareInstall.source)
    theirs = select(o.last_seen).where(same).scalar_subquery()
    # one statement each, not one per install: an install already on the other title keeps the later sighting
    await db.execute(update(SoftwareInstall).where(SoftwareInstall.title_id == new.id, exists().where(same))
                     .values(last_seen=case((theirs > SoftwareInstall.last_seen, theirs), else_=SoftwareInstall.last_seen))
                     .execution_options(synchronize_session=False))
    on_new = (SoftwareInstall.title_id == new.id) & (SoftwareInstall.device_id == o.device_id) \
        & (SoftwareInstall.version == o.version) & (SoftwareInstall.source == o.source)
    await db.execute(delete(o).where(o.title_id == old.id, exists().where(on_new)).execution_options(synchronize_session=False))
    await db.execute(update(SoftwareInstall).where(SoftwareInstall.title_id == old.id).values(title_id=new.id)
                     .execution_options(synchronize_session=False))
    for e in (await db.execute(select(SoftwareException).where(SoftwareException.title_id == old.id))).scalars().all():
        if (await db.execute(select(exists().where(SoftwareException.title_id == new.id,
                                                   SoftwareException.device_id == e.device_id)))).scalar():
            await db.delete(e)
        else:
            e.title_id = new.id
    await db.flush()
    await db.execute(update(SoftwareTitle).where(SoftwareTitle.id == old.id).values(status="unreviewed"))


async def _rekey_titles(db: AsyncSession, by_key: dict) -> int:
    """A stored title renamed by the current rules (its own name normalized again) merges into that title, with its
    installs, exceptions and review decision. Safe without the reported names: the rules are idempotent on a
    title they produced, so only names the rules now clean up move. Then a title with no vendor (a tool that sends
    none) merges into the one title that is its name led by a vendor."""
    moved = 0
    for old in list(dict.fromkeys(by_key.values())):
        n = software_norm.normalize(old.vendor, old.title)
        if n is None or n["key"] == old.key:
            continue
        new = by_key.get(n["key"])
        by_key.pop(old.key, None)
        if new is None or new is old:
            old.key, old.title, old.system = n["key"], n["title"], old.system or n["system"]
            by_key[n["key"]] = old
        else:
            await _merge(db, old, new)
        moved += 1
    led: dict = {}
    for t in by_key.values():
        b = software_norm.bare(t.vendor, t.title)
        if b:
            led.setdefault(b, []).append(t)
    for k, old in list(by_key.items()):
        to = led.get(k) or []
        if not old.vendor and len(to) == 1 and to[0] is not old:
            await _merge(db, old, to[0])
            by_key.pop(k, None)
            moved += 1
    await db.flush()
    return moved


async def run(db: AsyncSession) -> dict:
    from api.models.software import SoftwareException, SoftwareInstall, SoftwareTitle
    titles = {t.id: t for t in (await db.execute(select(SoftwareTitle))).scalars()}
    by_key = {t.key: t for t in titles.values()}
    renamed = await _rekey_titles(db, by_key)
    titles = {t.id: t for t in by_key.values()}
    moved, went = 0, {}   # old title id -> the titles its installs went to
    now = datetime.now(timezone.utc)
    for old in list(titles.values()):
        rows = (await db.execute(select(SoftwareInstall).where(SoftwareInstall.title_id == old.id))).scalars().all()
        for i in rows:
            if not (i.vendor_raw or i.family):
                continue   # stored before the reported names were kept: its next upload regroups it exactly
            n = software_norm.normalize(i.vendor_raw, i.product, i.family, i.kind, i.cpe)
            if n is None or n["key"] == old.key or (not n["vendor"] and software_norm.bare(old.vendor, old.title) == n["key"]):
                continue   # unchanged, or a name without its vendor already on its vendor's title
            new = by_key.get(n["key"])
            if new is None:
                new = SoftwareTitle(key=n["key"], vendor=n["vendor"], title=n["title"], system=n["system"],
                                    first_seen=old.first_seen or now, last_seen=old.last_seen or now)
                db.add(new)
                await db.flush()
                by_key[n["key"]] = new
            clash = (await db.execute(select(SoftwareInstall).where(
                SoftwareInstall.title_id == new.id, SoftwareInstall.device_id == i.device_id,
                SoftwareInstall.version == i.version, SoftwareInstall.source == i.source))).scalar_one_or_none()
            if clash:
                clash.last_seen = max(filter(None, [clash.last_seen, i.last_seen]))
                await db.delete(i)
            else:
                i.title_id = new.id
            went.setdefault(old.id, set()).add(new.id)
            if new.status == "unreviewed" and old.status != "unreviewed":
                new.status, new.status_note, new.decided_by, new.decided_at = old.status, old.status_note, old.decided_by, old.decided_at
            moved += 1
        await db.flush()
    # An exception follows its title when all of that title's installs went to one other title
    for e in (await db.execute(select(SoftwareException))).scalars().all():
        dest = went.get(e.title_id) or set()
        if len(dest) != 1 or (await db.execute(select(exists().where(SoftwareInstall.title_id == e.title_id)))).scalar():
            continue
        (to,) = dest
        if not (await db.execute(select(exists().where(SoftwareException.title_id == to,
                                                       SoftwareException.device_id == e.device_id)))).scalar():
            e.title_id = to
    # A title the system rules now cover (Windows' own packages, say) moves out of the third-party view
    for t in (await db.execute(select(SoftwareTitle).where(SoftwareTitle.system == False))).scalars():  # noqa: E712
        if software_norm.system(t.vendor, t.title):
            t.system = True
    empty = ~exists().where(SoftwareInstall.title_id == SoftwareTitle.id)
    unused = ~exists().where(SoftwareException.title_id == SoftwareTitle.id)
    r = await db.execute(delete(SoftwareTitle).where(empty, unused, SoftwareTitle.status == "unreviewed")
                         .execution_options(synchronize_session=False))
    await db.commit()
    return {"titles_renamed": renamed, "installs_moved": moved, "titles_removed": r.rowcount or 0}


VERSION_KEY = "software.rules_version"


async def if_rules_changed(db: AsyncSession) -> dict | None:
    """Regroup once after the name rules change. Skipped (until the next hour) while any sync or shipper run is
    going, so it never races an upload."""
    from api.models.integration import SyncJob, SyncStatus
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == VERSION_KEY))).scalar_one_or_none()
    if row is not None and row.value == str(software_norm.RULES_VERSION):
        return None
    recent = datetime.now(timezone.utc) - timedelta(hours=6)   # older "running" rows are runs that died
    if (await db.execute(select(exists().where(SyncJob.status == SyncStatus.running, SyncJob.started_at >= recent)))).scalar():
        return None
    out = await run(db)
    if row is None:
        db.add(AppSetting(key=VERSION_KEY, value=str(software_norm.RULES_VERSION)))
    else:
        row.value = str(software_norm.RULES_VERSION)
    await db.commit()
    return out


async def _main() -> None:
    import api.core.db as dbm

    dbm.init_db_worker()
    async with dbm._session_factory() as db:
        print(await run(db))


if __name__ == "__main__":
    asyncio.run(_main())
