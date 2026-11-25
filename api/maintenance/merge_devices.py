"""Fold duplicate device rows (DESKTOP001 vs desktop001.ad.acme.example) into one."""
# python -m api.maintenance.merge_devices            dry run, changes nothing
# python -m api.maintenance.merge_devices --apply    merge, then rescore
from __future__ import annotations

import argparse
import asyncio
import logging
from collections import Counter, defaultdict

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.device_match import NOT_HOSTS, add_source, device_domain, host_key, same_domain, source_list
from api.models.device import DeviceType

log = logging.getLogger("open-ctem.merge_devices")

_BATCH = 500
# Fields a duplicate may know that the survivor doesn't (pairs travel together)
_FILL = [("fqdn",), ("ip", "ip_hash"), ("mac_address",), ("os",), ("os_version",), ("ad_dn",),
         ("last_login_user", "last_login_user_hash"), ("recent_logins",), ("owner_user_id",), ("source_id",)]
_NEWEST = ["last_seen", "ad_last_logon"]


def _clusters(rows: list) -> list[list]:
    """Rows in related domains (ad.acme.example ~ acme.example) end up together."""
    out: list[list] = []
    for d in rows:
        home = [c for c in out if any(same_domain(device_domain(d), device_domain(x)) for x in c)]
        merged = [d] + [x for c in home for x in c]
        out = [c for c in out if c not in home] + [merged]
    return out


def _home_for_short(clusters: list[list], primary: str | None) -> list | None:
    """A bare name joins the AD-joined cluster, else the fleet's main domain, else nothing."""
    ad = [c for c in clusters if any(d.ad_joined for d in c)]
    if len(ad) == 1:
        return ad[0]
    main = [c for c in clusters if any(same_domain(device_domain(d), primary) for d in c)]
    return main[0] if primary and len(main) == 1 else None


def plan(devices: list, finding_counts: dict) -> tuple[list[tuple], list[tuple]]:
    """Return ([(survivor, [losers])], [(key, reason)]) without touching anything."""
    groups: dict[str, list] = defaultdict(list)
    for d in devices:
        if d.source not in NOT_HOSTS and host_key(d.hostname):
            groups[host_key(d.hostname)].append(d)
    tally = Counter(device_domain(d) for d in devices if device_domain(d))
    primary = tally.most_common(1)[0][0] if tally else None
    merges, skipped = [], []
    for key, rows in groups.items():
        if len(rows) < 2:
            continue
        clusters = _clusters([d for d in rows if device_domain(d)])
        bare = [d for d in rows if not device_domain(d)]
        if bare:
            home = clusters[0] if len(clusters) == 1 else _home_for_short(clusters, primary) if clusters else None
            if home is not None:
                home.extend(bare)
            elif not clusters:
                clusters = [bare]
            else:
                skipped.append((key, f"short name could be any of {len(clusters)} domains"))
        if len(clusters) > 1:
            skipped.append((key, f"{len(clusters)} different domains kept apart"))
        for c in clusters:
            if len(c) > 1:
                c.sort(key=lambda d: (-finding_counts.get(d.id, 0), d.created_at))
                merges.append((c[0], c[1:]))
    return merges, skipped


def _absorb(keep, dup) -> None:
    for group in _FILL:
        if getattr(keep, group[0]) in (None, "") and getattr(dup, group[0]) not in (None, ""):
            for f in group:
                setattr(keep, f, getattr(dup, f))
    if dup.edr_vendor and (not keep.edr_vendor or (dup.edr_active and not keep.edr_active)):
        keep.edr_vendor, keep.edr_active, keep.edr_last_seen = dup.edr_vendor, dup.edr_active, dup.edr_last_seen
        keep.edr_contained, keep.edr_hidden, keep.edr_device_id = dup.edr_contained, dup.edr_hidden, dup.edr_device_id
    for name in source_list(dup):
        add_source(keep, name)
    add_source(keep, dup.source)
    if dup.device_type == DeviceType.server:
        keep.device_type = DeviceType.server
    keep.ad_joined = keep.ad_joined or dup.ad_joined
    keep.is_internet_exposed = keep.is_internet_exposed or dup.is_internet_exposed
    for f in _NEWEST:
        if getattr(dup, f) and (getattr(keep, f) is None or getattr(dup, f) > getattr(keep, f)):
            setattr(keep, f, getattr(dup, f))


async def _merge_one(db: AsyncSession, keep, dup) -> None:
    from api.models.device import Device, DeviceTag
    from api.models.risk import AttackPath, RiskScore, RiskScoreHistory
    from api.models.vuln import CVEChain, Finding

    _absorb(keep, dup)
    # Keep a person's assignment: the survivor takes the duplicate's if it has none of its own
    from api.models.device import DeviceAssignment
    if not (await db.execute(select(DeviceAssignment.id).where(DeviceAssignment.device_id == keep.id))).first():
        await db.execute(update(DeviceAssignment).where(DeviceAssignment.device_id == dup.id)
                         .values(device_id=keep.id).execution_options(synchronize_session=False))
    for model, col in ((Finding, Finding.device_id), (CVEChain, CVEChain.device_id),
                       (AttackPath, AttackPath.source_device_id), (AttackPath, AttackPath.target_device_id)):
        await db.execute(update(model).where(col == dup.id).values({col.key: keep.id})
                         .execution_options(synchronize_session=False))
    have = set((await db.execute(select(DeviceTag.tag_id).where(DeviceTag.device_id == keep.id))).scalars())
    for tag_id in (await db.execute(select(DeviceTag.tag_id).where(DeviceTag.device_id == dup.id))).scalars():
        if tag_id not in have:
            await db.execute(insert(DeviceTag).values(device_id=keep.id, tag_id=tag_id))
    for model in (RiskScore, RiskScoreHistory):
        await db.execute(delete(model).where(model.entity_type == "device", model.entity_id == dup.id))
    db.expunge(dup)
    from api.scoring.dirty import mark_devices
    await mark_devices(db, [keep.id])
    await db.execute(delete(Device).where(Device.id == dup.id))


async def run(db: AsyncSession, apply: bool) -> dict:
    from api.models.device import Device
    from api.models.vuln import Finding

    devices = list((await db.execute(select(Device))).scalars())
    for d in devices:  # rows from before host_key existed
        key = None if d.source in NOT_HOSTS else host_key(d.hostname)
        if d.host_key != key:
            d.host_key = key
    counts = dict((await db.execute(select(Finding.device_id, func.count()).group_by(Finding.device_id))).all())
    merges, skipped = plan(devices, counts)
    summary = {"groups": len(merges), "rows_removed": sum(len(l) for _, l in merges),
               "skipped": len(skipped), "skipped_examples": skipped[:20]}
    if not apply:
        await db.rollback()
        return summary
    await db.commit()
    for i, (keep, dups) in enumerate(merges, 1):
        for dup in dups:
            await _merge_one(db, keep, dup)
        if i % _BATCH == 0:
            await db.commit()
            log.info("merged %d of %d groups", i, len(merges))
    await db.commit()
    from api.scoring.engine import recalculate_all
    await recalculate_all(db)
    await db.commit()
    return summary


async def _main(apply: bool) -> None:
    import api.core.db as dbm

    dbm.init_db_worker()
    async with dbm._session_factory() as db:
        out = await run(db, apply)
    print(("Merged" if apply else "Would merge") + f" {out['groups']} hosts, removing {out['rows_removed']} duplicate rows.")
    print(f"Skipped {out['skipped']} names that exist in more than one domain (left alone):")
    for key, why in out["skipped_examples"]:
        print(f"  {key}: {why}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Merge duplicate device rows")
    p.add_argument("--apply", action="store_true", help="actually merge (default is a dry run)")
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_main(p.parse_args().apply))
