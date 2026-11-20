"""Fill the Sources column and server types for devices that predate them."""
# python -m api.maintenance.backfill_sources     safe to re-run; only adds, never removes
from __future__ import annotations

import asyncio
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.device_match import add_source, remember_fqdn, type_from_os

_BATCH = 2000


async def run(db: AsyncSession) -> dict:
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding

    seen = defaultdict(set)
    for device_id, src in (await db.execute(select(Finding.device_id, Finding.source).distinct())).all():
        seen[device_id].add(src)
    changed = servers = 0
    rows = list((await db.execute(select(Device))).scalars())
    for i, d in enumerate(rows, 1):
        before, kind = d.sources, d.device_type
        for name in [d.source, d.edr_vendor, "ldap" if d.ad_joined else None, *seen.get(d.id, ())]:
            add_source(d, name)
        d.device_type = type_from_os(d.os, d.device_type)
        remember_fqdn(d, d.hostname)  # Rapid7 names like desktop001.ad.acme.example are the FQDN
        changed += d.sources != before
        servers += kind != d.device_type and d.device_type == DeviceType.server
        if i % _BATCH == 0:
            await db.commit()
    await db.commit()
    return {"devices": len(rows), "sources_updated": changed, "now_servers": servers}


async def _main() -> None:
    import api.core.db as dbm

    dbm.init_db_worker()
    async with dbm._session_factory() as db:
        out = await run(db)
    print(f"Checked {out['devices']} devices: sources filled on {out['sources_updated']}, "
          f"{out['now_servers']} reclassified as servers from their OS.")


if __name__ == "__main__":
    asyncio.run(_main())
