"""Is CrowdStrike Spotlight on for an integration? It is the shipper's CrowdStrike source's own Spotlight setting
(changed on the Shippers page or the integration's card, api/routes/integration_spotlight.py)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def owner(db: AsyncSession, integration_id: str):
    """The shipper profile whose CrowdStrike source feeds this integration, or None."""
    from api.models.collector import CollectorProfile
    for p in (await db.execute(select(CollectorProfile))).scalars():
        m = (p.modules or {}).get("crowdstrike") or {}
        if str(m.get("integration_id") or "") == integration_id:
            return p
    return None


async def states(db: AsyncSession) -> dict[str, bool]:
    """{integration id: Spotlight on} for every shipper-fed CrowdStrike integration (for the cards)."""
    from api.models.collector import CollectorProfile
    out = {}
    for p in (await db.execute(select(CollectorProfile))).scalars():
        m = (p.modules or {}).get("crowdstrike") or {}
        if m.get("integration_id"):
            out[str(m["integration_id"])] = str((m.get("settings") or {}).get("spotlight", "on")).lower() != "off"
    return out


async def pulling(db: AsyncSession, integration_id: str) -> bool:
    """Spotlight is on for this integration (anything not fed by a shipper's CrowdStrike source: yes)."""
    return (await states(db)).get(str(integration_id), True)
