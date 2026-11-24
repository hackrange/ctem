"""An asset's Context tab: where CTEM thinks it is (and why), its neighbors on the same /24, who else reaches the
internet from its public address, and which tools see it. Admins and cyber only, like the other security tabs;
neighbors are limited to assets this person may see. 404 for anyone else and for assets they can't see, alike."""
from __future__ import annotations

import uuid
from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.grc.checks import DIRECTORY, EDR, SCANNERS
from api.models.device import Device, DeviceTag
from api.models.user import User

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])
CLOUD = ("aws", "oci", "azure", "rapid7_cloudsec")
MAX_NEIGHBORS = 100


def coverage(d: Device) -> dict:
    """Which kinds of tool see this asset."""
    src = {s for s in (d.sources or "").split(",") if s}
    return {"scanner": bool(src & set(SCANNERS)), "edr": bool(src & set(EDR)) or bool(d.edr_vendor),
            "directory": bool(src & set(DIRECTORY)) or bool(d.ad_joined), "pentest": "horizon3" in src,
            "cloud": bool(src & set(CLOUD)), "probe": "netprobe" in src}


def gaps(c: dict) -> list[str]:
    out = []
    if c["pentest"] and not c["scanner"]:
        out.append("Seen by the pentest, not by your vulnerability scanner")
    if c["pentest"] and not (c["edr"] or c["directory"] or c["cloud"]):
        out.append("Only the pentest knows this asset: nothing manages it")
    if c["probe"] and not (c["scanner"] or c["edr"] or c["directory"] or c["cloud"] or c["pentest"]):
        out.append("Answers on the network, but no tool knows it: a possible rogue device")
    return out


def _place(d: Device) -> str | None:
    p = ", ".join(x for x in (d.loc_city, d.loc_state) if x)
    return p or d.loc_office or d.loc_site


@router.get("/{device_id}/context")
async def device_context(device_id: uuid.UUID, u: User = Depends(require_permission("devices", "read")),
                         db: AsyncSession = Depends(get_session)):
    from api.auth.device_scope import device_scope
    from api.core.location import subnet_of
    from api.routes.device_edr import _device
    from api.routes.device_query import display_name
    d = await _device(device_id, u, db)
    scope = await device_scope(u, db)
    mine = coverage(d)
    out = {"available": True,
           "location": {"site": d.loc_site, "office": d.loc_office, "city": d.loc_city, "state": d.loc_state,
                        "confidence": d.loc_confidence, "evidence": d.loc_evidence or [],
                        "at": d.loc_at.isoformat() if d.loc_at else None, "edr_site": d.edr_site, "edr_ou": d.edr_ou},
           "coverage": mine, "gaps": gaps(mine), "subnet": subnet_of(d.ip), "neighbors": [], "neighbors_total": 0,
           "probe": {"probed_at": d.probed_at.isoformat() if d.probed_at else None,
                     "alive_at": d.alive_at.isoformat() if d.alive_at else None, "ports": d.alive_ports}}
    if d.subnet_hash:
        cond = [Device.subnet_hash == d.subnet_hash, Device.id != d.id] + ([scope] if scope is not None else [])
        out["neighbors_total"] = (await db.execute(select(func.count()).select_from(Device).where(*cond))).scalar_one()
        rows = (await db.execute(select(Device).options(selectinload(Device.tags).selectinload(DeviceTag.tag), selectinload(Device.owner))
                                 .where(*cond).order_by(Device.risk_score.desc().nulls_last()).limit(MAX_NEIGHBORS))).scalars().all()
        seen = Counter()
        for n in rows:
            c = coverage(n)
            seen.update(k for k, v in c.items() if v)
            out["neighbors"].append({
                "id": str(n.id), "name": display_name(n), "ip": n.ip, "type": n.device_type.value if n.device_type else None,
                "os": n.os, "coverage": c, "gaps": gaps(c), "grade": n.risk_grade.value if n.risk_grade else None,
                "open_findings": n.open_findings, "kev": n.kev_findings, "place": _place(n), "site": n.edr_site, "ports": n.alive_ports,
                "owner": (n.owner.display_name or n.owner.username) if n.owner else None,
                "owner_tags": sorted(t.tag.name for t in n.tags if t.tag and t.tag.name.lower().startswith("owner:"))[:4],
                "last_seen": n.last_seen.isoformat() if n.last_seen else None})
        out["subnet_coverage"] = {k: seen.get(k, 0) for k in mine}
    if d.public_ip_hash:
        cond = [Device.public_ip_hash == d.public_ip_hash, Device.id != d.id] + ([scope] if scope is not None else [])
        same = (await db.execute(select(Device.loc_city, Device.loc_state, Device.loc_office).where(*cond))).all()
        places = Counter(", ".join(x for x in (c, s) if x) or o for c, s, o in same if c or s or o)
        out["public_ip"] = {"address": d.public_ip, "shared_with": len(same), "places": places.most_common(5)}
    return out
