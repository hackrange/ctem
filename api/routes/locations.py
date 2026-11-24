"""Sites: where assets are (api/core/location.py), each place with which tools cover it, what only the pentest
knows, its open risk, and its subnets. Admins and cyber, limited to the assets each person may see."""
from __future__ import annotations

from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.grc.checks import DIRECTORY, EDR, SCANNERS
from api.models.device import Device, HIDDEN_BY_DEFAULT
from api.models.user import User

router = APIRouter(prefix="/api/v1/locations", tags=["locations"])
def _PLACE():   # one per parameter: FastAPI binds a shared Query object to the first name it sees
    return Query(None, max_length=128, pattern=r"^[^\x00-\x1f<>]+$")
MAX_SUBNET_ASSETS = 20000


def _has(sources) -> object:
    return or_(*[Device.sources.like(f"%,{s},%") for s in sources])


def _n(cond):
    return func.sum(case((cond, 1), else_=0))


async def _base(u: User, db: AsyncSession) -> list:
    from api.auth.device_scope import device_scope
    from api.core.device_scope_exempt import in_scope
    from api.routes.device_edr import _deciders
    if not _deciders(u):
        raise HTTPException(404)
    scope = await device_scope(u, db)
    return [Device.device_type.not_in(HIDDEN_BY_DEFAULT), in_scope()] + ([scope] if scope is not None else [])


@router.get("")
async def list_locations(u: User = Depends(require_permission("devices", "read")), db: AsyncSession = Depends(get_session)):
    where = await _base(u, db)
    scanner, edr = _has(SCANNERS), or_(_has(EDR), Device.edr_vendor.is_not(None))
    directory, pentest = or_(_has(DIRECTORY), Device.ad_joined.is_(True)), Device.sources.like("%,horizon3,%")
    keys = (Device.loc_state, Device.loc_city, Device.loc_office, Device.loc_site)
    rows = (await db.execute(select(*keys, func.count(), _n(scanner), _n(edr), _n(directory), _n(pentest),
                                    _n(pentest & ~scanner), func.coalesce(func.sum(Device.open_findings), 0),
                                    func.coalesce(func.sum(Device.kev_findings), 0), _n(Device.loc_confidence == "high"))
                             .where(*where).group_by(*keys).order_by(func.count().desc()).limit(2000))).all()
    out = [{"state": r[0], "city": r[1], "office": r[2], "site": r[3], "assets": r[4], "scanner": r[5], "edr": r[6],
            "directory": r[7], "pentest": r[8], "pentest_only": r[9], "open_findings": r[10], "kev": r[11], "high_confidence": r[12]}
           for r in rows]
    located = [x for x in out if any(x[k] for k in ("state", "city", "office", "site"))]
    unknown = sum(x["assets"] for x in out if x not in located)
    return {"locations": located, "unlocated": unknown,
            "states": sorted({x["state"] for x in located if x["state"]}),
            "cities": sorted({f"{x['city']}|{x['state'] or ''}" for x in located if x["city"]}),
            "offices": sorted({x["office"] for x in located if x["office"]}), "sites": sorted({x["site"] for x in located if x["site"]})}


@router.get("/subnets")
async def location_subnets(u: User = Depends(require_permission("devices", "read")), db: AsyncSession = Depends(get_session),
                           loc_state: str | None = _PLACE(), loc_city: str | None = _PLACE(), loc_office: str | None = _PLACE(),
                           loc_site: str | None = _PLACE()):
    """The internal subnets of one place (or of the unlocated assets, with no place given), with coverage."""
    from api.core.location import subnet_of
    from api.routes.device_context import coverage
    where = await _base(u, db)
    picked = {"loc_state": loc_state, "loc_city": loc_city, "loc_office": loc_office, "loc_site": loc_site}
    for key, col in (("loc_state", Device.loc_state), ("loc_city", Device.loc_city), ("loc_office", Device.loc_office), ("loc_site", Device.loc_site)):
        where.append(col == picked[key] if picked[key] else col.is_(None))
    nets: dict = defaultdict(lambda: {"assets": 0, "scanner": 0, "edr": 0, "directory": 0, "pentest": 0, "pentest_only": 0, "open_findings": 0})
    rows = (await db.execute(select(Device).where(*where).limit(MAX_SUBNET_ASSETS))).scalars()
    for d in rows:
        net = subnet_of(d.ip) or "no internal address"
        c, s = coverage(d), nets[net]
        s["assets"] += 1
        s["open_findings"] += d.open_findings or 0
        for k in ("scanner", "edr", "directory", "pentest"):
            s[k] += 1 if c[k] else 0
        s["pentest_only"] += 1 if c["pentest"] and not c["scanner"] else 0
    return {"subnets": sorted(({"subnet": k, **v} for k, v in nets.items()), key=lambda x: -x["assets"])[:500]}
