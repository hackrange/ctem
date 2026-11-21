"""Cloud Inventory: every cloud instance next to what makes it breachable: is it reachable from the internet, on
which ports and through which firewall, does a scanner and an EDR see it, and what it is exposed to (open
and known-exploited findings). Read from cloud_assets joined to the CTEM device it matched, if any."""
from __future__ import annotations

from sqlalchemy import String, and_, cast, func, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.grc.checks import SCANNERS
from api.models.cloud import CloudAsset
from api.models.device import Device, DeviceTag, RiskGrade

SORTS = {"name": CloudAsset.name, "provider": CloudAsset.provider, "region": CloudAsset.region,
         "account": CloudAsset.account, "exposed": CloudAsset.internet_exposed, "risk": Device.risk_score,
         "open": Device.open_findings, "kev": Device.kev_findings}
FILTERS = ("exposed", "breachable", "unscanned", "no_edr", "kev", "unmatched")


def _scanned():
    srcs = func.coalesce(Device.sources, "")
    return or_(*(srcs.like(f"%,{s},%") for s in SCANNERS))


def _breachable():
    """Reachable from the internet and carrying a known-exploited finding or a grade-F risk."""
    return and_(CloudAsset.internet_exposed.is_(True),
                or_(func.coalesce(Device.kev_findings, 0) > 0, Device.risk_grade == RiskGrade.F))


def conditions(provider: str | None, account: str | None, region: str | None, show: str | None, q: str | None) -> list:
    """Allow-listed filters only: names are compared as bound values, never built into SQL."""
    from api.rules.apply import _like
    out = []
    if provider:
        out.append(CloudAsset.provider == provider)
    if account:
        out.append(CloudAsset.account == account)
    if region:
        out.append(CloudAsset.region == region)
    if show == "exposed":
        out.append(CloudAsset.internet_exposed.is_(True))
    elif show == "breachable":
        out.append(_breachable())
    elif show == "unscanned":
        out.append(or_(CloudAsset.device_id.is_(None), not_(_scanned())))
    elif show == "no_edr":
        out.append(or_(CloudAsset.device_id.is_(None), Device.edr_active.is_not(True)))
    elif show == "kev":
        out.append(func.coalesce(Device.kev_findings, 0) > 0)
    elif show == "unmatched":
        out.append(CloudAsset.device_id.is_(None))
    if q and q.strip():
        like = f"%{_like(q.strip()[:120])}%"
        out.append(or_(func.lower(func.coalesce(CloudAsset.name, "")).like(like, escape="\\"),
                       func.lower(CloudAsset.resource_id).like(like, escape="\\"),
                       func.lower(cast(CloudAsset.public_ips, String)).like(like, escape="\\"),
                       func.lower(func.coalesce(Device.hostname, "")).like(like, escape="\\")))
    return out


def base():
    return select(CloudAsset, Device).outerjoin(Device, Device.id == CloudAsset.device_id)


async def summary(db: AsyncSession) -> dict:
    stmt = select(func.count(), func.count().filter(CloudAsset.internet_exposed.is_(True)),
                  func.count().filter(_breachable()),
                  func.count().filter(or_(CloudAsset.device_id.is_(None), not_(_scanned()))),
                  func.count().filter(or_(CloudAsset.device_id.is_(None), Device.edr_active.is_not(True))),
                  func.count().filter(CloudAsset.device_id.is_(None))
                  ).select_from(CloudAsset).outerjoin(Device, Device.id == CloudAsset.device_id)
    total, exposed, breachable, unscanned, no_edr, unmatched = (await db.execute(stmt)).one()
    providers = [{"provider": p, "count": n} for p, n in (await db.execute(
        select(CloudAsset.provider, func.count()).group_by(CloudAsset.provider).order_by(func.count().desc()))).all()]
    accounts = [{"provider": p, "account": a, "count": n} for p, a, n in (await db.execute(
        select(CloudAsset.provider, CloudAsset.account, func.count()).group_by(CloudAsset.provider, CloudAsset.account)
        .order_by(func.count().desc()).limit(50))).all()]
    regions = sorted({r for (r,) in (await db.execute(select(CloudAsset.region).distinct())).all() if r})
    return {"total": total, "exposed": exposed, "breachable": breachable, "unscanned": unscanned, "no_edr": no_edr,
            "unmatched": unmatched, "providers": providers, "accounts": accounts, "regions": regions}


def _port(p: dict) -> str:
    rng = "all" if p.get("from") is None else (str(p["from"]) if p["from"] == p.get("to") else f"{p['from']}-{p['to']}")
    return f"{rng}/{p.get('proto')}"


def row(a: CloudAsset, d: Device | None) -> dict:
    from api.core import tag_roles
    from api.routes import device_query as dq
    ports = a.ports or []
    srcs = (d.sources or "") if d is not None else ""
    names = [dt.tag.name for dt in (d.tags or []) if dt.tag] if d is not None else []
    return {
        "id": str(a.id), "provider": a.provider, "account": a.account, "region": a.region, "name": a.name,
        "resource_id": a.resource_id, "public_ips": a.public_ips or [], "private_ips": a.private_ips or [],
        "internet_exposed": a.internet_exposed,
        "internet_ports": [_port(p) for p in ports if p.get("reach") == "internet"][:20],
        "restricted_ports": sum(1 for p in ports if p.get("reach") != "internet"),
        "firewalls": [{"type": f.get("type"), "id": f.get("id"), "name": f.get("name")} for f in (a.firewalls or [])][:10],
        "device_id": str(d.id) if d is not None else None,
        "hostname": dq.short_name(d.hostname) if d is not None else None,
        "scanned": any(f",{s}," in srcs for s in SCANNERS),
        "edr": bool(d is not None and d.edr_active),
        "open_findings": (d.open_findings or 0) if d is not None else None,
        "kev_findings": (d.kev_findings or 0) if d is not None else None,
        "risk_grade": d.risk_grade.value if d is not None and d.risk_grade else None,
        "risk_score": d.risk_score if d is not None else None,
        "owner": tag_roles.first(names, tag_roles.OWNER_ROLES) if names else None,
        "seen_at": a.seen_at.isoformat() if a.seen_at else None,
    }


def with_tags(stmt):
    return stmt.options(selectinload(Device.tags).selectinload(DeviceTag.tag))
