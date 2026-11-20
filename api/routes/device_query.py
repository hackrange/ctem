"""Shared filter, sort, and serializer logic for the device list, summary, and export."""
from __future__ import annotations

import ipaddress

from sqlalchemy import func, or_, select
from sqlalchemy.orm import aliased, selectinload

import api.models.tag  # noqa: F401  -- aliased() below configures mappers, so every related model must be loaded
import api.models.vuln  # noqa: F401
from api.core.encryption import search_hash
from api.models.device import Device, DeviceTag, DeviceType, RiskGrade
from api.models.user import User

Owner = aliased(User)

# Allow-listed sort keys -> columns. Anything else falls back to risk_score.
SORTS = {
    "hostname": Device.hostname,
    "user": Owner.username,
    "device_type": Device.device_type,
    "os": Device.os,
    "risk_grade": Device.risk_grade,
    "risk_score": Device.risk_score,
    "open_findings": Device.open_findings,
    "kev_findings": Device.kev_findings,
    "last_seen": Device.last_seen,
    "edr_active": Device.edr_active,
    "source": Device.source,
}

EXPORT_HEADER = ["Hostname", "FQDN", "User", "IP", "MAC", "Type", "OS", "Grade", "Score", "Open findings",
                 "KEV findings", "Last seen", "EDR", "EDR vendor", "Internet exposed", "Source", "Tags"]


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def build_query(scope, q: str | None, grade: str | None, device_type: DeviceType | None,
                source: str | None, tags: list[str] | None):
    """Return a SELECT of Device (with owner joined) filtered by scope and the request filters."""
    stmt = select(Device).outerjoin(Owner, Owner.id == Device.owner_user_id)
    if scope is not None:
        stmt = stmt.where(scope)
    if device_type:
        stmt = stmt.where(Device.device_type == device_type)
    if grade:
        g = grade.strip().upper()
        if g == "NONE":
            stmt = stmt.where(Device.risk_grade.is_(None))
        elif g in RiskGrade.__members__:
            stmt = stmt.where(Device.risk_grade == RiskGrade[g])
    if source:
        stmt = stmt.where(Device.source == source[:64])
    if tags:
        from api.models.tag import Tag
        for tag in [t for t in tags if t][:10]:  # every tag must match (AND)
            tagged = select(DeviceTag.device_id).join(Tag, Tag.id == DeviceTag.tag_id).where(Tag.name == tag[:128])
            stmt = stmt.where(Device.id.in_(tagged))
    if q:
        q = q.strip()[:200]
        like = _like(q)
        hashes = {search_hash(q), search_hash(q.lower())}
        stmt = stmt.where(or_(
            Device.hostname.ilike(like, escape="\\"),
            Device.fqdn.ilike(like, escape="\\"),
            func.upper(Device.mac_address) == q.upper(),
            Device.ip_hash.in_(hashes),
            Device.last_login_user_hash.in_(hashes),
            Owner.username.ilike(like, escape="\\"),
        ))
    return stmt


def sorted_query(stmt, sort: str | None, order: str | None):
    col = SORTS.get(sort or "", Device.risk_score)
    direction = col.asc() if (order or "").lower() == "asc" else col.desc()
    return stmt.order_by(direction.nullslast(), Device.hostname.asc(), Device.id.asc())


def with_relations(stmt):
    return stmt.options(selectinload(Device.tags).selectinload(DeviceTag.tag), selectinload(Device.owner))


def count_query(stmt):
    return select(func.count()).select_from(stmt.order_by(None).subquery())


def grade_counts_query(filtered):
    sub = filtered.order_by(None).with_only_columns(Device.id, Device.risk_grade, Device.kev_findings).subquery()
    return select(sub.c.risk_grade, func.count(), func.count().filter(sub.c.kev_findings > 0)).group_by(sub.c.risk_grade)


def env_breakdown_query(filtered):
    """Per env:* tag: device count, average score, grade-F count. Untagged devices land under None."""
    from sqlalchemy import case

    from api.models.tag import Tag
    sub = filtered.order_by(None).with_only_columns(Device.id, Device.risk_score, Device.risk_grade).subquery()
    env = (select(DeviceTag.device_id, Tag.name.label("env")).join(Tag, Tag.id == DeviceTag.tag_id)
           .where(Tag.name.like("env:%")).subquery())
    return (select(env.c.env, func.count(sub.c.id), func.avg(sub.c.risk_score),
                   func.sum(case((sub.c.risk_grade == RiskGrade.F, 1), else_=0)))
            .select_from(sub).outerjoin(env, env.c.device_id == sub.c.id).group_by(env.c.env))


def user_label(d: Device) -> str | None:
    owner = d.owner
    if owner is not None:
        return getattr(owner, "display_name", None) or owner.username
    return d.last_login_user


def short_name(name: str | None) -> str | None:
    """desktop001.ad.acme.example shows as desktop001; IPs stay whole."""
    if not name or "." not in name or _is_ip(name):
        return name
    return name.split(".", 1)[0]


def full_name(d: Device) -> str | None:
    if d.fqdn:
        return d.fqdn
    return d.hostname if d.hostname and "." in d.hostname and not _is_ip(d.hostname) else None


def _is_ip(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def summary(d: Device) -> dict:
    return {
        "id": str(d.id),
        "hostname": short_name(d.hostname),
        "fqdn": full_name(d),
        "user": user_label(d),
        "ip": d.ip,
        "os": d.os,
        "device_type": d.device_type.value,
        "risk_score": d.risk_score,
        "risk_grade": d.risk_grade.value if d.risk_grade else None,
        "open_findings": d.open_findings or 0,
        "kev_findings": d.kev_findings or 0,
        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        "edr_active": d.edr_active,
        "edr_vendor": d.edr_vendor,
        "ad_joined": d.ad_joined,
        "is_internet_exposed": d.is_internet_exposed,
        "source": d.source,
        "tags": [dt.tag.name for dt in d.tags if dt.tag],
    }


def export_row(d: Device) -> list:
    s = summary(d)
    return [s["hostname"], s["fqdn"], s["user"], s["ip"], d.mac_address, s["device_type"], s["os"], s["risk_grade"],
            s["risk_score"], s["open_findings"], s["kev_findings"], s["last_seen"], s["edr_active"],
            s["edr_vendor"], s["is_internet_exposed"], s["source"], "; ".join(s["tags"])]

