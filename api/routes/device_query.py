"""Shared filter, sort, and serializer logic for the device list, summary, and export."""
from __future__ import annotations

import ipaddress
import re

from sqlalchemy import func, or_, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import aliased, selectinload

import api.models.tag  # noqa: F401  -- aliased() below configures mappers, so every related model must be loaded
import api.models.vuln  # noqa: F401
from api.core.device_match import SOURCE_CODES, source_list
from api.core.encryption import search_hash
from api.models.device import Device, DeviceAssignment, DeviceTag, DeviceType, RiskGrade
from api.models.user import User

Owner = aliased(User)

# Allow-listed sort keys -> columns. Anything else falls back to risk_score.
SORTS = {
    "hostname": Device.host_key,
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
    "firewall_enabled": Device.firewall_enabled,
    "usb_storage_blocked": Device.usb_storage_blocked,
}

EXPORT_HEADER = ["Hostname", "FQDN", "User", "Assigned to", "Status", "IP", "MAC", "Type", "OS", "Grade", "Score", "Open findings",
                 "KEV findings", "Last seen", "EDR", "EDR vendor", "Firewall", "USB storage blocked", "Internet exposed", "Sources", "Tags"]


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


INVENTORY_STATUSES = ("shipped", "lost", "stolen", "returned")


def build_query(scope, q: str | None, grade: str | None, device_type: DeviceType | None,
                source: str | None, tags: list[str] | None, status: str | None = None):
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
    if status in INVENTORY_STATUSES:
        stmt = stmt.where(Device.id.in_(select(DeviceAssignment.device_id).where(DeviceAssignment.status == status)))
    elif status == "assigned":
        stmt = stmt.where(Device.id.in_(select(DeviceAssignment.device_id).where(DeviceAssignment.user_id.is_not(None))))
    if source in SOURCE_CODES:  # allow-listed, so it's safe inside LIKE
        stmt = stmt.where(Device.sources.like(f"%,{source},%"))
    elif source:
        stmt = stmt.where(Device.source == source[:64])
    if tags:
        from api.models.tag import Tag
        for tag in [t for t in tags if t][:10]:  # every tag must match (AND)
            tagged = select(DeviceTag.device_id).join(Tag, Tag.id == DeviceTag.tag_id).where(Tag.name == tag[:128])
            stmt = stmt.where(Device.id.in_(tagged))
    if q:
        q = q.strip()[:200]
        like = _like(q)
        hashes = {search_hash(q), search_hash(q.lower()), *(search_hash(n) for n in sign_in_names(q))}
        named = select(User.id).where(or_(User.username.ilike(like, escape="\\"), User.upn_hash == search_hash(q.lower())))
        assigned_to = select(DeviceAssignment.device_id).where(DeviceAssignment.user_id.in_(named))
        stmt = stmt.where(or_(
            Device.hostname.ilike(like, escape="\\"),
            Device.fqdn.ilike(like, escape="\\"),
            func.upper(Device.mac_address) == q.upper(),
            Device.ip_hash.in_(hashes),
            Device.last_login_user_hash.in_(hashes),
            Owner.username.ilike(like, escape="\\"),
            Owner.upn_hash == search_hash(q.lower()),
            Device.id.in_(assigned_to),
        ))
    return stmt


def sign_in_names(q: str) -> list[str]:
    """dhollin also finds machines where they signed in as sulocal_dhollin."""
    from api.core.config import get_settings
    from api.core.user_match import bare

    b = bare(q)
    if not b:
        return []
    prefixes = [p.strip().lower() for p in get_settings().account_alias_prefixes.split(",") if p.strip()]
    return [b, *(p + b for p in prefixes)]


def sorted_query(stmt, sort: str | None, order: str | None):
    col = SORTS.get(sort or "", Device.risk_score)
    direction = col.asc() if (order or "").lower() == "asc" else col.desc()
    return stmt.order_by(direction.nullslast(), Device.hostname.asc(), Device.id.asc())


def with_relations(stmt):
    return stmt.options(selectinload(Device.tags).selectinload(DeviceTag.tag), selectinload(Device.owner),
                        *ASSIGNMENT_LOAD)


# Load these wherever a device's user is shown; assignment() returns None if a query forgot to
ASSIGNMENT_LOAD = (selectinload(Device.assignment).selectinload(DeviceAssignment.user),)


def assignment(d: Device):
    if "assignment" in sa_inspect(d).unloaded:
        return None
    return d.assignment


def _person(u) -> str | None:
    return (getattr(u, "display_name", None) or u.username) if u is not None else None


def inventory_status(d: Device) -> dict | None:
    a = assignment(d)
    if a is None or not a.status:
        return None
    return {"status": a.status, "by": a.status_by, "at": a.status_at.isoformat() if a.status_at else None,
            "note": a.status_note, "carrier": a.carrier, "tracking_number": a.tracking_number}


def assigned_user(d: Device) -> dict | None:
    a = assignment(d)
    if a is None or a.user is None:
        return None
    return {"id": str(a.user_id), "username": a.user.username, "name": _person(a.user), "upn": getattr(a.user, "upn", None), "title": getattr(a.user, "title", None),
            "assigned_by": a.assigned_by, "assigned_at": a.created_at.isoformat() if a.created_at else None,
            "note": a.note}


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
    """Who should be on it: the assignment, then the directory user seen signing in, then the raw sign-in."""
    a = assigned_user(d)
    if a:
        return a["name"]
    return _person(d.owner) or d.last_login_user


def short_name(name: str | None) -> str | None:
    """desktop001.ad.acme.example and Desktop001$ both show as DESKTOP001; IPs stay whole."""
    if not name or _is_ip(name):
        return name
    return name.split(".", 1)[0].rstrip("$").upper()


def full_name(d: Device) -> str | None:
    if d.fqdn:
        return d.fqdn.upper()
    return d.hostname.upper() if d.hostname and "." in d.hostname and not _is_ip(d.hostname) else None


def severity(cvss: float | None, contained: bool = False) -> str:
    """CVSS band, except a contained host can't be reached, so all of it is info until it's released."""
    if contained:
        return "info"
    c = cvss or 0.0
    return "critical" if c >= 9 else "high" if c >= 7 else "medium" if c >= 4 else "low"


_ENV_WORDS = {"prod": "Production", "production": "Production", "prd": "Production", "dev": "Development",
              "development": "Development", "qa": "QA", "stg": "Staging", "stage": "Staging", "staging": "Staging",
              "uat": "UAT", "test": "Test", "tst": "Test", "sandbox": "Sandbox", "dr": "DR"}


def environment(d: Device) -> str | None:
    """An env: tag wins; otherwise the nearest AD OU that names an environment (OU=Prod, OU=DE Test)."""
    for name in tag_names(d):
        name = name.lower()
        if name.startswith("env:") and name[4:]:
            return _ENV_WORDS.get(name[4:], name[4:].title())
        bare = name.split(":", 1)[-1]  # r7:production, or a plain "prod" tag
        if bare in _ENV_WORDS:
            return _ENV_WORDS[bare]
    for part in (d.ad_dn or "").split(","):
        if part.strip().upper().startswith("OU="):
            for word in re.split(r"[\s_-]+", part.strip()[3:].lower()):
                if word in _ENV_WORDS:
                    return _ENV_WORDS[word]
    return None


def tag_names(d: Device) -> list[str]:
    return [dt.tag.name for dt in d.tags or [] if dt.tag]


def tag_value(d: Device, prefix: str) -> str | None:
    """First tag under a prefix, e.g. location:Dallas -> Dallas."""
    return next((n.split(":", 1)[1] for n in tag_names(d) if n.startswith(prefix + ":")), None)


def owner_label(d: Device) -> str | None:
    """Explicit owner, then the scanner's owner tag, then whoever signed in last."""
    a = assigned_user(d)
    if a:
        return a["name"]
    return tag_value(d, "owner") or _person(d.owner) or d.last_login_user


def source_codes(d: Device) -> list[str]:
    names = source_list(d) or ([d.source] if d.source else [])
    order = list(SOURCE_CODES)
    names = sorted(names, key=lambda n: order.index(n) if n in order else len(order))
    return [SOURCE_CODES.get(n, n.upper()) for n in names]


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
        "assigned_user": assigned_user(d),
        "inventory_status": inventory_status(d),
        "detected_user": _person(d.owner),
        "detected_user_id": str(d.owner_user_id) if d.owner_user_id else None,
        "last_login_user": d.last_login_user,
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
        "edr_contained": bool(d.edr_contained),
        "criticality": d.criticality,
        "raw_risk_score": d.raw_risk_score,
        "raw_risk_grade": d.raw_risk_grade,
        "firewall_enabled": d.firewall_enabled,
        "usb_storage_blocked": d.usb_storage_blocked,
        "ad_joined": d.ad_joined,
        "is_internet_exposed": d.is_internet_exposed,
        "source": d.source,
        "sources": source_codes(d),
        "tags": [dt.tag.name for dt in d.tags if dt.tag],
    }


def export_row(d: Device) -> list:
    s = summary(d)
    a, st = s["assigned_user"], s["inventory_status"]
    return [s["hostname"], s["fqdn"], s["user"], a["username"] if a else None, st["status"] if st else None, s["ip"], d.mac_address, s["device_type"], s["os"], s["risk_grade"],
            s["risk_score"], s["open_findings"], s["kev_findings"], s["last_seen"], s["edr_active"],
            s["edr_vendor"], s["firewall_enabled"], s["usb_storage_blocked"], s["is_internet_exposed"], " ".join(s["sources"]), "; ".join(s["tags"])]

