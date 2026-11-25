"""Shared filter, sort, and serializer logic for the device list, summary, and export."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

from sqlalchemy import func, or_, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import aliased, selectinload
from sqlalchemy.sql.functions import FunctionElement

import api.models.tag  # noqa: F401  -- aliased() below configures mappers, so every related model must be loaded
import api.models.vuln  # noqa: F401
from api.core.device_match import SOURCE_CODES, source_list
from api.core.encryption import search_hash
from api.models.device import Device, DeviceAssignment, DeviceTag, DeviceType, RiskGrade, HIDDEN_BY_DEFAULT, NON_HOST_TYPES
from api.models.user import User
from api.core.user_match import sign_in_names

Owner = aliased(User)

class greatest(FunctionElement):  # noqa: N801  -- reads like the SQL function it is
    """GREATEST(...) in Postgres; SQLite (tests) spells it max(...) with several arguments."""
    name = "greatest"
    inherit_cache = True


@compiles(greatest)
def _greatest_default(element, compiler, **kw):
    return f"GREATEST({compiler.process(element.clauses, **kw)})"


@compiles(greatest, "sqlite")
def _greatest_sqlite(element, compiler, **kw):
    return f"max({compiler.process(element.clauses, **kw)})"


# Every tool's sign of life for a device: a scan, an EDR heartbeat, an AD computer logon, a network probe answer
# (display and sorting only: last_seen itself stays the scanner's, which the coverage checks rely on)
SEEN_BY = (("Scanner", "last_seen"), ("EDR", "edr_last_seen"), ("AD logon", "ad_last_logon"), ("net probe", "alive_at"))
_NEVER = datetime(1970, 1, 1, tzinfo=timezone.utc)
LAST_SEEN_ANY = greatest(*(func.coalesce(getattr(Device, col), _NEVER) for _, col in SEEN_BY))


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def freshest(d: Device) -> tuple[datetime | None, str | None, dict]:
    """(newest sign of life from any tool, which tool, each tool's own time) for a device."""
    seen = {label: _aware(getattr(d, col, None)) for label, col in SEEN_BY}
    have = {k: v for k, v in seen.items() if v}
    if not have:
        return None, None, {}
    by = max(have, key=have.get)
    return have[by], by, {k: v.isoformat() for k, v in have.items()}


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
    "last_seen": LAST_SEEN_ANY,   # the freshest of scanner, EDR, AD logon and network probe
    "edr_active": Device.edr_active,
    "source": Device.source,
    "firewall_enabled": Device.firewall_enabled,
    "usb_storage_blocked": Device.usb_storage_blocked,
}

EXPORT_HEADER = ["Hostname", "FQDN", "User", "Assigned to", "Status", "IP", "MAC", "Type", "OS", "Grade", "Score", "Open findings",
                 "KEV findings", "Last seen", "EDR", "EDR vendor", "Host firewall", "USB storage blocked", "Internet exposed", "Sources", "Tags"]


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


INVENTORY_STATUSES = ("shipped", "lost", "stolen", "returned")


def location_filters(card: dict) -> list:
    """Where an asset is: office, AD site, city, state, or one internal subnet (matched by its keyed hash)."""
    out = []
    for key, col in (("loc_state", Device.loc_state), ("loc_city", Device.loc_city), ("loc_site", Device.loc_site),
                     ("loc_office", Device.loc_office)):
        if card.get(key):
            out.append(col == str(card[key])[:128])
    if card.get("subnet"):
        from api.core.encryption import search_hash
        from api.core.location import subnet_of
        net = subnet_of(str(card["subnet"]).split("/")[0])
        out.append(Device.subnet_hash == (search_hash(net) if net else "-"))
    return out


def card_filters(card: dict) -> list:
    """Same conditions the asset widgets count with, so a card and its list always agree."""
    from datetime import timedelta

    from api.dashboards import fleet
    from api.dashboards.m_assets import where
    dtype = "compute" if card.get("compute") else "cloud_resource" if card.get("asset") == "cloud" else "any"
    out = where(type("V", (), {"scope": None})(), {"device_type": dtype,
                                                   "os_family": card.get("os_family") or "any",
                                                   "missing": card.get("missing") or "none"})
    if card.get("active_days"):
        out.append(fleet.active(int(card["active_days"])))
    if card.get("asset") == "repositories":   # the Security Overview's Code tab
        out.append(Device.device_type == DeviceType.code_repository)
    elif card.get("asset") == "sites":       # its Web apps tab
        out.append(Device.device_type == DeviceType.website)
    elif card.get("asset") == "hosts":       # its Infrastructure tab: everything but repositories and sites
        out.append(Device.device_type.not_in(NON_HOST_TYPES))
    elif card.get("asset") == "cloud":       # its Cloud tab: resources a CSPM tool checks
        out.append(Device.device_type == DeviceType.cloud_resource)
    out += location_filters(card)
    if card.get("repo"):   # one code repository, by its "org/name"
        out += [Device.device_type == DeviceType.code_repository, Device.hostname == card["repo"]]
    if card.get("repo_org"):   # every repository of one organization; its own _ and % are not LIKE wildcards
        org = card["repo_org"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        out += [Device.device_type == DeviceType.code_repository, Device.hostname.like(f"{org}/%", escape="\\")]
    if card.get("new_days"):
        out.append(Device.created_at >= fleet.now().replace(tzinfo=None) - timedelta(days=int(card["new_days"])))
    if card.get("without"):   # no owner or application tag of that kind (Security Overview: Ownership and coverage)
        from api.dashboards.m_posture import _without_role
        out.append(_without_role(card.get("without_tags") or []))
    if card.get("unseen_days"):   # no tool has seen it in that many days
        cut = fleet.now() - timedelta(days=int(card["unseen_days"]))
        out += [Device.last_seen < cut, ~fleet.active(int(card["unseen_days"]))]
    if card.get("edr_quiet_days"):   # the EDR agent exists but hasn't reported in that many days
        out += [Device.edr_last_seen.is_not(None), Device.edr_last_seen < fleet.now() - timedelta(days=int(card["edr_quiet_days"]))]
    if card.get("with_findings"):
        out.append(Device.open_findings > 0)
    if card.get("internet"):
        out.append(Device.is_internet_exposed.is_(True))
    if card.get("kev"):   # the summary's "devices with known exploited" count
        out.append(Device.kev_findings > 0)
    if card.get("fix"):   # the assets one fix applies to: those with an open finding it resolves
        from api.models.vuln import Finding, FindingStatus
        out.append(Device.id.in_(select(Finding.device_id).where(
            Finding.fix_key == card["fix"], Finding.status.in_((FindingStatus.open, FindingStatus.in_progress)))))
    return out


def build_query(scope, q: str | None, grade: str | None, device_type: DeviceType | None,
                source: str | None, tags: list[str] | None, status: str | None = None, ad_stale_days: int | None = None,
                card: dict | None = None):
    """Return a SELECT of Device (with owner joined) filtered by scope and the request filters.
    card: the allow-listed filters a dashboard card links with (os_family, missing, active_days, new_days, compute)."""
    stmt = select(Device).outerjoin(Owner, Owner.id == Device.owner_user_id)
    if scope is not None:
        stmt = stmt.where(scope)
    if card:
        stmt = stmt.where(*card_filters(card))
    if ad_stale_days:   # AD computer objects with no logon for this many days (or never)
        from api.dashboards.m_directory import stale_computers
        quiet = (card or {}).get("ad_tools_quiet_days")
        stmt = stmt.where(*stale_computers(int(ad_stale_days), None, int(quiet) if quiet else None))
    if device_type:
        stmt = stmt.where(Device.device_type == device_type)
    elif not (card or {}).get("asset") == "cloud":
        stmt = stmt.where(Device.device_type.not_in(HIDDEN_BY_DEFAULT))
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
    elif status == "contained":  # network-isolated by the EDR
        stmt = stmt.where(Device.edr_contained.is_(True))
    elif status == "edr_hidden":  # hidden in the EDR console
        stmt = stmt.where(Device.edr_hidden.is_(True))
    elif status == "out_of_scope":  # Not In Scope, still running
        from api.core.device_scope_exempt import now
        stmt = stmt.where(Device.scope_exempt_until > now())
    if source in SOURCE_CODES:  # allow-listed, so it's safe inside LIKE
        stmt = stmt.where(Device.sources.like(f"%,{source},%"))
    elif source:
        stmt = stmt.where(Device.source == source[:64])
    if tags:
        from api.models.tag import Tag
        for tag in [t for t in tags if t][:10]:  # every tag must match (AND); "a|b" is either one (OR)
            tagged = select(DeviceTag.device_id).join(Tag, Tag.id == DeviceTag.tag_id).where(Tag.name.in_(tag_alternatives(tag)))
            stmt = stmt.where(Device.id.in_(tagged))
    if q:
        q = q.strip()[:200]
        like = _like(q)
        hashes = {search_hash(q), search_hash(q.lower()), *(search_hash(n) for n in sign_in_names(q))}
        # A person by their UPN, whole or its first half (jane.doe), or the directory username
        whole = search_hash(q.lower())
        person = or_(User.username.ilike(like, escape="\\"), User.upn_hash == whole, User.upn_local_hash == whole)
        named = select(User.id).where(person)
        assigned_to = select(DeviceAssignment.device_id).where(DeviceAssignment.user_id.in_(named))
        from api.models.tag import Tag
        # A tag's name or its value: "specops" finds app:SPECOPS, "pat@" finds app_owner:pat@acme.example
        tagged_like = select(DeviceTag.device_id).join(Tag, Tag.id == DeviceTag.tag_id).where(Tag.name.ilike(like, escape="\\"))
        stmt = stmt.where(or_(
            Device.id.in_(tagged_like),
            Device.hostname.ilike(like, escape="\\"),
            Device.fqdn.ilike(like, escape="\\"),
            func.upper(Device.mac_address) == q.upper(),
            Device.ip_hash.in_(hashes),
            Device.public_ip_hash.in_(hashes),   # the public address it reaches the internet from (EDR)
            Device.last_login_user_hash.in_(hashes),
            Owner.username.ilike(like, escape="\\"),
            Owner.upn_hash == whole,
            Owner.upn_local_hash == whole,
            Device.id.in_(assigned_to),
            # anyone the identity provider saw signed in on it, by UPN or its first half
            or_(*(Device.idp_login_keys.like(f"%,{h},%") for h in (whole, search_hash(q.lower().split("@", 1)[0])))),
        ))
    return stmt


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


def env_breakdown_query(filtered, rules=(("prefix", "env:"),)):
    """Per environment tag (the Environment role's rules in Tag mapping): device count, average score,
    grade-F count. Untagged devices land under None."""
    from sqlalchemy import case

    from api.models.tag import Tag
    from api.rules.apply import _like
    name = func.lower(Tag.name)
    conds = [name.like(f"{_like(v)}%", escape="\\") if kind == "prefix" else name == v.lower() for kind, v in rules]
    sub = filtered.order_by(None).with_only_columns(Device.id, Device.risk_score, Device.risk_grade).subquery()
    env = (select(DeviceTag.device_id, Tag.name.label("env")).join(Tag, Tag.id == DeviceTag.tag_id)
           .where(or_(*conds) if conds else Tag.name.is_(None)).subquery())
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


def display_name(d: Device) -> str | None:
    """A host's short name; a repository ("acme/payments") or a site ("shop.acme.example") keeps its whole name."""
    if d.device_type in NON_HOST_TYPES:
        return d.hostname
    return short_name(d.hostname)


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


def role_value(d: Device, key: str) -> str | None:
    """The first value a device's tags give for a tag role (Admin > Tag mapping)."""
    from api.core import tag_roles
    return tag_roles.first(tag_names(d), (key,))


def location(d: Device) -> str | None:
    return role_value(d, "location") or tag_value(d, "location")


def environment(d: Device) -> str | None:
    """The Environment tag role wins; then an env-like tag word; then the nearest AD OU naming one (OU=Prod)."""
    mapped = role_value(d, "environment")
    if mapped:
        return _ENV_WORDS.get(mapped.lower(), mapped)
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
    """Explicit owner; then the technical, application or executive owner tag role; then any scanner owner tag;
    then whoever signed in last."""
    from api.core import tag_roles
    a = assigned_user(d)
    if a:
        return a["name"]
    return (tag_roles.first(tag_names(d), tag_roles.OWNER_ROLES) or tag_value(d, "owner")
            or _person(d.owner) or d.last_login_user)


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


def _exempt(d: Device) -> bool:
    from api.core.device_scope_exempt import is_exempt
    return is_exempt(d)


def summary(d: Device) -> dict:
    return {
        "id": str(d.id),
        "hostname": display_name(d),
        "fqdn": full_name(d) if d.device_type not in NON_HOST_TYPES else None,
        "user": user_label(d),
        "assigned_user": assigned_user(d),
        "inventory_status": inventory_status(d),
        "out_of_scope_until": d.scope_exempt_until.isoformat() if d.scope_exempt_until and _exempt(d) else None,
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
        **_seen_fields(d),
        "edr_active": d.edr_active,
        "edr_vendor": d.edr_vendor,
        "edr_contained": bool(d.edr_contained),
        "edr_hidden": bool(d.edr_hidden),
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


def _seen_fields(d: Device) -> dict:
    at, by, each = freshest(d)
    return {"last_seen": at.isoformat() if at else None, "last_seen_by": by, "seen_by": each,
            "scan_last_seen": d.last_seen.isoformat() if d.last_seen else None}


def export_row(d: Device) -> list:
    s = summary(d)
    a, st = s["assigned_user"], s["inventory_status"]
    return [s["hostname"], s["fqdn"], s["user"], a["username"] if a else None, st["status"] if st else None, s["ip"], d.mac_address, s["device_type"], s["os"], s["risk_grade"],
            s["risk_score"], s["open_findings"], s["kev_findings"], s["last_seen"], s["edr_active"],
            s["edr_vendor"], s["firewall_enabled"], s["usb_storage_blocked"], s["is_internet_exposed"], " ".join(s["sources"]), "; ".join(s["tags"])]



def tag_alternatives(value: str) -> list[str]:
    """One tag filter value: a tag name, or several joined by "|" that mean the same thing (the same application
    tagged by two tools, say "app:MuleSoft|r7:app:MuleSoft"). At most 10, each at most 128 characters."""
    return [t[:128] for t in str(value or "")[:1400].split("|") if t][:10]


def tag_cond(tags: list[str] | None):
    """Device condition: matches every one of these tag filters (at most 10), or None. A filter value may list
    alternatives joined by "|", any of which counts."""
    from sqlalchemy import and_

    from api.models.tag import Tag
    wanted = [tag_alternatives(t) for t in (tags or []) if t][:10]
    wanted = [w for w in wanted if w]
    if not wanted:
        return None
    return and_(*(Device.id.in_(select(DeviceTag.device_id).join(Tag, Tag.id == DeviceTag.tag_id).where(Tag.name.in_(w)))
                  for w in wanted))


def with_tags(scope, tags: list[str] | None):
    """A viewer's device scope narrowed to a tag focus (dashboard owner filter and the like)."""
    from sqlalchemy import and_
    cond = tag_cond(tags)
    if cond is None:
        return scope
    return cond if scope is None else and_(scope, cond)


def with_location(scope, card: dict):
    """A viewer's device scope narrowed to where assets are (the Vulnerabilities page's location filter)."""
    from sqlalchemy import and_
    conds = location_filters(card)
    if not conds:
        return scope
    cond = and_(*conds)
    return cond if scope is None else and_(scope, cond)
