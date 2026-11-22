"""Widget filters: conditions on tags, tag-mapping roles (Executive owner, Application...), sources, device type,
OS family, criticality and risk grade, combined with "all" (AND) or "any" (OR). They narrow the devices a widget
counts, the same way a viewer's device scope does, so every device-based widget honors them.

Stored on a widget as "filters": [{"field", "op", "value"}] and "filter_match": "all" | "any". Every field, op and
value is checked here; values are only ever bound parameters."""
from __future__ import annotations

from sqlalchemy import and_, false, func, not_, or_, select

from api.models.device import Device, DeviceTag, DeviceType, RiskGrade

MAX = 10
FIELDS = {
    "tag": ("is", "is_not", "starts_with", "not_starts_with"),
    "role": ("is", "is_not", "any", "none"),
    "source": ("is", "is_not"),
    "device_type": ("is", "is_not"),
    "os_family": ("is", "is_not"),
    "criticality": ("is", "is_not"),
    "grade": ("is", "is_not"),
    "access": ("mine",),
    "ou": ("not_in", "in"),   # directory OU anywhere in the device's DN ("OU=Blocked_Computers" or just the name)   # only devices the viewer is granted (tags or assignment), whatever their role
}
# Device values by the data source they come from. type picks the operators; only these columns are reachable.
ATTRS = {
    # Directory (AD)
    "ad_last_logon": ("Last AD logon", "Directory (AD)", "days"),
    "ad_joined": ("In AD", "Directory (AD)", "bool"),
    # Vulnerability scanner
    "last_seen": ("Last seen by a scanner", "Vulnerability scanner", "days"),
    "risk_score": ("Risk score (0-100)", "Vulnerability scanner", "number"),
    "open_findings": ("Open findings", "Vulnerability scanner", "number"),
    "kev_findings": ("Known exploited (KEV) findings", "Vulnerability scanner", "number"),
    "is_internet_exposed": ("Internet exposed", "Vulnerability scanner", "bool"),
    # EDR
    "edr_last_seen": ("Last seen by the EDR", "EDR", "days"),
    "edr_active": ("EDR sensor working", "EDR", "bool"),
    "edr_contained": ("Contained by the EDR", "EDR", "bool"),
    "edr_hidden": ("Hidden in the EDR console", "EDR", "bool"),
    "edr_vendor": ("EDR product", "EDR", "text"),
    "firewall_enabled": ("Host firewall on", "EDR", "bool"),
    "usb_storage_blocked": ("USB storage blocked", "EDR", "bool"),
    # Device
    "hostname": ("Hostname", "Device", "text"),
    "fqdn": ("FQDN", "Device", "text"),
    "os": ("Operating system", "Device", "text"),
    "os_version": ("OS version", "Device", "text"),
    "created_at": ("First seen by CTEM", "Device", "days"),
    # Cloud
    "in_cloud": ("A cloud instance", "Cloud", "bool"),
}
ATTR_OPS = {
    "text": ("contains", "not_contains", "starts_with", "not_starts_with", "ends_with", "not_ends_with", "equals", "not_equals",
             "is_set", "is_empty"),
    "number": ("gt", "gte", "lt", "lte", "eq"),
    "days": ("older_than", "within", "never", "ever"),
    "bool": ("is_true", "is_false"),
}
_NO_ATTR_VALUE = {"is_set", "is_empty", "never", "ever", "is_true", "is_false"}

NEEDS_VALUE = {"is", "is_not", "starts_with", "not_starts_with", "in", "not_in"}


def _text(v, n=128) -> str | None:
    if not isinstance(v, str):
        return None
    v = " ".join(v.split())[:n]
    return v if v and not any(c in v for c in "<>") else None


def clean(raw) -> list[dict]:
    """Known fields, ops and values only; anything else is dropped. Role filters are {"field": "role", "role": key}."""
    from api.core import tag_roles
    from api.core.device_match import SOURCE_CODES
    from api.dashboards import fleet
    out = []
    for f in raw if isinstance(raw, list) else []:
        if isinstance(f, dict) and f.get("field") == "attr":
            c = _clean_attr(f)
            if c:
                out.append(c)
            if len(out) >= MAX:
                break
            continue
        if not isinstance(f, dict) or f.get("field") not in FIELDS or f.get("op") not in FIELDS[f["field"]]:
            continue
        field, op = f["field"], f["op"]
        c = {"field": field, "op": op}
        if field == "role":
            if not isinstance(f.get("role"), str) or not tag_roles.valid_key(f["role"]):
                continue
            c["role"] = f["role"]
        if op in NEEDS_VALUE:
            v = _text(f.get("value"))
            ok = {"source": lambda x: x in SOURCE_CODES, "device_type": lambda x: x in DeviceType.__members__,
                  "os_family": lambda x: x in fleet.OS_FAMILIES, "grade": lambda x: x in RiskGrade.__members__}.get(field)
            if v is None or (ok and not ok(v)):
                continue
            c["value"] = v
        out.append(c)
        if len(out) >= MAX:
            break
    return out


def _clean_attr(f: dict) -> dict | None:
    spec = ATTRS.get(f.get("attr"))
    if spec is None or f.get("op") not in ATTR_OPS[spec[2]]:
        return None
    c = {"field": "attr", "attr": f["attr"], "op": f["op"]}
    if f["op"] in _NO_ATTR_VALUE:
        return c
    kind = spec[2]
    try:
        if kind == "number":
            v = float(f.get("value"))
            if not -1e9 < v < 1e9:
                return None
            c["value"] = int(v) if v.is_integer() else round(v, 2)
        elif kind == "days":
            c["value"] = min(max(int(float(f.get("value"))), 0), 3650)
        else:
            v = _text(f.get("value"))
            if v is None:
                return None
            c["value"] = v
    except (TypeError, ValueError):
        return None
    return c


def _attr(f: dict):
    """One condition on a device value. The column comes from the ATTRS allow-list; the value is bound."""
    from datetime import timedelta

    from api.dashboards import fleet
    key, op, v = f["attr"], f["op"], f.get("value")
    kind = ATTRS[key][2]
    if key == "in_cloud":
        c = Device.id.in_(fleet.cloud_ids())
        return c if op == "is_true" else not_(c)
    col = getattr(Device, key)
    if kind == "bool":
        return col.is_(True) if op == "is_true" else or_(col.is_(False), col.is_(None))
    if kind == "number":
        x = func.coalesce(col, 0)
        return {"gt": x > v, "gte": x >= v, "lt": x < v, "lte": x <= v, "eq": x == v}[op]
    if kind == "days":
        if op == "never":
            return col.is_(None)
        if op == "ever":
            return col.is_not(None)
        cut = fleet.now() - timedelta(days=v)
        if key == "created_at":   # stored without a time zone
            cut = cut.replace(tzinfo=None)
        return or_(col.is_(None), col < cut) if op == "older_than" else col >= cut   # never seen counts as old
    t = func.lower(func.coalesce(col, ""))
    lv = (v or "").lower()
    return {"contains": t.like(f"%{_like(lv)}%", escape="\\"), "not_contains": ~t.like(f"%{_like(lv)}%", escape="\\"),
            "starts_with": t.like(f"{_like(lv)}%", escape="\\"), "not_starts_with": ~t.like(f"{_like(lv)}%", escape="\\"),
            "ends_with": t.like(f"%{_like(lv)}", escape="\\"), "not_ends_with": ~t.like(f"%{_like(lv)}", escape="\\"),
            "equals": t == lv, "not_equals": t != lv, "is_set": t != "", "is_empty": t == ""}[op]


def _like(v: str) -> str:
    return v.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _tagged(cond):
    from api.models.tag import Tag
    return Device.id.in_(select(DeviceTag.device_id).join(Tag, Tag.id == DeviceTag.tag_id).where(cond))


def _norm(v: str) -> str:
    """Compare names the way people type them: any case, and "Pat_Lee", "Pat-Lee" or "Pat  Lee" as "pat lee"."""
    return " ".join(v.replace("_", " ").replace("-", " ").lower().split())


async def _role_tags(db, key: str, value: str | None) -> list[str]:
    """Tag names the mapping assigns to this role (and, given a value, that value, compared as the dashboards show
    it, any case). Resolved through the mapping itself so tidied values ("Jeffrey_Davis") still match."""
    from api.core import tag_roles
    from api.models.tag import Tag
    roles = tag_roles.current()
    role = next((r for r in roles if r.key == key), None)
    if role is None or not role.rules:
        return []
    name = func.lower(Tag.name)
    conds = [name == rule if kind == "exact" else name.like(_like(rule) + "%", escape="\\") for kind, rule in role.rules]
    names = (await db.execute(select(Tag.name).where(or_(*conds)).limit(20000))).scalars().all()
    out = []
    for n in names:
        m = tag_roles.match(n, roles)
        if m and m[0] == key and (value is None or _norm(m[1]) == _norm(value)):
            out.append(n)
    return out


def _one(f: dict):
    from api.dashboards import fleet
    from api.models.tag import Tag
    field, op, v = f["field"], f["op"], f.get("value")
    neg = op in ("is_not", "not_starts_with", "none", "not_in")
    if field == "access":
        return f["_cond"]
    if field == "attr":
        return _attr(f)
    if field == "ou":
        from api.core.device_ou import ou_key
        c = func.coalesce(Device.ad_ou_keys, "").like(f"%,{ou_key(v)},%")   # a hex key, nothing to escape
        return not_(c) if neg else c
    if field == "tag":
        c = _tagged(func.lower(Tag.name).like(_like(v) + "%", escape="\\") if "starts" in op else func.lower(Tag.name) == v.lower())
    elif field == "role":
        tags = f.get("_tags") or []
        c = _tagged(Tag.name.in_(tags)) if tags else false()
    elif field == "source":
        c = func.coalesce(Device.sources, "").like(f"%,{v},%")   # v is from the allow-list
    elif field == "device_type":
        c = Device.device_type == DeviceType[v]
    elif field == "os_family":
        c = fleet.os_family() == v
    elif field == "criticality":
        c = func.lower(func.coalesce(Device.criticality, "")) == v.lower()
    else:
        c = Device.risk_grade == RiskGrade[v]
    return not_(c) if neg else c


async def granted(db, user):
    """Devices this person is granted by tag (through their roles and groups) or by assignment. The same grants
    the device scope uses, applied even to roles that otherwise see everything, so anyone can view their own
    slice, including their own rules (Admin > Users > Data access)."""
    from api.models.device import DeviceAssignment
    from api.models.tag import GroupTagAccess
    tag_ids = [r[0] for r in (await db.execute(select(GroupTagAccess.tag_id).where(
        GroupTagAccess.role_name.in_(list(user.role_names) or ["__none__"])))).all()]
    from api.core import user_access
    if await user_access.sees_all(db, user):
        return Device.id.is_not(None)   # every asset
    tag_ids = sorted({str(t) for t in tag_ids} | await user_access.tag_ids(db, user))
    tagged = select(DeviceTag.device_id).where(DeviceTag.tag_id.in_(tag_ids or ["__none__"]))
    assigned = select(DeviceAssignment.device_id).where(DeviceAssignment.user_id == user.id)
    return or_(Device.id.in_(tagged), Device.id.in_(assigned))


def personal(filters: list[dict]) -> bool:
    """The result depends on who is looking (so it's cached per person)."""
    return any(f["field"] == "access" for f in filters)


async def where(db, filters: list[dict], match: str = "all", user=None):
    """The filter as one condition on Device. Role filters are resolved to tag names first."""
    ready = []
    for f in filters:
        if f["field"] == "access":
            f = {**f, "_cond": await granted(db, user) if user is not None else false()}
        elif f["field"] == "role":
            f = {**f, "_tags": await _role_tags(db, f["role"], f.get("value") if f["op"] in ("is", "is_not") else None)}
        ready.append(f)
    conds = [_one(f) for f in ready]
    return (or_ if match == "any" else and_)(*conds)


ATTR_WORDS = {"contains": "contains", "not_contains": "doesn't contain", "starts_with": "starts with",
              "not_starts_with": "doesn't start with", "ends_with": "ends with", "not_ends_with": "doesn't end with",
              "equals": "is", "not_equals": "is not", "is_set": "is set", "is_empty": "is empty", "gt": "over", "gte": "at least",
              "lt": "under", "lte": "at most", "eq": "equals", "older_than": "older than", "within": "within the last",
              "never": "never", "ever": "has a date", "is_true": "yes", "is_false": "no"}


def spec() -> dict:
    """For the filter editor: the device values by source and the operators for each kind."""
    return {"attrs": [{"key": k, "label": lab, "group": g, "type": t} for k, (lab, g, t) in ATTRS.items()],
            "ops": {t: [[o, ATTR_WORDS[o]] for o in ops] for t, ops in ATTR_OPS.items()}}


def describe(filters: list[dict], match: str = "all") -> str:
    from api.core import tag_roles
    words = {"is": "is", "is_not": "is not", "starts_with": "starts with", "not_starts_with": "doesn't start with",
             "any": "is set", "none": "isn't set", "in": "is", "not_in": "is not"}
    parts = []
    for f in filters:
        if f["field"] == "access":
            parts.append("only devices the viewer has access to")
            continue
        if f["field"] == "attr":
            parts.append(f"{ATTRS[f['attr']][0]} {ATTR_WORDS[f['op']]}" + (f" {f['value']}" if "value" in f else "")
                         + (" days" if ATTRS[f["attr"]][2] == "days" and "value" in f else ""))
            continue
        name = (tag_roles.name_of(f["role"]) if f["field"] == "role" else "AD OU" if f["field"] == "ou"
                else f["field"].replace("_", " ").capitalize())
        parts.append(f"{name} {words[f['op']]}" + (f" {f['value']}" if f.get("value") else ""))
    return (" or " if match == "any" else " and ").join(parts)


def link_params(filters: list[dict], match: str) -> dict:
    """The part of a filter the device list understands (exact tags and one source), for card click-throughs."""
    if match != "all":
        return {}
    out: dict = {}
    tags = [f["value"] for f in filters if f["field"] == "tag" and f["op"] == "is"]
    if tags:
        out["tag"] = tags
    src = [f["value"] for f in filters if f["field"] == "source" and f["op"] == "is"]
    if len(src) == 1:
        out["source"] = src[0]
    return out
