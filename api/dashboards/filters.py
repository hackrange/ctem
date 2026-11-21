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
    "access": ("mine",),   # only devices the viewer is granted (tags or assignment), whatever their role
}
NEEDS_VALUE = {"is", "is_not", "starts_with", "not_starts_with"}


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
    neg = op in ("is_not", "not_starts_with", "none")
    if field == "access":
        return f["_cond"]
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
    slice. Per-user tag grants plug in here when they're added."""
    from api.models.device import DeviceAssignment
    from api.models.tag import GroupTagAccess
    tag_ids = [r[0] for r in (await db.execute(select(GroupTagAccess.tag_id).where(
        GroupTagAccess.role_name.in_(list(user.role_names) or ["__none__"])))).all()]
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


def describe(filters: list[dict], match: str = "all") -> str:
    from api.core import tag_roles
    words = {"is": "is", "is_not": "is not", "starts_with": "starts with", "not_starts_with": "doesn't start with",
             "any": "is set", "none": "isn't set"}
    parts = []
    for f in filters:
        if f["field"] == "access":
            parts.append("only devices the viewer has access to")
            continue
        name = tag_roles.name_of(f["role"]) if f["field"] == "role" else f["field"].replace("_", " ").capitalize()
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
