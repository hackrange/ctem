"""Tag roles: read a customer's tags as CTEM concepts (executive owner, application, environment...).

A role has match rules over tag names: "prefix" (starts with) or "exact" (is exactly), case-insensitive. A tag
that several rules match goes to the longest match, so "location:ENV: AWS" can be an environment while
"location:Dallas" stays a location. The value shown is the tag with the matched prefix removed.

Rules are cached per process for a minute; every process re-reads them after that, so a change made in the
Admin page reaches the web app and the worker without a restart."""
from __future__ import annotations

import re
import time
from collections import Counter
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

# Built-in roles CTEM features read. The default rules are CTEM's own neutral tag forms only;
# a customer's naming (for example a scanner's "E-O:" owner tags) is added in Admin > Tag mapping.
BUILTIN = (
    ("executive_owner", "Executive owner", True, ("exec_owner:",)),
    ("technical_owner", "Technical owner", True, ("tech_owner:",)),
    ("application_owner", "Application owner", True, ("app_owner:",)),
    ("application", "Application", True, ("app:",)),
    ("environment", "Environment", True, ("env:",)),
    ("location", "Location", False, ("location:",)),
    ("business_unit", "Business unit", False, ("bu:",)),
)
OWNER_ROLES = ("technical_owner", "application_owner", "executive_owner")   # who to show as "Owner", in order
MAX_RULES = 20
MAX_ROLES = 30
_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")
_TTL = 60.0


@dataclass(frozen=True)
class Role:
    key: str
    name: str
    builtin: bool
    show_filter: bool
    title_case: bool
    position: int
    rules: tuple[tuple[str, str], ...]   # (match, lowercased value)


def clean_rules(raw) -> list[dict]:
    """Validate rules from the API: at most 20, match is prefix or exact, value 1-128 printable characters."""
    if not isinstance(raw, list) or len(raw) > MAX_RULES:
        raise ValueError(f"give at most {MAX_RULES} rules")
    out, seen = [], set()
    for r in raw:
        if not isinstance(r, dict) or r.get("match") not in ("prefix", "exact"):
            raise ValueError('each rule needs match "prefix" or "exact"')
        v = r.get("value")
        if not isinstance(v, str) or not v.strip() or len(v) > 128 or any(ord(c) < 32 for c in v) or "<" in v or ">" in v:
            raise ValueError("each rule needs a value of 1 to 128 characters, without < or >")
        k = (r["match"], v.lower())
        if k not in seen:
            seen.add(k)
            out.append({"match": r["match"], "value": v})
    return out


# ── cache ─────────────────────────────────────────────────────────────────────
_cache: dict = {"at": 0.0, "roles": None}


def _defaults() -> list[Role]:
    return [Role(k, n, True, show, False, i, tuple(("prefix", p.lower()) for p in prefixes))
            for i, (k, n, show, prefixes) in enumerate(BUILTIN)]


def current() -> list[Role]:
    """The roles as last loaded (built-in defaults until ensure() has run in this process)."""
    return _cache["roles"] or _defaults()


async def seed(db: AsyncSession) -> None:
    """Create any missing built-in role with its neutral default rules."""
    from api.models.tag_role import TagRole
    have = set((await db.execute(select(TagRole.key))).scalars())
    added = False
    for i, (k, n, show, prefixes) in enumerate(BUILTIN):
        if k not in have:
            db.add(TagRole(key=k, name=n, builtin=True, show_filter=show, position=i,
                           rules=[{"match": "prefix", "value": p} for p in prefixes]))
            added = True
    if added:
        await db.commit()


async def ensure(db: AsyncSession, fresh: bool = False) -> list[Role]:
    if not fresh and _cache["roles"] is not None and time.monotonic() - _cache["at"] < _TTL:
        return _cache["roles"]
    from api.models.tag_role import TagRole
    await seed(db)
    rows = (await db.execute(select(TagRole).order_by(TagRole.position, TagRole.name))).scalars().all()
    roles = [Role(r.key, r.name, r.builtin, r.show_filter, r.title_case, r.position,
                  tuple((x["match"], x["value"].lower()) for x in (r.rules or []) if isinstance(x, dict) and x.get("value")))
             for r in rows]
    _cache.update(at=time.monotonic(), roles=roles)
    return roles


def forget() -> None:
    _cache.update(at=0.0, roles=None)


# ── matching ──────────────────────────────────────────────────────────────────
def _tidy(value: str, title: bool) -> str:
    value = value.strip(" :-=").strip()
    return value.title() if title else value


def _best(tag: str, roles: list[Role] | None):
    """(length, role, kind, rule value) of the longest rule matching the tag, or None."""
    low, best = (tag or "").lower(), None
    for r in roles or current():
        for kind, v in r.rules:
            hit = low == v if kind == "exact" else low.startswith(v)
            if hit and (best is None or len(v) > best[0]):
                best = (len(v), r, kind, v)
    return best


def match(tag: str, roles: list[Role] | None = None) -> tuple[str, str] | None:
    """(role key, value) for a tag name, or None. The longest matching rule wins."""
    best = _best(tag, roles)
    if best is None:
        return None
    _, r, kind, v = best
    value = tag if kind == "exact" else tag[len(v):]
    value = _tidy(value, r.title_case)
    return (r.key, value) if value else None


def values(tags, key: str, roles: list[Role] | None = None) -> list[str]:
    """Every value a device's tags give for one role, in tag order."""
    out = []
    for t in tags or []:
        m = match(t, roles)
        if m and m[0] == key and m[1] not in out:
            out.append(m[1])
    return out


def first(tags, keys, roles: list[Role] | None = None) -> str | None:
    """The first value for the first of these roles that has one."""
    for k in keys:
        v = values(tags, k, roles)
        if v:
            return v[0]
    return None


def name_of(key: str) -> str:
    return next((r.name for r in current() if r.key == key), key.replace("_", " ").title())


# ── what the dashboard and pages need ─────────────────────────────────────────
async def options(db: AsyncSession, roles: list[Role], devices=None) -> dict[str, list[dict]]:
    """Per role: the tags in use that map to it, with the value to show, sorted by value. devices: a condition
    on Device to count only tags on those (say, only web applications)."""
    from api.models.device import Device, DeviceTag
    from api.models.tag import Tag
    used = select(DeviceTag.tag_id).distinct()
    if devices is not None:
        used = used.where(DeviceTag.device_id.in_(select(Device.id).where(devices)))
    names = (await db.execute(select(Tag.name).where(Tag.id.in_(used)))).scalars().all()
    out: dict[str, list[dict]] = {r.key: [] for r in roles}
    for n in names:
        m = match(n, roles)
        if m:
            out[m[0]].append({"tag": n, "value": m[1]})
    for k in out:
        out[k].sort(key=lambda o: o["value"].lower())
    return out


async def preview(db: AsyncSession, rules: list[dict], title_case: bool = False, key: str | None = None,
                  others: list[Role] | None = None) -> dict:
    """What a set of rules would match right now: tags, devices, and some of the values. With `key`, the role
    is judged alongside the other roles, so a tag a longer rule of another role takes doesn't count here."""
    from api.models.device import DeviceTag
    from api.models.tag import Tag
    role = Role(key or "preview", "Preview", False, False, title_case, 0, tuple((r["match"], r["value"].lower()) for r in rules))
    field = [role] + [r for r in (others or []) if r.key != role.key]
    rows = (await db.execute(select(Tag.id, Tag.name).where(Tag.id.in_(select(DeviceTag.tag_id).distinct())))).all()
    hit = {tid: m[1] for tid, n in rows if (m := match(n, field)) and m[0] == role.key}
    devices = 0
    if hit:
        devices = (await db.execute(select(func.count(func.distinct(DeviceTag.device_id)))
                                    .where(DeviceTag.tag_id.in_(list(hit))))).scalar_one()
    vals = sorted(set(hit.values()), key=str.lower)
    return {"tags": len(hit), "devices": devices, "values": len(vals), "sample": vals[:12]}


# Patterns that usually mean a role, matched against the start of a tag name. The prefix proposed is the
# tag's own text up to and including the marker, so suggestions use the customer's real naming.
_SUGGEST = (
    ("executive_owner", r"(?:exec(?:utive)?[ _-]?owner|e-o|eo)\s*[:=]\s*"),
    ("technical_owner", r"(?:tech(?:nical)?[ _-]?owner|it[ _-]?owner|t-o|to)\s*[:=]\s*"),
    ("application_owner", r"(?:app(?:lication)?[ _-]?owner|business[ _-]?owner|a-o|ao)\s*[:=]\s*"),
    ("application", r"(?:app(?:lication)?|service)\s*[:=]\s*"),
    ("environment", r"(?:env(?:ironment)?|stage|tier)\s*[:=]\s*"),
    ("location", r"(?:location|site|region|datacenter)\s*[:=]\s*"),
    ("business_unit", r"(?:bu|business[ _-]?unit|department|dept|cost[ _-]?center)\s*[:=]\s*"),
)
_SUGGEST_RE = [(k, re.compile(rf"^(.{{0,60}}?(?:^|[:\s_-]){p})(.+)$", re.I)) for k, p in _SUGGEST]


async def suggestions(db: AsyncSession, roles: list[Role]) -> list[dict]:
    """Prefixes seen in the tags in use that look like a role and aren't mapped yet, most devices first."""
    from api.models.device import DeviceTag
    from api.models.tag import Tag
    rows = (await db.execute(select(Tag.name, func.count(DeviceTag.device_id)).join(DeviceTag, DeviceTag.tag_id == Tag.id)
                             .group_by(Tag.name))).all()
    found: dict[tuple[str, str], Counter] = {}
    for name, n in rows:
        mapped = _best(name, roles)
        for key, rx in _SUGGEST_RE:
            m = rx.match(name)
            if m and m.group(2).strip():
                prefix = m.group(1)
                if mapped and (mapped[0] >= len(prefix.strip()) or mapped[1].key == key):
                    break   # already mapped as well or better ("location:ENV:" still beats a plain "location:")
                found.setdefault((key, prefix.lower()), Counter())[prefix] += n
                break
    out = []
    for (key, _), spellings in found.items():
        prefix, devices = spellings.most_common(1)[0][0], sum(spellings.values())
        out.append({"role": key, "match": "prefix", "value": prefix, "devices": devices})
    out.sort(key=lambda s: -s["devices"])
    return out[:40]


def valid_key(key: str) -> bool:
    return bool(_KEY_RE.match(key or ""))
