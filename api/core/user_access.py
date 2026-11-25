"""Per-user data access rules, resolved to tags.

A rule is a tag role (from Admin > Tag mapping) and the values that grant it, for example executive owner is
"Elmer Fudd" or "elmer.fudd@acme.example". It matches through the mapping, so every tool's owner tags count
(exec_owner:..., owner:E-O:...), and tags that appear later match without editing the user. Values compare without
case and surrounding spaces, and may hold wildcards (* any run of characters, ? one character): "*@acme.example".
Any rule, any value grants (OR). "tag" rules name a tag (or a pattern such as "app:*"). "all" = "*" grants every
asset, tagged or not, for complete visibility (a CISO, an audit team); what the person can do still comes from roles.
Cloud provider tags (aws:..., azure:..., oci:...) grant only through a "tag" rule that names them."""
from __future__ import annotations

import fnmatch
import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

MAX_RULES, MAX_VALUES = 20, 25
_TTL = 60.0
_cache: dict[str, tuple[float, tuple[bool, set[str]]]] = {}


ALL = "all"   # the rule key for every asset
CLOUD_TAGS = ("aws:", "azure:", "oci:")   # the tags cloud sync writes (api/cloud/exposure.py tag_names)


def norm(v) -> str:
    return " ".join(str(v or "").split()).lower()


def _hit(value: str, wanted: set[str]) -> bool:
    """value (normalized) against plain values and wildcard patterns ([ and ] are taken literally)."""
    if value in wanted:
        return True
    return any(("*" in w or "?" in w) and fnmatch.fnmatchcase(value, w.replace("[", "[[]")) for w in wanted)


async def rules(db: AsyncSession, user_id: str) -> list[dict]:
    """[{role, values}] for one user, in a stable order."""
    from api.models.user_access import UserAccessRule
    rows = (await db.execute(select(UserAccessRule.role_key, UserAccessRule.value)
                             .where(UserAccessRule.user_id == str(user_id))
                             .order_by(UserAccessRule.role_key, UserAccessRule.value))).all()
    out: dict[str, list[str]] = {}
    for k, v in rows:
        out.setdefault(k, []).append(v)
    return [{"role": k, "values": vs} for k, vs in out.items()]


async def matching_tags(db: AsyncSession, wanted: list[dict]) -> list[tuple[str, str]]:
    """(tag id, tag name) for every tag the rules match."""
    from api.core import tag_roles
    from api.models.tag import Tag
    if not wanted:
        return []
    roles = await tag_roles.ensure(db)
    exact = {norm(v) for r in wanted if r["role"] == "tag" for v in r["values"]}
    by_role = {r["role"]: {norm(v) for v in r["values"]} for r in wanted if r["role"] not in ("tag", ALL)}
    out = []
    for tid, name in (await db.execute(select(Tag.id, Tag.name))).all():
        if exact and _hit(norm(name), exact):
            out.append((str(tid), name))
            continue
        # Cloud tags are written by whoever can tag an instance, and land on whatever device the instance matched
        # (a private IP can collide with an on-prem server): they grant only when a rule names them, never by role
        m = tag_roles.match(name, roles) if by_role and not name.lower().startswith(CLOUD_TAGS) else None
        if m and m[0] in by_role and _hit(norm(m[1]), by_role[m[0]]):
            out.append((str(tid), name))
    return out


def grants_all(wanted: list[dict]) -> bool:
    return any(r["role"] == ALL for r in wanted)


async def _resolved(db: AsyncSession, user) -> tuple[bool, set[str]]:
    """(every asset?, the tags granted), kept a minute; rules and tags change rarely."""
    uid = str(user.id)
    hit = _cache.get(uid)
    if hit and time.monotonic() - hit[0] < _TTL:
        return hit[1]
    wanted = await rules(db, uid)
    got = (grants_all(wanted), set() if grants_all(wanted) else {t for t, _ in await matching_tags(db, wanted)})
    _cache[uid] = (time.monotonic(), got)
    return got


async def tag_ids(db: AsyncSession, user) -> set[str]:
    """The tags a user's own rules grant."""
    return (await _resolved(db, user))[1]


async def sees_all(db: AsyncSession, user) -> bool:
    """An "all" rule: every asset, like the roles that see the whole fleet."""
    return (await _resolved(db, user))[0]


def forget(user_id: str | None = None) -> None:
    if user_id is None:
        _cache.clear()
    else:
        _cache.pop(str(user_id), None)
