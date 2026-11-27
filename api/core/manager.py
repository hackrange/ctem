"""A person's manager, from the directory: AD (through Okta's profile) names the manager by DN, so the manager is the
person whose own DN has the same keyed hash. Only names already in the directory are shown; nothing new is stored
about the manager (the DN is kept encrypted, and its hash is for the lookup)."""
from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

_DN = re.compile(r"^(?i:cn)=.{1,200}?,(?i:ou|dc|cn)=", re.S)


def is_dn(v) -> bool:
    return isinstance(v, str) and len(v) <= 1024 and bool(_DN.match(v.strip()))


def dn_key(dn: str | None) -> str | None:
    """The DN's lookup key: case and the spaces after commas don't matter (AD hands both forms out)."""
    if not is_dn(dn):
        return None
    from api.core.encryption import search_hash
    return search_hash(re.sub(r"\s*,\s*", ",", dn.strip()).lower())


def set_dn(user, dn: str | None) -> None:
    """The person's own DN, encrypted, and its key."""
    if is_dn(dn):
        user.ad_dn, user.ad_dn_hash = dn.strip()[:1024], dn_key(dn)


def view(m) -> dict:
    return {"id": str(m.id), "first_name": m.first_name, "last_name": m.last_name, "email": m.email or m.upn,
            "title": m.title, "department": m.department, "display_name": m.display_name}


async def manager_of(db: AsyncSession, user) -> dict | None:
    """{first_name, last_name, email, title, ...} of the person's manager, {"name": ...} when the directory names one
    CTEM hasn't seen, or None when it names none."""
    from api.models.user import User
    if user is None or not user.manager_dn:
        return None
    key = dn_key(user.manager_dn)
    rows = (await db.execute(select(User).where(User.ad_dn_hash == key))).scalars().all() if key else []
    rows = sorted((r for r in rows if r.id != user.id), key=lambda r: (r.is_local, not r.is_active))   # directory people first
    if rows:
        return {**view(rows[0]), "found": True}
    rdn = user.manager_dn.split(",", 1)[0].split("=", 1)[-1].replace("\\", "").strip()[:200]
    return {"name": rdn or None, "found": False}
