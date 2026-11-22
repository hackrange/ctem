"""Admin > Users > Data access: which assets (and their findings) one person may see, by tag role and value.

Admins only. Every value is checked and stored as given; matching is case-insensitive and goes through the tag
mapping (api/core/user_access.py), so nothing a client sends reaches SQL as text."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import _GLOBAL_SCOPE_ROLES, require_admin
from api.core import tag_roles, user_access
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/admin/users", tags=["admin"])


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]{0,63}$")
    values: list[str] = Field(min_length=1, max_length=user_access.MAX_VALUES)

    @field_validator("values")
    @classmethod
    def _clean(cls, vs: list[str]) -> list[str]:
        out = []
        for v in vs:
            v = " ".join(str(v).split())
            if not v:
                continue
            if len(v) > 256 or any(ord(c) < 32 for c in v) or "<" in v or ">" in v:
                raise ValueError("Each value is up to 256 characters, without < or >")
            if user_access.norm(v) not in {user_access.norm(x) for x in out}:
                out.append(v)
        if not out:
            raise ValueError("Give at least one value")
        return out


class Rules(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rules: list[Rule] = Field(default_factory=list, max_length=user_access.MAX_RULES)


async def _roles(db) -> dict[str, str]:
    return {"tag": "Tag", user_access.ALL: "All assets", **{r.key: r.name for r in await tag_roles.ensure(db)}}


async def _user(db, user_id: uuid.UUID) -> User:
    from sqlalchemy.orm import selectinload
    u = (await db.execute(select(User).options(selectinload(User.roles)).where(User.id == str(user_id)))).scalar_one_or_none()
    if u is None:
        raise HTTPException(404)
    return u


async def _preview(db, rules: list[dict]) -> dict:
    from api.models.device import Device, DeviceTag
    if user_access.grants_all(rules):
        n = (await db.execute(select(func.count()).select_from(Device))).scalar_one()
        return {"tags": None, "assets": n, "sample": [], "all": True}
    tags = await user_access.matching_tags(db, rules)
    ids = [t for t, _ in tags]
    assets = 0
    if ids:
        assets = (await db.execute(select(func.count(func.distinct(DeviceTag.device_id))).where(DeviceTag.tag_id.in_(ids)))).scalar_one()
    return {"tags": len(tags), "assets": assets, "sample": sorted(n for _, n in tags)[:15]}


@router.get("/access/options")
async def options(admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    """The roles a rule can use, with the values in use for each (for suggestions as the admin types)."""
    from api.models.device import DeviceTag
    from api.models.tag import Tag
    roles = await tag_roles.ensure(db)
    vals = await tag_roles.options(db, roles)
    used = (await db.execute(select(Tag.name).where(Tag.id.in_(select(DeviceTag.tag_id).distinct())).order_by(Tag.name))).scalars().all()
    # mapped roles first (owners, application...), then exact tags; only roles that have values in use
    shown = [r for r in roles if vals.get(r.key)] + [r for r in roles if not vals.get(r.key)]
    return {"roles": [{"key": r.key, "name": r.name} for r in shown] + [{"key": "tag", "name": "Tag"},
                                                                         {"key": user_access.ALL, "name": "All assets"}],
            "values": {**{k: sorted({o["value"] for o in v}, key=str.lower)[:500] for k, v in vals.items()}, "tag": list(used)[:2000]}}


@router.get("/{user_id}/access")
async def get_access(user_id: uuid.UUID, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    u = await _user(db, user_id)
    rules = await user_access.rules(db, str(u.id))
    return {"rules": rules, "sees_everything": bool(set(u.role_names) & _GLOBAL_SCOPE_ROLES),
            **await _preview(db, rules)}


@router.post("/access/preview")
async def preview(body: Rules, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    known = await _roles(db)
    return await _preview(db, [r.model_dump() for r in body.rules if r.role in known])


@router.put("/{user_id}/access")
async def set_access(user_id: uuid.UUID, body: Rules, admin: User = Depends(require_admin),
                     db: AsyncSession = Depends(get_session)):
    """Replace this person's rules. An empty list removes them."""
    from api.models.user_access import UserAccessRule
    from api.routes.admin import _audit
    u = await _user(db, user_id)
    known = await _roles(db)
    bad = [r.role for r in body.rules if r.role not in known]
    if bad:
        return {"ok": False, "error": f"Unknown tag role: {bad[0]}. Pick one from Admin > Tag mapping."}
    if any(r.role == user_access.ALL and r.values != ["*"] for r in body.rules):
        return {"ok": False, "error": 'All assets takes one value: "*".'}
    merged: dict[str, list[str]] = {}
    for r in body.rules:
        have = merged.setdefault(r.role, [])
        have += [v for v in r.values if user_access.norm(v) not in {user_access.norm(x) for x in have}]
    await db.execute(delete(UserAccessRule).where(UserAccessRule.user_id == str(u.id)))
    for role, vals in merged.items():
        for v in vals[:user_access.MAX_VALUES]:
            db.add(UserAccessRule(user_id=str(u.id), role_key=role, value=v, created_by=admin.username))
    summary = "; ".join(f"{known[k]} is {' or '.join(vs)}" for k, vs in merged.items()) or "none"
    await _audit(admin, "user.data_access", "user", str(u.id), f"{u.username}: {summary}"[:1000], db)
    await db.commit()
    user_access.forget(str(u.id))
    rules = await user_access.rules(db, str(u.id))
    return {"ok": True, "rules": rules, "sees_everything": bool(set(u.role_names) & _GLOBAL_SCOPE_ROLES),
            **await _preview(db, rules)}
