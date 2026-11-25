"""Admin > Tag mapping: which of a customer's tags mean executive owner, application, environment and so on.

Anyone signed in reads the roles and the filter options (tag names are already readable by every user);
only admins change them, and every change is audited. User-facing refusals answer 200 with ok: false
because the load balancer replaces 4xx bodies."""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.middleware import get_current_user
from api.auth.rbac import require_admin
from api.core import tag_roles as tr
from api.core.db import get_session
from api.models.settings import AuditLog
from api.models.tag_role import TagRole
from api.models.user import User

router = APIRouter(prefix="/api/v1/tag-roles", tags=["tag-roles"])
_NAME_RE = re.compile(r"^[A-Za-z0-9 .,&()/'_-]{1,60}$")


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    match: str = Field(pattern="^(prefix|exact)$")
    value: str = Field(min_length=1, max_length=128)


class RoleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=60)
    show_filter: bool = True
    title_case: bool = False
    rules: list[Rule] = Field(default_factory=list, max_length=tr.MAX_RULES)


class NewRole(RoleIn):
    key: str = Field(min_length=2, max_length=40)


class PreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rules: list[Rule] = Field(default_factory=list, max_length=tr.MAX_RULES)
    title_case: bool = False
    key: str | None = Field(None, max_length=40)   # judge alongside the other roles (longest match wins)


class ResolveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tags: list[str] = Field(default_factory=list, max_length=10)   # a value may join alternatives with "|"


def _out(r: TagRole) -> dict:
    return {"key": r.key, "name": r.name, "builtin": r.builtin, "show_filter": r.show_filter, "title_case": r.title_case,
            "position": r.position, "rules": r.rules or [], "version": r.version, "updated_by": r.updated_by,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None}


def _audit(db: AsyncSession, actor: User, action: str, r: TagRole, detail: str) -> None:
    db.add(AuditLog(actor_user_id=str(actor.id), actor_username=actor.username, action=action,
                    resource_type="tag_role", resource_id=r.key, detail=detail[:500]))


def _refuse(msg: str) -> dict:
    return {"ok": False, "error": msg}


def _check(body: RoleIn) -> tuple[list[dict] | None, str | None]:
    if not _NAME_RE.match(body.name.strip()):
        return None, "Use letters, digits, spaces and . , & ( ) / ' _ - in the name."
    try:
        return tr.clean_rules([r.model_dump() for r in body.rules]), None
    except ValueError as e:
        return None, str(e).capitalize() + "."


@router.get("")
async def list_roles(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_session)):
    await tr.ensure(db)
    rows = (await db.execute(select(TagRole).order_by(TagRole.position, TagRole.name))).scalars().all()
    return {"roles": [_out(r) for r in rows]}


@router.get("/filters")
async def filters(_: User = Depends(get_current_user), db: AsyncSession = Depends(get_session),
                  asset: str | None = Query(None, pattern="^(hosts|repositories|sites)$")):
    """The dashboard dropdowns: each role marked as a filter, with the tags in use that map to it. asset: only the
    values found on hosts, repositories or sites (the Security Overview's tabs)."""
    from api.routes.device_query import card_filters
    roles = await tr.ensure(db)
    cond = None
    if asset:
        from sqlalchemy import and_
        cond = and_(*card_filters({"asset": asset}))
    opts = await tr.options(db, roles, cond)
    return {"filters": [{"key": r.key, "name": r.name, "options": merged(opts.get(r.key, []))} for r in roles if r.show_filter]}


def merged(options: list[dict]) -> list[dict]:
    """One choice per value: the same application or owner tagged by two tools ("app:MuleSoft" and
    "r7:app:MuleSoft", or a different case) is one entry whose tag lists both, joined by "|"."""
    groups: dict[str, dict] = {}
    for o in options:
        key = " ".join(str(o["value"]).replace("_", " ").lower().split())
        g = groups.setdefault(key, {"value": o["value"], "tags": []})
        if o["tag"] not in g["tags"]:
            g["tags"].append(o["tag"])
    return [{"tag": "|".join(g["tags"][:10]), "value": g["value"]} for g in groups.values()]


@router.post("/resolve")
async def resolve(body: ResolveIn, _: User = Depends(get_current_user), db: AsyncSession = Depends(get_session)):
    """How to show some tag names: role name and value, for the tag-focus chips."""
    roles = await tr.ensure(db)
    out = []
    for t in [t for t in body.tags if isinstance(t, str) and 0 < len(t) <= 1400]:
        m = tr.match(t.split("|")[0][:128], roles)   # alternatives share one meaning: name it by the first
        out.append({"tag": t, "role": m[0] if m else None, "role_name": tr.name_of(m[0]) if m else None,
                    "value": m[1] if m else t})
    return {"tags": out}


@router.get("/suggestions")
async def suggestions(_: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    roles = await tr.ensure(db, fresh=True)
    return {"suggestions": await tr.suggestions(db, roles)}


@router.post("/preview")
async def preview(body: PreviewIn, _: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    try:
        rules = tr.clean_rules([r.model_dump() for r in body.rules])
    except ValueError as e:
        return _refuse(str(e).capitalize() + ".")
    key = body.key if body.key and tr.valid_key(body.key) else None
    others = await tr.ensure(db) if key else None
    return {"ok": True, **await tr.preview(db, rules, body.title_case, key, others)}


@router.put("/{key}")
async def update_role(key: str, body: RoleIn, actor: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    if not tr.valid_key(key):
        raise HTTPException(404)
    await tr.ensure(db)
    r = (await db.execute(select(TagRole).where(TagRole.key == key))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404)
    rules, err = _check(body)
    if err:
        return _refuse(err)
    before = [x["value"] for x in r.rules or []]
    r.name, r.show_filter, r.title_case, r.rules = body.name.strip(), body.show_filter, body.title_case, rules
    r.version, r.updated_by = (r.version or 1) + 1, actor.username
    _audit(db, actor, "tag_role.update", r, f"{r.name}: {before} -> {[x['value'] for x in rules]}")
    from api.scoring.dirty import mark_app_assets
    await mark_app_assets(db)   # repositories' and sites' scores read the mapping
    await db.commit()
    tr.forget()
    return {"ok": True, "role": _out(r)}


@router.post("")
async def create_role(body: NewRole, actor: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    key = body.key.strip().lower()
    if not tr.valid_key(key):
        return _refuse("The key is 2 to 40 lowercase letters, digits or _ and starts with a letter.")
    roles = await tr.ensure(db)
    if len(roles) >= tr.MAX_ROLES:
        return _refuse(f"There can be at most {tr.MAX_ROLES} roles.")
    if any(r.key == key for r in roles):
        return _refuse("A role with that key already exists.")
    rules, err = _check(body)
    if err:
        return _refuse(err)
    r = TagRole(key=key, name=body.name.strip(), builtin=False, show_filter=body.show_filter, title_case=body.title_case,
                position=max((x.position for x in roles), default=0) + 1, rules=rules, updated_by=actor.username)
    db.add(r)
    _audit(db, actor, "tag_role.create", r, f"{r.name}: {[x['value'] for x in rules]}")
    from api.scoring.dirty import mark_app_assets
    await mark_app_assets(db)   # repositories' and sites' scores read the mapping
    await db.commit()
    tr.forget()
    return {"ok": True, "role": _out(r)}


@router.delete("/{key}")
async def delete_role(key: str, actor: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    if not tr.valid_key(key):
        raise HTTPException(404)
    r = (await db.execute(select(TagRole).where(TagRole.key == key))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404)
    if r.builtin:
        return _refuse("Built-in roles can't be deleted; clear their rules instead.")
    _audit(db, actor, "tag_role.delete", r, r.name)
    await db.delete(r)
    from api.scoring.dirty import mark_app_assets
    await mark_app_assets(db)   # repositories' and sites' scores read the mapping
    await db.commit()
    tr.forget()
    return {"ok": True}
