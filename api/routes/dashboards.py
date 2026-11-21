"""Dashboards and Favorites.

Anyone signed in can build dashboards. A dashboard is private, shared with chosen roles, or shared with everyone;
only its owner and admins edit it, others can view, star or copy it. Admins see every dashboard. Widget data is
computed per viewer, limited to what that viewer may see.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.middleware import get_current_user
from api.core.db import get_session
from api.dashboards import catalog as cat
from api.models.dashboard import Dashboard, Favorite, Visibility
from api.models.settings import AuditLog
from api.models.user import User

router = APIRouter(prefix="/api/v1/dashboards", tags=["dashboards"])
fav_router = APIRouter(prefix="/api/v1/favorites", tags=["favorites"])
cat.load_metrics()

ROLES = ("admin", "cyber", "grc", "it_user", "read_only", "inventory", "business_stakeholder")
FAV_KINDS = ("dashboard",)
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120, pattern=r"^[^\x00-\x1f<>]+$")]
Desc = Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000, pattern=r"^[^\x00-\x08\x0b-\x1f<>]*$")]


def _member(u: User = Depends(get_current_user)) -> User:
    if not set(ROLES).intersection(u.role_names):   # e.g. no_access: brand-new SSO people
        raise HTTPException(404)
    return u


def _admin(u: User) -> bool:
    return "admin" in u.role_names


def can_view(d: Dashboard, u: User) -> bool:
    return (_admin(u) or d.owner_id == str(u.id) or d.visibility == Visibility.everyone
            or (d.visibility == Visibility.roles and bool(set(d.share_roles or []) & set(u.role_names))))


def can_edit(d: Dashboard, u: User) -> bool:
    return _admin(u) or d.owner_id == str(u.id)


class DashBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Name
    description: Desc | None = None
    visibility: Literal["private", "roles", "everyone"] = "private"
    share_roles: list[Literal[ROLES]] = Field(default_factory=list, max_length=len(ROLES))
    widgets: list[dict] = Field(default_factory=list, max_length=cat.MAX_WIDGETS)


def _widgets(raw: list) -> list[dict]:
    out = []
    for w in raw[:cat.MAX_WIDGETS]:
        c = cat.clean_widget(w)
        if c:
            c["id"] = c["id"] or uuid.uuid4().hex[:12]
            out.append(c)
    return out


def _audit(db, u: User, action: str, d: Dashboard) -> None:
    db.add(AuditLog(actor_user_id=str(u.id), actor_username=u.username, action=action, resource_type="dashboard",
                    resource_id=str(d.id), detail=d.name[:200]))


async def _starred(db, u: User) -> set[str]:
    return {r[0] for r in (await db.execute(select(Favorite.ref).where(
        Favorite.user_id == str(u.id), Favorite.kind == "dashboard"))).all()}


def _summary(d: Dashboard, u: User, starred: set[str]) -> dict:
    return {"id": str(d.id), "name": d.name, "description": d.description, "owner": d.owner_name,
            "mine": d.owner_id == str(u.id), "visibility": d.visibility.value, "share_roles": d.share_roles or [],
            "widgets": len(d.widgets or []), "updated_at": (d.updated_at or d.created_at).isoformat() + "Z",
            "can_edit": can_edit(d, u), "starred": str(d.id) in starred}


async def _get(db, u: User, dash_id: uuid.UUID) -> Dashboard:
    d = await db.get(Dashboard, str(dash_id))
    if d is None or not can_view(d, u):
        raise HTTPException(404)   # same for "absent" and "not shared with you"
    return d


@router.get("/catalog")
async def catalog(u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    """The metrics this person may put on a dashboard."""
    ctx = await cat.context(db, u)
    return {"metrics": [m.spec() for m in cat.REGISTRY.values() if cat.allowed(m, ctx)],
            "roles": list(ROLES), "grid_cols": cat.GRID_COLS, "max_widgets": cat.MAX_WIDGETS}


@router.get("")
async def list_dashboards(u: User = Depends(_member), db: AsyncSession = Depends(get_session),
                          scope: str = Query("mine", pattern="^(mine|shared|starred|all)$"),
                          q: str | None = Query(None, max_length=120)):
    stmt = select(Dashboard)
    me = str(u.id)
    if scope == "mine":
        stmt = stmt.where(Dashboard.owner_id == me)
    elif scope == "shared":
        stmt = stmt.where(Dashboard.owner_id != me, Dashboard.visibility != Visibility.private)
    elif scope == "starred":
        stmt = stmt.where(Dashboard.id.in_(select(Favorite.ref).where(Favorite.user_id == me, Favorite.kind == "dashboard")))
    elif not _admin(u):
        raise HTTPException(404)   # "all" is the admin view
    rows = (await db.execute(stmt.order_by(Dashboard.name))).scalars().all()
    rows = [d for d in rows if can_view(d, u)]
    if q and q.strip():
        rows = [d for d in rows if q.strip().lower() in d.name.lower() or q.strip().lower() in (d.description or "").lower()]
    starred = await _starred(db, u)
    return {"dashboards": [_summary(d, u, starred) for d in rows], "is_admin": _admin(u)}


@router.post("")
async def create(body: DashBody, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    d = Dashboard(name=body.name, description=body.description or None, owner_id=str(u.id), owner_name=u.username,
                  visibility=Visibility(body.visibility), share_roles=list(dict.fromkeys(body.share_roles)) or None,
                  widgets=_widgets(body.widgets))
    db.add(d)
    await db.flush()
    _audit(db, u, "dashboard.create", d)
    await db.commit()
    return {"ok": True, "id": str(d.id)}


@router.get("/{dash_id}")
async def get_dashboard(dash_id: uuid.UUID, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    d = await _get(db, u, dash_id)
    return {**_summary(d, u, await _starred(db, u)), "widgets": [w for w in map(cat.clean_widget, d.widgets or []) if w]}


@router.put("/{dash_id}")
async def update(dash_id: uuid.UUID, body: DashBody, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    d = await _get(db, u, dash_id)
    if not can_edit(d, u):
        raise HTTPException(404)
    d.name, d.description = body.name, body.description or None
    d.visibility, d.share_roles = Visibility(body.visibility), list(dict.fromkeys(body.share_roles)) or None
    d.widgets = _widgets(body.widgets)
    _audit(db, u, "dashboard.update", d)
    await db.commit()
    return {"ok": True}


@router.delete("/{dash_id}")
async def delete(dash_id: uuid.UUID, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    d = await _get(db, u, dash_id)
    if not can_edit(d, u):
        raise HTTPException(404)
    _audit(db, u, "dashboard.delete", d)
    await db.execute(Favorite.__table__.delete().where(Favorite.kind == "dashboard", Favorite.ref == str(d.id)))
    await db.delete(d)
    await db.commit()
    return {"ok": True}


@router.post("/{dash_id}/copy")
async def copy(dash_id: uuid.UUID, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    """Your own private copy to change as you like."""
    src = await _get(db, u, dash_id)
    d = Dashboard(name=f"{src.name} (copy)"[:120], description=src.description, owner_id=str(u.id), owner_name=u.username,
                  visibility=Visibility.private, widgets=_widgets(src.widgets or []))
    db.add(d)
    await db.flush()
    _audit(db, u, "dashboard.copy", d)
    await db.commit()
    return {"ok": True, "id": str(d.id)}


class DataBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    widgets: list[dict] = Field(max_length=cat.MAX_WIDGETS)


@router.post("/data")
async def widget_data(body: DataBody, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    """Data for widgets (saved or being edited), computed for this viewer. Keyed by widget id."""
    ctx = await cat.context(db, u)
    out = {}
    for raw in body.widgets:
        w = cat.clean_widget(raw)
        if w:
            out[w["id"] or w["metric"]] = await cat.evaluate(ctx, w)
    return {"data": out}


@fav_router.get("")
async def favorites(u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    """What this person starred, with names, for the menu. Dashboards no longer shared with them drop out."""
    favs = (await db.execute(select(Favorite).where(Favorite.user_id == str(u.id)).order_by(Favorite.created_at))).scalars().all()
    ids = [f.ref for f in favs if f.kind == "dashboard"]
    dashes = {str(d.id): d for d in (await db.execute(select(Dashboard).where(Dashboard.id.in_(ids)))).scalars()} if ids else {}
    items = [{"kind": "dashboard", "ref": f.ref, "label": dashes[f.ref].name, "url": f"/dashboards/{f.ref}"}
             for f in favs if f.kind == "dashboard" and f.ref in dashes and can_view(dashes[f.ref], u)]
    return {"favorites": items}


@fav_router.put("/{kind}/{ref}")
async def star(kind: Literal[FAV_KINDS], ref: uuid.UUID, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    await _get(db, u, ref)   # you can only star what you can see
    exists = (await db.execute(select(Favorite.id).where(Favorite.user_id == str(u.id), Favorite.kind == kind,
                                                         Favorite.ref == str(ref)))).first()
    if not exists:
        db.add(Favorite(user_id=str(u.id), kind=kind, ref=str(ref), created_at=datetime.now(timezone.utc)))
        await db.commit()
    return {"ok": True, "starred": True}


@fav_router.delete("/{kind}/{ref}")
async def unstar(kind: Literal[FAV_KINDS], ref: uuid.UUID, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    await db.execute(Favorite.__table__.delete().where(Favorite.user_id == str(u.id), Favorite.kind == kind,
                                                       Favorite.ref == str(ref)))
    await db.commit()
    return {"ok": True, "starred": False}

