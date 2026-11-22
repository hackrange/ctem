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
from api.dashboards.data_scope import _ask, _scope_change, _until, can_widen, shows_everything
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
    """Owners and admins always; anyone else only once it's published and shared with them."""
    if _admin(u) or d.owner_id == str(u.id):
        return True
    if d.scope_request and can_widen(u):   # cyber reviewing a request to show all the data
        return True
    return d.published is not False and (d.visibility == Visibility.everyone
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
    theme: Literal[cat.THEMES] = "default"
    filters: list[dict] = Field(default_factory=list, max_length=10)        # dashboard-wide conditions
    filter_match: Literal["all", "any"] = "all"
    template: Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,40}$")] | None = None   # start from a starter dashboard
    data_scope: Literal["viewer", "everything"] | None = None   # None: leave it as it is
    scope_days: Literal[1, 7, 30, 90, 365] | None = None        # how long "everything" lasts (None: no end)


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


def _dfilters(raw, match="all") -> dict | None:
    """Dashboard-wide filters, cleaned like a widget's; None when there are none."""
    from api.dashboards import filters as flt
    c = flt.clean(raw)
    return {"filters": c, "match": "any" if match == "any" else "all"} if c else None


def _fl(f) -> tuple:
    return ((f or {}).get("filters"), (f or {}).get("match"))


def _shown_filters(f: dict | None) -> dict:
    return _dfilters((f or {}).get("filters"), (f or {}).get("match")) or {"filters": [], "match": "all"}


def _summary(d: Dashboard, u: User, starred: set[str]) -> dict:
    return {"id": str(d.id), "name": d.name, "description": d.description, "owner": d.owner_name,
            "mine": d.owner_id == str(u.id), "visibility": d.visibility.value, "share_roles": d.share_roles or [],
            "widgets": len(d.widgets or []), "updated_at": (d.updated_at or d.created_at).isoformat() + "Z",
            "can_edit": can_edit(d, u), "starred": str(d.id) in starred, "theme": d.theme or "default",
            "published": d.published is not False, "has_draft": bool(d.draft) and can_edit(d, u),
            "published_at": d.published_at.isoformat() if d.published_at else None, "filters": _shown_filters(d.filters),
            "data_scope": "everything" if shows_everything(d) else "viewer", "can_widen": can_widen(u),
            "scope_until": d.scope_until.isoformat() if d.scope_until and shows_everything(d) else None,
            "scope_request": d.scope_request if (can_widen(u) or can_edit(d, u)) else None}


def _editing(d: Dashboard) -> dict:
    """What the owner is working on: the draft if there is one, else the published version."""
    if d.draft:
        return {"widgets": d.draft.get("widgets") or [], "theme": d.draft.get("theme") or d.theme or "default",
                "filters": d.draft.get("filters", d.filters)}
    return {"widgets": d.widgets or [], "theme": d.theme or "default", "filters": d.filters}


async def _get(db, u: User, dash_id: uuid.UUID) -> Dashboard:
    d = await db.get(Dashboard, str(dash_id))
    if d is None or not can_view(d, u):
        raise HTTPException(404)   # same for "absent" and "not shared with you"
    return d


@router.get("/catalog")
async def catalog(u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    """The metrics this person may put on a dashboard."""
    ctx = await cat.context(db, u)
    from api.core import vuln_dashboard as vd
    from api.dashboards import presets
    used = set(await vd.configured_sources(db))

    def spec(m):   # a source picker offers only the tools this install has
        out = m.spec()
        for p in out["params"]:
            if p["key"] == "source" and p.get("choices"):
                p["choices"] = [c for c in p["choices"] if c["value"] == "any" or c["value"] in used]
        return out
    return {"metrics": [spec(m) for m in cat.REGISTRY.values() if cat.allowed(m, ctx)],
            "roles": list(ROLES), "grid_cols": cat.GRID_COLS, "max_widgets": cat.MAX_WIDGETS, "themes": list(cat.THEMES),
            **presets.for_viewer(ctx), "filter_options": await _filter_options(db, ctx.scope is None)}


async def _filter_options(db, fleet_wide: bool) -> dict:
    """What the widget filter editor offers: tag-mapping roles with the values in use, sources and the fixed lists."""
    from api.core import tag_roles
    from api.core.device_match import SOURCE_CODES
    from api.core.device_ou import names_in_use as ou_names
    from api.dashboards import filters, fleet
    from api.models.device import DeviceType, RiskGrade
    roles = await tag_roles.ensure(db)
    opts = await tag_roles.options(db, roles)
    from api.routes.tag_roles import merged   # one suggestion per value, however many tools tag it
    return {"roles": [{"key": r.key, "name": r.name, "values": sorted({o["value"] for o in merged(opts.get(r.key, []))}, key=str.lower)[:500]}
                      for r in roles],
            "sources": [{"value": k, "label": f"{k.replace('_', ' ')} ({v})"} for k, v in SOURCE_CODES.items()],
            "device_types": list(DeviceType.__members__), "os_families": [{"value": k, "label": v} for k, v in fleet.OS_LABEL.items()],
            "grades": [g.value for g in RiskGrade],
            # OU names describe the whole directory, so only people who see every device get the suggestions
            "ous": await ou_names(db) if fleet_wide else [], **filters.spec()}


@router.get("")
async def list_dashboards(u: User = Depends(_member), db: AsyncSession = Depends(get_session),
                          scope: str = Query("mine", pattern="^(mine|shared|starred|all)$"),
                          q: str | None = Query(None, max_length=120)):
    stmt = select(Dashboard)
    me = str(u.id)
    if scope == "mine":
        stmt = stmt.where(Dashboard.owner_id == me)
    elif scope == "shared":
        stmt = stmt.where(Dashboard.owner_id != me)
        if not can_widen(u):   # approvers also see private ones waiting for them (can_view below)
            stmt = stmt.where(Dashboard.visibility != Visibility.private)
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
    """New dashboards start as drafts: only the owner (and admins) see them until they're published."""
    widgets, theme = _widgets(body.widgets), body.theme
    if body.template and not widgets:
        from api.dashboards import presets
        t = next((t for t in presets.TEMPLATES if t["key"] == body.template), None)
        if t is None:
            raise HTTPException(422, "No such starter dashboard")
        widgets = _widgets(presets.pack(t["rows"], await cat.context(db, u)))
        theme = t["theme"] if body.theme == "default" else body.theme
    d = Dashboard(name=body.name, description=body.description or None, owner_id=str(u.id), owner_name=u.username,
                  visibility=Visibility(body.visibility), share_roles=list(dict.fromkeys(body.share_roles)) or None,
                  widgets=widgets, theme=theme, published=False, filters=_dfilters(body.filters, body.filter_match))
    db.add(d)
    await db.flush()
    _audit(db, u, "dashboard.create", d)
    await db.commit()
    return {"ok": True, "id": str(d.id)}


@router.get("/{dash_id}")
async def get_dashboard(dash_id: uuid.UUID, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    d = await _get(db, u, dash_id)
    out = {**_summary(d, u, await _starred(db, u)), "widgets": [w for w in map(cat.clean_widget, d.widgets or []) if w]}
    if can_edit(d, u) and d.draft:
        e = _editing(d)
        out["draft"] = {"widgets": [w for w in map(cat.clean_widget, e["widgets"]) if w], "theme": e["theme"],
                        "filters": _shown_filters(e["filters"])}
    return out


@router.put("/{dash_id}")
async def update(dash_id: uuid.UUID, body: DashBody, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    d = await _get(db, u, dash_id)
    if not can_edit(d, u):
        raise HTTPException(404)
    pending = _scope_change(d, u, body.data_scope, body.scope_days)
    d.name, d.description = body.name, body.description or None
    d.visibility, d.share_roles = Visibility(body.visibility), list(dict.fromkeys(body.share_roles)) or None
    widgets, dfl = _widgets(body.widgets), _dfilters(body.filters, body.filter_match)
    if d.published is False:   # still a draft: nobody else sees it, so save in place
        d.widgets, d.theme, d.filters, d.draft = widgets, body.theme, dfl, None
    elif widgets != (d.widgets or []) or body.theme != (d.theme or "default") or dfl != _dfilters(*_fl(d.filters)):
        d.draft = {"widgets": widgets, "theme": body.theme, "filters": dfl}   # viewers keep the published version until Publish
    else:
        d.draft = None
    _audit(db, u, "dashboard.update", d)
    await db.commit()
    return {"ok": True, "draft": bool(d.draft) or d.published is False, "scope_pending": pending}


@router.post("/{dash_id}/publish")
async def publish(dash_id: uuid.UUID, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    """Make the draft what everyone it's shared with sees."""
    d = await _get(db, u, dash_id)
    if not can_edit(d, u):
        raise HTTPException(404)
    if not can_widen(u) and shows_everything(d):
        _ask(d, u, "published changes after it was approved")
    if d.draft:
        d.widgets, d.theme = _widgets(d.draft.get("widgets") or []), d.draft.get("theme") or d.theme
        d.filters = _dfilters(*_fl(d.draft.get("filters"))) if "filters" in d.draft else d.filters
    d.draft, d.published, d.published_at = None, True, datetime.now(timezone.utc)
    _audit(db, u, "dashboard.publish", d)
    await db.commit()
    return {"ok": True}


@router.post("/{dash_id}/discard")
async def discard(dash_id: uuid.UUID, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    """Throw away unpublished changes."""
    d = await _get(db, u, dash_id)
    if not can_edit(d, u):
        raise HTTPException(404)
    d.draft = None
    _audit(db, u, "dashboard.discard_draft", d)
    await db.commit()
    return {"ok": True}


@router.post("/{dash_id}/unpublish")
async def unpublish(dash_id: uuid.UUID, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    """Back to a draft: only the owner and admins see it until it's published again."""
    d = await _get(db, u, dash_id)
    if not can_edit(d, u):
        raise HTTPException(404)
    if d.draft:
        d.widgets, d.theme = _widgets(d.draft.get("widgets") or []), d.draft.get("theme") or d.theme
        d.filters = _dfilters(*_fl(d.draft.get("filters"))) if "filters" in d.draft else d.filters
        d.draft = None
    d.published = False
    _audit(db, u, "dashboard.unpublish", d)
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


class ScopeDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    days: Literal[1, 7, 30, 90, 365] | None = 30   # None: no end
    note: Annotated[str, StringConstraints(max_length=500, pattern=r"^[^<>]*$")] | None = None


@router.post("/{dash_id}/scope/approve")
async def approve_scope(dash_id: uuid.UUID, body: ScopeDecision, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    """An admin or cyber lets this dashboard, as published now, show everyone it's shared with all the data, for a time."""
    if not can_widen(u):
        raise HTTPException(404)
    d = await _get(db, u, dash_id)
    if d.published is False:
        return {"ok": False, "error": "Publish it first: approval covers the widgets as published."}
    d.data_scope, d.scope_until, d.scope_request = "everything", _until(body.days), None
    _audit(db, u, "dashboard.scope_approve", d)
    await db.commit()
    return {"ok": True, "scope_until": d.scope_until.isoformat() if d.scope_until else None}


@router.post("/{dash_id}/scope/deny")
async def deny_scope(dash_id: uuid.UUID, body: ScopeDecision, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    if not can_widen(u):
        raise HTTPException(404)
    d = await _get(db, u, dash_id)
    d.scope_request = None
    if not shows_everything(d):
        d.data_scope, d.scope_until = "viewer", None
    _audit(db, u, "dashboard.scope_deny", d)
    await db.commit()
    return {"ok": True}


@router.post("/{dash_id}/copy")
async def copy(dash_id: uuid.UUID, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    """Your own private copy to change as you like."""
    src = await _get(db, u, dash_id)
    e = _editing(src) if can_edit(src, u) else {"widgets": src.widgets or [], "theme": src.theme or "default", "filters": src.filters}
    d = Dashboard(name=f"{src.name} (copy)"[:120], description=src.description, owner_id=str(u.id), owner_name=u.username,
                  visibility=Visibility.private, widgets=_widgets(e["widgets"]), theme=e["theme"], published=False,
                  filters=_dfilters(*_fl(e["filters"])))
    db.add(d)
    await db.flush()
    _audit(db, u, "dashboard.copy", d)
    await db.commit()
    return {"ok": True, "id": str(d.id)}


class DataBody(BaseModel):
    """Widgets plus the dashboard-wide filters in force (saved ones, or a viewer's own for this visit). Filters only
    ever narrow what the viewer may already see."""
    model_config = ConfigDict(extra="forbid")
    widgets: list[dict] = Field(max_length=cat.MAX_WIDGETS)
    filters: list[dict] = Field(default_factory=list, max_length=10)
    filter_match: Literal["all", "any"] = "all"
    dashboard: uuid.UUID | None = None   # the saved dashboard these come from (for one that shows all the data)


async def _published_wide(db, u: User, dash_id) -> dict[str, dict]:
    """The published widgets, by id, of a dashboard set to show all the data, if this person may view it. Only these
    stored definitions are evaluated without the viewer's limits; whatever a browser sends is never trusted for it."""
    if dash_id is None:
        return {}
    d = await db.get(Dashboard, str(dash_id))
    if d is None or not can_view(d, u) or not shows_everything(d) or d.published is False:
        return {}
    return {w["id"]: w for w in map(cat.clean_widget, d.widgets or []) if w and w.get("id")}


@router.post("/data")
async def widget_data(body: DataBody, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    """Data for widgets (saved or being edited), computed for this viewer. Keyed by widget id."""
    ctx = await cat.context(db, u)
    wide = await _published_wide(db, u, body.dashboard)
    wctx = await cat.context(db, u, everything=True) if wide else None
    out = {}
    for raw in body.widgets:
        w = cat.clean_widget(raw)
        if w:
            stored = wide.get(w["id"]) if w.get("id") else None
            out[w["id"] or w["metric"]] = await cat.evaluate(wctx if stored else ctx, stored or w,
                                                             {"filters": body.filters, "match": body.filter_match})
    return {"data": out, "everything": bool(wide)}


class ExportBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    widget: dict
    filters: list[dict] = Field(default_factory=list, max_length=10)
    filter_match: Literal["all", "any"] = "all"
    dashboard: uuid.UUID | None = None


def _table_of(w: dict, out: dict) -> tuple[list[str], list[list]]:
    """A widget's data as rows: tables as shown, slices as name and count, charts as one row per point."""
    shape = out.get("shape")
    if shape == "table":
        return list(out.get("columns") or []), [[c.get("v") if isinstance(c, dict) else c for c in r] for r in out.get("rows") or []]
    if shape == "parts":
        return ["Name", "Value"], [[i.get("name"), i.get("value")] for i in out.get("items") or []]
    if shape == "series":
        ser = out.get("series") or []
        x = out.get("x") or []
        return ["", *[s.get("name") for s in ser]], [[d, *[(s.get("data") or [None] * len(x))[i] if i < len(s.get("data") or []) else None
                                                            for s in ser]] for i, d in enumerate(x)]
    if shape == "points":
        return ["Group", "Name", out.get("x_label") or "x", out.get("y_label") or "y", out.get("size_label") or "Size"], \
            [[g.get("name"), p[3], p[0], p[1], p[2]] for g in out.get("groups") or [] for p in g.get("points") or []]
    return ["Value"], [[out.get("value")]]


@router.post("/export")
async def export_widget(body: ExportBody, u: User = Depends(_member), db: AsyncSession = Depends(get_session)):
    """One widget's data as CSV, computed for the person exporting (their access and the widget's filters) and
    safe to open in a spreadsheet."""
    from api.core.csv_export import csv_response
    w = cat.clean_widget(body.widget)
    if w is None:
        raise HTTPException(422, "Unknown widget")
    stored = (await _published_wide(db, u, body.dashboard)).get(w.get("id")) if w.get("id") else None
    out = await cat.evaluate(await cat.context(db, u, everything=bool(stored)), stored or w,
                             {"filters": body.filters, "match": body.filter_match})
    w = stored or w
    if out.get("error"):
        raise HTTPException(422, "This widget has no data to export right now")
    header, rows = _table_of(w, out)
    return csv_response(w["title"] or w["metric"], [str(h) for h in header], rows)


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

