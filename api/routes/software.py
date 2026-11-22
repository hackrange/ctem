"""Software inventory: normalized titles with their version and asset counts, each title's versions and assets, and
the review decision (approved or unauthorized). Counts follow the viewer's access; deciding is for admins and cyber."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.device_scope import device_scope
from api.auth.rbac import require_permission
from api.core.db import get_session
from api.core.software_ingest import STALE_DAYS
from api.models.device import Device
from api.models.settings import AuditLog
from api.models.software import SoftwareInstall, SoftwareTitle
from api.models.user import User

router = APIRouter(prefix="/api/v1/software", tags=["software"])
STATUSES = ("unreviewed", "approved", "unauthorized")
_SORTS = {"title": SoftwareTitle.title, "vendor": SoftwareTitle.vendor, "status": SoftwareTitle.status}


def _live():
    return SoftwareInstall.last_seen >= datetime.now(timezone.utc) - timedelta(days=STALE_DAYS)


def _scoped(scope) -> list:
    return [] if scope is None else [SoftwareInstall.device_id.in_(select(Device.id).where(scope))]


def _deciders(u: User) -> bool:
    return bool({"admin", "cyber"} & set(u.role_names))


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("")
async def list_titles(u: User = Depends(require_permission("devices", "read")), db: AsyncSession = Depends(get_session),
                      q: str | None = Query(None, max_length=120),
                      status: Literal["unreviewed", "approved", "unauthorized"] | None = None,
                      include_system: bool = False,
                      sort: str = Query("assets", max_length=16), order: Literal["asc", "desc"] = "desc",
                      limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=1_000_000)):
    scope = await device_scope(u, db)
    assets = func.count(func.distinct(SoftwareInstall.device_id)).label("assets")
    versions = func.count(func.distinct(SoftwareInstall.version)).label("versions")
    stmt = (select(SoftwareTitle, assets, versions).join(SoftwareInstall, SoftwareInstall.title_id == SoftwareTitle.id)
            .where(_live(), *_scoped(scope)).group_by(SoftwareTitle.id))
    if not include_system:
        stmt = stmt.where(SoftwareTitle.system == False)  # noqa: E712
    if status:
        stmt = stmt.where(SoftwareTitle.status == status)
    if q and q.strip():
        like = _like(q.strip())
        stmt = stmt.where(or_(SoftwareTitle.title.ilike(like, escape="\\"), SoftwareTitle.vendor.ilike(like, escape="\\")))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    numeric = {"assets": assets, "versions": versions}
    col = numeric[sort] if sort in numeric else _SORTS.get(sort, assets)
    rows = (await db.execute(stmt.order_by(col.asc() if order == "asc" else col.desc(), SoftwareTitle.title)
                             .limit(limit).offset(offset))).all()
    counts = dict((await db.execute(select(SoftwareTitle.status, func.count(func.distinct(SoftwareTitle.id)))
                                    .join(SoftwareInstall, SoftwareInstall.title_id == SoftwareTitle.id)
                                    .where(_live(), *_scoped(scope),
                                           *([] if include_system else [SoftwareTitle.system == False]))  # noqa: E712
                                    .group_by(SoftwareTitle.status))).all())
    return {"total": total, "scoped": scope is not None, "can_decide": _deciders(u),
            "counts": {s: counts.get(s, 0) for s in STATUSES},
            "titles": [_title(t) | {"assets": a, "versions": v} for t, a, v in rows]}


def _title(t: SoftwareTitle) -> dict:
    return {"id": str(t.id), "title": t.title, "vendor": t.vendor, "system": t.system, "status": t.status,
            "status_note": t.status_note, "decided_by": t.decided_by,
            "decided_at": t.decided_at.isoformat() if t.decided_at else None,
            "first_seen": t.first_seen.isoformat() if t.first_seen else None}


async def _get_title(db, title_id: uuid.UUID) -> SoftwareTitle:
    t = await db.get(SoftwareTitle, str(title_id))
    if t is None:
        raise HTTPException(404)
    return t


@router.get("/{title_id}")
async def title_detail(title_id: uuid.UUID, u: User = Depends(require_permission("devices", "read")),
                       db: AsyncSession = Depends(get_session)):
    """A title's versions, each with how many assets run it (the viewer's assets), and the names sources used."""
    t = await _get_title(db, title_id)
    scope = await device_scope(u, db)
    rows = (await db.execute(
        select(SoftwareInstall.version, func.count(func.distinct(SoftwareInstall.device_id)), func.max(SoftwareInstall.last_seen))
        .where(SoftwareInstall.title_id == t.id, _live(), *_scoped(scope))
        .group_by(SoftwareInstall.version))).all()
    if scope is not None and not rows:
        raise HTTPException(404)   # nothing of it on this person's assets: the same answer as absent
    names = [n for (n,) in (await db.execute(select(SoftwareInstall.product).where(
        SoftwareInstall.title_id == t.id, SoftwareInstall.product.is_not(None)).distinct().limit(20))).all()]
    return {**_title(t), "can_decide": _deciders(u), "reported_as": sorted(set(names)),
            "versions": sorted([{"version": v or "(unknown)", "raw": v, "assets": n, "last_seen": ls.isoformat() if ls else None}
                                for v, n, ls in rows], key=lambda x: _vkey(x["raw"]), reverse=True)}


def _vkey(v: str | None):
    import re
    return [int(p) if p.isdigit() else -1 for p in re.split(r"[.\-+_ ]", v or "")[:8]] or [-1]


@router.get("/{title_id}/assets")
async def title_assets(title_id: uuid.UUID, u: User = Depends(require_permission("devices", "read")),
                       db: AsyncSession = Depends(get_session), version: str | None = Query(None, max_length=128),
                       limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=1_000_000)):
    t = await _get_title(db, title_id)
    scope = await device_scope(u, db)
    w = [SoftwareInstall.title_id == t.id, _live(), *_scoped(scope)]
    if version is not None:
        w.append(SoftwareInstall.version == ("" if version == "(unknown)" else version))
    total = (await db.execute(select(func.count(func.distinct(SoftwareInstall.device_id))).where(*w))).scalar_one()
    rows = (await db.execute(select(Device.id, Device.hostname, Device.device_type, Device.os, SoftwareInstall.version,
                                    SoftwareInstall.source, SoftwareInstall.last_seen)
                             .join(SoftwareInstall, SoftwareInstall.device_id == Device.id).where(*w)
                             .order_by(Device.hostname).limit(limit).offset(offset))).all()
    from api.core.software_status import effective
    from api.models.software import SoftwareException
    from api.routes import device_query as dq
    excs = {e.device_id: e for e in (await db.execute(select(SoftwareException).where(
        SoftwareException.title_id == t.id, SoftwareException.device_id.in_([str(r[0]) for r in rows] or ["-"])))).scalars()}
    return {"total": total, "assets": [{"id": str(i), "hostname": dq.short_name(h), "device_type": dt.value if dt else None,
                                        "os": (o or "")[:80], "version": v or "(unknown)", "source": s,
                                        "last_seen": ls.isoformat() if ls else None,
                                        "status_here": effective(t.status, excs.get(str(i))), "exception": _exc(excs.get(str(i)))}
                                       for i, h, dt, o, v, s, ls in rows]}


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["unreviewed", "approved", "unauthorized"]
    note: str | None = Field(None, max_length=1000, pattern=r"^[^<>\x00-\x08\x0b-\x1f]*$")


@router.put("/{title_id}/status")
async def decide(title_id: uuid.UUID, body: Decision, u: User = Depends(require_permission("devices", "read")),
                 db: AsyncSession = Depends(get_session)):
    """Approve a title or mark it unauthorized (or back to unreviewed). Admins and cyber only; audited."""
    if not _deciders(u):
        raise HTTPException(404)
    t = await _get_title(db, title_id)
    before = t.status
    t.status, t.status_note = body.status, (body.note or "").strip() or None
    t.decided_by = None if body.status == "unreviewed" else u.username
    t.decided_at = None if body.status == "unreviewed" else datetime.now(timezone.utc)
    db.add(AuditLog(actor_user_id=str(u.id), actor_username=u.username, action="software.status", resource_type="software",
                    resource_id=str(t.id), detail=f"{t.title}: {before} to {body.status}"[:300]))
    await db.commit()
    return {"ok": True, "title": _title(t)}


@router.get("/device/{device_id}")
async def device_software(device_id: uuid.UUID, u: User = Depends(require_permission("devices", "read")),
                          db: AsyncSession = Depends(get_session), include_system: bool = False):
    """One asset's software: each title once with its versions here, its status on this asset (its own, or this
    asset's exception), and the file details sources sent (publisher, path, SHA-256, MD5)."""
    from api.core.software_status import effective
    from api.models.software import SoftwareException
    from api.routes.devices import _visible_device
    d = await _visible_device(device_id, u, db)   # 404 for absent and not yours alike
    stmt = (select(SoftwareTitle, SoftwareInstall).join(SoftwareInstall, SoftwareInstall.title_id == SoftwareTitle.id)
            .where(SoftwareInstall.device_id == d.id, _live()))
    if not include_system:
        stmt = stmt.where(SoftwareTitle.system == False)  # noqa: E712
    excs = {e.title_id: e for e in (await db.execute(select(SoftwareException).where(SoftwareException.device_id == d.id))).scalars()}
    out: dict[str, dict] = {}
    for t, i in (await db.execute(stmt.order_by(SoftwareTitle.title))).all():
        e = excs.get(t.id)
        row = out.setdefault(str(t.id), {**_title(t), "versions": [], "last_seen": None, "files": [],
                                         "status_here": effective(t.status, e), "exception": _exc(e)})
        if (i.version or "(unknown)") not in row["versions"]:
            row["versions"].append(i.version or "(unknown)")
        ls = i.last_seen.isoformat() if i.last_seen else None
        row["last_seen"] = max(filter(None, [row["last_seen"], ls]), default=None)
        if i.publisher or i.install_path or i.sha256 or i.md5:
            row["files"].append({"version": i.version or "(unknown)", "publisher": i.publisher, "path": i.install_path,
                                 "sha256": i.sha256, "md5": i.md5, "source": i.source})
    return {"software": list(out.values()), "can_decide": _deciders(u)}


def _exc(e) -> dict | None:
    if e is None:
        return None
    from api.core.software_status import effective
    active = effective("unreviewed", e) != "unreviewed"
    return {"decision": e.decision, "reason": e.reason, "expires_at": e.expires_at.isoformat() if e.expires_at else None,
            "decided_by": e.decided_by, "active": active}
