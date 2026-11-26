"""The IDV page (cyber and admin): identity verification requests from Persona in three tabs (pending, approved,
rejected), the count waiting for a cyber decision (the sidebar bubble), and approve or decline, which goes to Persona
too. Persona facts are personal data, so everything here is cyber or admin only; 404 for an id that isn't there."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.models.idv import IdvRequest
from api.models.user import User

log = logging.getLogger("open-ctem.idv")
router = APIRouter(prefix="/api/v1/idv", tags=["idv"])
TABS = {"pending": ("pending", "review"), "approved": ("approved",), "rejected": ("rejected", "expired", "superseded")}


def view(r: IdvRequest, person: User | None) -> dict:
    f = r.facts or {}
    return {"id": r.id, "state": r.state, "persona_status": r.persona_status, "template": r.template, "origin": r.origin,
            "created_at": _iso(r.created_at), "completed_at": _iso(r.completed_at), "decided_at": _iso(r.decided_at),
            "expires_at": _iso(r.expires_at), "reviewed_at": _iso(r.reviewed_at), "review_note": r.review_note,
            "country": f.get("country"), "region": f.get("region"), "id_type": f.get("id_type"),
            "device_type": f.get("device_type"), "os": f.get("os"), "browser": f.get("browser"),
            "threat_level": f.get("threat_level"), "flags": [k for k in ("vpn", "proxy", "tor", "datacenter") if f.get(k)],
            "person": {"id": person.id, "name": person.display_name or person.username, "upn": person.upn,
                       "idv_verified_at": _iso(person.idv_verified_at)} if person is not None else None}


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


@router.get("/summary")
async def summary(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    rows = dict((await db.execute(select(IdvRequest.state, func.count()).group_by(IdvRequest.state))).all())
    return {"review": rows.get("review", 0), **{t: sum(rows.get(s, 0) for s in states) for t, states in TABS.items()}}


@router.get("/requests")
async def list_requests(tab: str = Query("pending", pattern="^(pending|approved|rejected)$"),
                        q: str | None = Query(None, max_length=100, pattern=r"^[^\x00-\x1f\x7f]*$"), limit: int = Query(50, ge=1, le=200),
                        offset: int = Query(0, ge=0, le=100_000),
                        _: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    stmt = select(IdvRequest, User).outerjoin(User, User.id == IdvRequest.user_id).where(IdvRequest.state.in_(TABS[tab]))
    if q and q.strip():
        from api.core.encryption import search_hash
        from api.core.user_match import upn_keys
        term = q.strip().lower()
        keys = [k for k in upn_keys(term) if k] if "@" in term else [search_hash(term)]
        stmt = stmt.where(or_(User.upn_hash.in_(keys), User.upn_local_hash.in_(keys), User.email_hash.in_(keys),
                              User.username == term[:128]))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    order = (IdvRequest.state == "review").desc() if tab == "pending" else IdvRequest.state.asc()
    rows = (await db.execute(stmt.order_by(order, IdvRequest.created_at.desc().nullslast(), IdvRequest.id)
                             .limit(limit).offset(offset))).all()
    return {"requests": [view(r, u) for r, u in rows], "total": total, "limit": limit, "offset": offset}


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern="^(approve|decline)$")
    note: str = Field(min_length=3, max_length=500)


@router.post("/requests/{request_id}/review")
async def review(request_id: uuid.UUID, body: Review, me: User = Depends(require_cyber_or_admin),
                 db: AsyncSession = Depends(get_session)):
    """Approve or decline one waiting for cyber. Persona gets the same decision; if it refuses, nothing changes here."""
    from api.integrations.base import get_connector
    from api.integrations.persona import PersonaError
    from api.models.integration import IntegrationConfig
    from api.models.settings import AuditLog
    r = (await db.execute(select(IdvRequest).where(IdvRequest.id == str(request_id)).with_for_update())).scalar_one_or_none()
    if r is None:
        raise HTTPException(404)
    if r.state != "review":
        raise HTTPException(409, detail="Only a request waiting for review can be approved or declined")
    cfg = await db.get(IntegrationConfig, r.integration_id) if r.integration_id else None
    if cfg is None or not cfg.is_enabled:
        raise HTTPException(409, detail="The Persona integration this came from is off or gone")
    conn = get_connector("persona", cfg.config or {})
    if not (cfg.config or {}).get("allow_actions"):
        raise HTTPException(409, detail="Approve and decline are turned off in the Persona integration")
    approve = body.decision == "approve"
    try:
        status = await conn.review(r.inquiry_id, approve, f"CTEM ({me.username}): {body.note}")
    except PersonaError as e:
        log.warning("Persona review of %s failed: %s", r.id, e)
        raise HTTPException(502, detail="Persona didn't accept the decision; nothing was changed") from e
    now = datetime.now(timezone.utc)
    r.state, r.persona_status = ("approved" if approve else "rejected"), (status or ("approved" if approve else "declined"))[:32]
    r.reviewed_by, r.reviewed_at, r.review_note, r.decided_at = str(me.id), now, body.note, now
    db.add(AuditLog(actor_user_id=str(me.id), actor_username=me.username, action=f"idv.{body.decision}",
                    resource_type="idv_request", resource_id=str(r.id), detail=body.note[:300]))
    await db.flush()
    from api.integrations.persona_ingest import link_people
    await link_people(db)
    await db.commit()
    person = await db.get(User, r.user_id) if r.user_id else None
    return view(r, person)
