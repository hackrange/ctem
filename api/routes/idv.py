"""The IDV page (cyber, admin and IDV approvers): identity verification requests from Persona in three tabs (pending,
approved, rejected), the count waiting for a decision (the sidebar bubble), and one request in full: what the person
presented, what failed and what to validate. Approve, decline and revoke are in api/routes/idv_review.py, for the
IDV Approvers role only. Persona facts are personal data; 404 for an id that isn't there."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.middleware import get_current_user
from api.core.db import get_session
from api.models.idv import IdvRequest
from api.models.user import User

log = logging.getLogger("open-ctem.idv")
router = APIRouter(prefix="/api/v1/idv", tags=["idv"])
VIEWERS = {"admin", "cyber", "idv_approvers"}


async def require_idv_viewer(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_session)) -> User:
    """The IDV page holds personal data: cyber, admin, and whoever may decide (idv:approve, so a copy of the IDV
    Approvers role sees what it decides)."""
    from api.auth.rbac import _load_user_permissions
    if VIEWERS.intersection(user.role_names):
        return user
    if any(p.startswith("idv:approve:") for p in await _load_user_permissions(user, db)):
        return user
    raise HTTPException(403, detail="Cyber, Admin or IDV Approver access required")


TABS = {"pending": ("pending", "review"), "approved": ("approved",), "rejected": ("rejected", "expired", "superseded")}


def view(r: IdvRequest, person: User | None) -> dict:
    f = r.facts or {}
    return {"id": r.id, "state": r.state, "persona_status": r.persona_status, "template": r.template, "origin": r.origin,
            "created_at": _iso(r.created_at), "completed_at": _iso(r.completed_at), "decided_at": _iso(r.decided_at),
            "expires_at": _iso(r.expires_at), "reviewed_at": _iso(r.reviewed_at), "review_note": r.review_note,
            "review_reason": r.review_reason, "superseded": r.state == "superseded", "created_via": r.created_via,
            "country": f.get("country"), "region": f.get("region"), "id_type": f.get("id_type"),
            "device_type": f.get("device_type"), "os": f.get("os"), "browser": f.get("browser"),
            "threat_level": f.get("threat_level"), "flags": [k for k in ("vpn", "proxy", "tor", "datacenter") if f.get(k)],
            "person": {"id": person.id, "name": person.display_name or person.username, "upn": person.upn,
                       "idv_verified_at": _iso(person.idv_verified_at), "idv_revoked_at": _iso(person.idv_revoked_at)}
            if person is not None else None}


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


@router.get("/summary")
async def summary(_: User = Depends(require_idv_viewer), db: AsyncSession = Depends(get_session)):
    rows = dict((await db.execute(select(IdvRequest.state, func.count()).group_by(IdvRequest.state))).all())
    return {"review": rows.get("review", 0), **{t: sum(rows.get(s, 0) for s in states) for t, states in TABS.items()}}


@router.get("/requests")
async def list_requests(tab: str = Query("pending", pattern="^(pending|approved|rejected)$"),
                        q: str | None = Query(None, max_length=100, pattern=r"^[^\x00-\x1f\x7f]*$"), limit: int = Query(50, ge=1, le=200),
                        offset: int = Query(0, ge=0, le=100_000),
                        _: User = Depends(require_idv_viewer), db: AsyncSession = Depends(get_session)):
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


@router.get("/requests/{request_id}")
async def one_request(request_id: uuid.UUID, me: User = Depends(require_idv_viewer), db: AsyncSession = Depends(get_session)):
    """One request in full, for the review dialog: what the person presented, which checks failed, what each means
    and what to validate, the person's other attempts, and what this viewer may do."""
    from api.auth.rbac import _load_user_permissions
    from api.integrations.persona_checks import APPROVE_REASONS, DECLINE_REASONS, REVOKE_REASONS, explain
    r = (await db.execute(select(IdvRequest).where(IdvRequest.id == str(request_id)))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404)
    person = await db.get(User, r.user_id) if r.user_id else None
    others = []
    if r.okta_id:
        others = (await db.execute(select(IdvRequest).where(IdvRequest.okta_id == r.okta_id, IdvRequest.id != r.id)
                                   .order_by(IdvRequest.created_at.desc().nullslast()).limit(30))).scalars().all()
    approver = any(p.startswith("idv:approve:") for p in await _load_user_permissions(me, db))
    return {**view(r, person), "explain": explain(r.facts),
            "person_detail": {"first_name": person.first_name, "last_name": person.last_name, "title": person.title,
                              "department": person.department} if person is not None else None,
            "attempts": [{"id": o.id, "state": o.state, "created_at": _iso(o.created_at), "id_type": (o.facts or {}).get("id_type"),
                          "country": (o.facts or {}).get("country"),
                          "failed": [f["check"] for f in explain(o.facts)["failed"]][:6]} for o in others],
            "can": {"review": approver and r.state == "review", "revoke": approver and person is not None and person.idv_verified_at is not None,
                    "names": approver},
            "reasons": {"approve": APPROVE_REASONS, "decline": DECLINE_REASONS, "revoke": REVOKE_REASONS} if approver else None}
