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
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.middleware import get_current_user
from api.core.db import get_session
from api.models.idv import IdvRequest
from api.models.user import User

log = logging.getLogger("open-ctem.idv")
router = APIRouter(prefix="/api/v1/idv", tags=["idv"])
VIEWERS = {"admin", "cyber", "idv_approvers"}
RECENT_DAYS = 5   # the list's default window and the sidebar bubble's


async def require_idv_viewer(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_session)) -> User:
    """The IDV page holds personal data: cyber, admin, and whoever may decide (idv:approve, so a copy of the IDV
    Approvers role sees what it decides)."""
    from api.auth.rbac import _load_user_permissions
    if VIEWERS.intersection(user.role_names):
        return user
    if any(p.startswith("idv:approve:") for p in await _load_user_permissions(user, db)):
        return user
    raise HTTPException(403, detail="Cyber, Admin or IDV Approver access required")


# Pending: what needs a decision (failed or flagged, and passed-but-not-ID-verified); a check the person hasn't
# finished isn't one. Expired (abandoned) checks aren't shown.
TABS = {"pending": ("review",), "approved": ("approved",), "rejected": ("rejected", "superseded")}


def unproven_sql():
    """A check that passed in Persona but doesn't earn the badge, for someone with no badge: a selfie-only re-check
    from someone who never passed a government ID, or one started from a hosted link. It waits in Pending for an
    approver, because Persona says yes and CTEM can't confirm who it was."""
    return and_(IdvRequest.state == "approved", IdvRequest.user_id.is_not(None), User.idv_verified_at.is_(None),
                or_(User.idv_revoked_at.is_(None), IdvRequest.created_at > User.idv_revoked_at))


def unproven(r: IdvRequest, person: User | None) -> bool:
    if r.state != "approved" or person is None or person.idv_verified_at is not None:
        return False
    return person.idv_revoked_at is None or (r.created_at is not None and r.created_at > person.idv_revoked_at)


def view(r: IdvRequest, person: User | None) -> dict:
    f = r.facts or {}
    return {"id": r.id, "state": "unproven" if unproven(r, person) else r.state, "persona_status": r.persona_status, "template": r.template, "origin": r.origin,
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
    odd = (await db.execute(select(func.count()).select_from(IdvRequest).join(User, User.id == IdvRequest.user_id)
                            .where(unproven_sql()))).scalar_one()
    from datetime import timedelta
    cut = datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)   # the sidebar bubble: what is new, not the backlog
    recent = (await db.execute(select(func.count()).select_from(IdvRequest).outerjoin(User, User.id == IdvRequest.user_id)
                               .where(IdvRequest.created_at >= cut, or_(IdvRequest.state == "review", unproven_sql())))).scalar_one()
    return {"review": rows.get("review", 0) + odd, "unproven": odd, "review_recent": recent, "recent_days": RECENT_DAYS,
            **{t: sum(rows.get(s, 0) for s in states) for t, states in TABS.items()}}


@router.get("/requests")
async def list_requests(tab: str = Query("pending", pattern="^(pending|approved|rejected)$"),
                        q: str | None = Query(None, max_length=100, pattern=r"^[^\x00-\x1f\x7f]*$"), limit: int = Query(50, ge=1, le=200),
                        offset: int = Query(0, ge=0, le=100_000),
                        days: int | None = Query(None, ge=1, le=3650, description="Only requests from the last N days"),
                        _: User = Depends(require_idv_viewer), db: AsyncSession = Depends(get_session)):
    tab_rows = IdvRequest.state.in_(TABS[tab])
    if tab == "pending":
        tab_rows = or_(tab_rows, unproven_sql())
    elif tab == "approved":
        tab_rows = and_(tab_rows, ~unproven_sql())
    stmt = select(IdvRequest, User).outerjoin(User, User.id == IdvRequest.user_id).where(tab_rows)
    older = 0
    if days:
        from datetime import timedelta
        cut = datetime.now(timezone.utc) - timedelta(days=days)
        older = (await db.execute(select(func.count()).select_from(stmt.where(IdvRequest.created_at < cut).subquery()))).scalar_one()
        stmt = stmt.where(IdvRequest.created_at >= cut)
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
    return {"requests": [view(r, u) for r, u in rows], "total": total, "limit": limit, "offset": offset, "older": older}


@router.get("/requests/{request_id}")
async def one_request(request_id: uuid.UUID, me: User = Depends(require_idv_viewer), db: AsyncSession = Depends(get_session)):
    """One request in full, for the review dialog: what the person presented, which checks failed, what each means
    and what to validate, how often the person verified before, and what this viewer may do."""
    from api.auth.rbac import _load_user_permissions
    from api.integrations.persona_checks import APPROVE_REASONS, DECLINE_REASONS, EXPIRE_REASONS, REVOKE_REASONS, explain
    r = (await db.execute(select(IdvRequest).where(IdvRequest.id == str(request_id)))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404)
    person = await db.get(User, r.user_id) if r.user_id else None
    history = {"verified": 0, "failed": 0, "expired": 0, "in_progress": 0, "last_verified_at": None, "id_passed_before": False}
    if r.okta_id:   # the person's other checks, as counts: this dialog is about the one being reviewed
        from api.integrations.persona_checks import gov_id_passed
        others = (await db.execute(select(IdvRequest.state, IdvRequest.completed_at, IdvRequest.decided_at, IdvRequest.facts)
                                   .where(IdvRequest.okta_id == r.okta_id, IdvRequest.id != r.id).limit(1000))).all()
        for state, done, decided, facts in others:
            key = {"approved": "verified", "review": "failed", "rejected": "failed", "superseded": "failed",
                   "expired": "expired"}.get(state, "in_progress")
            history[key] += 1
            at = done or decided
            if state == "approved" and at and (history["last_verified_at"] is None or at > history["last_verified_at"]):
                history["last_verified_at"] = at
            if gov_id_passed(facts):
                history["id_passed_before"] = True
        history["last_verified_at"] = _iso(history["last_verified_at"])
    approver = any(p.startswith("idv:approve:") for p in await _load_user_permissions(me, db))
    return {**view(r, person), "explain": explain(r.facts),
            "person_detail": {"first_name": person.first_name, "last_name": person.last_name, "title": person.title,
                              "department": person.department} if person is not None else None,
            "history": history,
            "can": {"review": approver and (r.state == "review" or unproven(r, person)), "revoke": approver and person is not None and person.idv_verified_at is not None,
                    "names": approver},
            "reasons": {"approve": APPROVE_REASONS, "decline": DECLINE_REASONS, "revoke": REVOKE_REASONS,
                        "expire": EXPIRE_REASONS} if approver else None}
