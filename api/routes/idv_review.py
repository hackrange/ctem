"""IDV decisions, for the IDV Approvers role only (permission idv:approve; not even admin has it unless the role is
assigned): approve or decline a check waiting for review, revoke a person's verification, and read the name printed on
the ID and the network the check came from, to compare. Every decision takes a reason from a fixed list
(api/integrations/persona_checks.py) and a note, goes to Persona too, and is audited.

Revoking marks the person (User.idv_revoked_at): every pass before it stops counting, so the badge goes until they
pass a new check with both a government ID and a selfie that matches it (a selfie-only re-check never brings it back), and their approved checks are declined in Persona when Persona actions are on. Okta decides when it next
asks the person to verify; CTEM never writes to Okta."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.integrations.persona_checks import APPROVE_REASONS, DECLINE_REASONS, EXPIRE_REASONS, REVOKE_REASONS
from api.models.idv import IdvRequest
from api.models.user import User
from api.routes.idv import view

log = logging.getLogger("open-ctem.idv")
router = APIRouter(prefix="/api/v1/idv", tags=["idv"])
_approver = require_permission("idv", "approve")


async def approver(me: User = Depends(_approver), db: AsyncSession = Depends(get_session)) -> User:
    """An IDV approver, while IDV approval is on (Persona integration: Enable IDV approval)."""
    from api.core.idv_send import approval_enabled
    if not await approval_enabled(db):
        raise HTTPException(409, detail="IDV approval is turned off in the Persona integration")
    return me
MAX_REVOKE = 25   # approved checks declined in Persona per revoke; older ones stop counting anyway


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern="^(approve|decline)$")
    reason: str = Field(pattern="^[a-z_]{2,32}$")
    note: str = Field(min_length=3, max_length=500, pattern=r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*$")


class Revoke(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: str = Field("revoke", pattern="^(revoke|expire)$")   # expire: no longer enough, not a judgment on the check
    send: str | None = Field(None, pattern="^(sms|email)$")      # also send a re-verification link now, to this verified contact
    confirm_recent: bool = False                                  # the approver checked a contact enrolled or changed recently
    reason: str = Field(pattern="^[a-z_]{2,32}$")
    note: str = Field(min_length=3, max_length=500, pattern=r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*$")


async def _connector(db: AsyncSession, r: IdvRequest, need_actions: bool = True):
    from api.integrations.base import get_connector
    from api.models.integration import IntegrationConfig
    cfg = await db.get(IntegrationConfig, r.integration_id) if r.integration_id else None
    if cfg is None or not cfg.is_enabled:
        raise HTTPException(409, detail="The Persona integration this came from is off or gone")
    if need_actions and not (cfg.config or {}).get("allow_actions"):
        raise HTTPException(409, detail="Approve and decline are turned off in the Persona integration")
    return get_connector("persona", cfg.config or {})


def _audit(db, me: User, action: str, kind: str, rid: str, detail: str) -> None:
    from api.models.settings import AuditLog
    db.add(AuditLog(actor_user_id=str(me.id), actor_username=me.username, action=action, resource_type=kind,
                    resource_id=rid, detail=detail[:300]))


@router.post("/requests/{request_id}/review")
async def review(request_id: uuid.UUID, body: Review, me: User = Depends(approver), db: AsyncSession = Depends(get_session)):
    """Approve or decline one waiting for review. Persona gets the same decision; if it refuses, nothing changes here."""
    from api.integrations.persona import PersonaError
    from api.integrations.persona_ingest import link_people
    approve = body.decision == "approve"
    reasons = APPROVE_REASONS if approve else DECLINE_REASONS
    if body.reason not in reasons:
        raise HTTPException(400, detail="Pick a reason from the list")
    r = (await db.execute(select(IdvRequest).where(IdvRequest.id == str(request_id)).with_for_update())).scalar_one_or_none()
    if r is None:
        raise HTTPException(404)
    from api.routes.idv import unproven
    person = await db.get(User, r.user_id) if r.user_id else None
    if r.state != "review" and not unproven(r, person):
        raise HTTPException(409, detail="Only a request waiting for review can be approved or declined")
    conn = await _connector(db, r)
    try:
        status = await conn.review(r.inquiry_id, approve, f"CTEM ({me.username}): {reasons[body.reason]}. {body.note}")
    except PersonaError as e:
        log.warning("Persona review of %s failed: %s", r.id, e)
        raise HTTPException(502, detail="Persona didn't accept the decision; nothing was changed") from e
    now = datetime.now(timezone.utc)
    r.state, r.persona_status = ("approved" if approve else "rejected"), (status or ("approved" if approve else "declined"))[:32]
    r.reviewed_by, r.reviewed_at, r.review_note, r.review_reason, r.decided_at = str(me.id), now, body.note, body.reason, now
    _audit(db, me, f"idv.{body.decision}", "idv_request", str(r.id), f"{body.reason}")   # the note stays encrypted on the row
    await db.flush()
    await link_people(db)
    await db.commit()
    if person is not None:
        await db.refresh(person)
    return view(r, person)


@router.post("/people/{user_id}/revoke")
async def revoke(user_id: uuid.UUID, body: Revoke, me: User = Depends(approver), db: AsyncSession = Depends(get_session)):
    """Take a person's verification away: the badge goes until they verify again with a government ID and a selfie
    that matches it. expire: it is no longer enough (periodic, role change); Persona's checks stay as they are, and
    such a pass brings the badge back. revoke: something is wrong with it; their approved checks are declined in
    Persona too, and a new pass waits in Pending for an approver before the badge comes back. Either can send the
    person a re-verification link at once (send)."""
    from api.integrations.persona import PersonaError
    from api.integrations.persona_ingest import link_people
    reasons = EXPIRE_REASONS if body.mode == "expire" else REVOKE_REASONS
    if body.reason not in reasons:
        raise HTTPException(400, detail="Pick a reason from the list")
    person = (await db.execute(select(User).where(User.id == str(user_id)).with_for_update())).scalar_one_or_none()
    if person is None or not (await db.execute(select(IdvRequest.id).where(IdvRequest.user_id == person.id).limit(1))).first():
        raise HTTPException(404)   # the same for nobody and for someone with no verification
    now = datetime.now(timezone.utc)
    person.idv_revoked_at, person.idv_revoked_kind = now, body.mode
    approved = [] if body.mode == "expire" else (await db.execute(
        select(IdvRequest).where(IdvRequest.user_id == person.id, IdvRequest.state == "approved")
        .order_by(IdvRequest.created_at.desc().nullslast()).limit(MAX_REVOKE))).scalars().all()
    declined, kept = 0, 0
    for r in approved:
        try:
            conn = await _connector(db, r)
            status = await conn.review(r.inquiry_id, False, f"CTEM ({me.username}) revoked: {REVOKE_REASONS[body.reason]}. {body.note}")
        except (HTTPException, PersonaError) as e:
            log.warning("Persona decline of %s on revoke failed: %s", r.id, getattr(e, "detail", e))
            kept += 1   # stays approved in Persona; the revoke date still sets it aside here
            continue
        r.state, r.persona_status = "rejected", (status or "declined")[:32]
        r.reviewed_by, r.reviewed_at, r.review_note, r.review_reason, r.decided_at = str(me.id), now, body.note, body.reason, now
        declined += 1
    _audit(db, me, f"idv.{body.mode}", "user", str(person.id), f"{body.reason}")
    await db.flush()
    await link_people(db)
    await db.commit()
    link = None
    if body.send:   # the link goes out after the revoke is saved; if it can't, the revoke still stands
        from api.core.idv_send import send_link
        try:
            _, out = await send_link(db, str(user_id), body.send, body.confirm_recent, str(me.id), me.username, note=f" after {body.mode}",
                                     kind="id_selfie")   # after an expire or revoke it's always a government ID and a selfie
            link = {"sent": True, "to": out["to"], "channel": out["channel"]}
        except HTTPException as e:
            link = {"sent": False, "error": e.detail if isinstance(e.detail, str) else "The link didn't go out"}
    await db.refresh(person)
    return {"revoked_at": now.isoformat(), "kind": body.mode, "link": link, "declined_in_persona": declined, "not_declined_in_persona": kept,
            "idv_verified_at": person.idv_verified_at.isoformat() if person.idv_verified_at else None}


@router.get("/requests/{request_id}/live")
async def live(request_id: uuid.UUID, response: Response, me: User = Depends(approver),
                   db: AsyncSession = Depends(get_session)):
    """For the approver, read from Persona now: the name printed on the ID next to the name in the directory, and the
    network each session came from (ISP, country by IP and GPS). Not stored and not cached; each look is audited."""
    from api.integrations.persona import PersonaError
    response.headers["Cache-Control"] = "no-store"
    r = (await db.execute(select(IdvRequest).where(IdvRequest.id == str(request_id)))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404)
    conn = await _connector(db, r, need_actions=False)
    try:
        got = await conn.live_details(r.inquiry_id)
    except PersonaError as e:
        log.warning("Persona name read for %s failed: %s", r.id, e)
        raise HTTPException(502, detail="Persona didn't answer; try again") from e
    person = await db.get(User, r.user_id) if r.user_id else None
    _audit(db, me, "idv.view_live", "idv_request", str(r.id), "read the name on the ID and the network from Persona")
    await db.commit()
    return {**got,
            "directory": {"first": person.first_name, "last": person.last_name, "display": person.display_name}
            if person is not None else None}
