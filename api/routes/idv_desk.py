"""Send a person a Persona re-verification link, by SMS or email, from Discovered Users or a device's detected user.

Who: anyone with idv:request (admin, cyber, IDV Validation). Where it goes: only a contact the person's SSO/MFA
provider verified (api/core/verified_contacts.py), never a number or address typed in, so the link reaches the person
the account belongs to. What happens: CTEM starts a Persona inquiry on the service desk's template with the person's
Okta id as its reference, makes a one-time link (24 hours), and sends it through Twilio (SMS) or CTEM's email
service. The link is never stored, logged or shown to the sender. The request then shows on the IDV page and its
result comes in with the Persona sync, like any other check. Limits: one link per person every 10 minutes, and 30 an
hour per sender."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.core.verified_contacts import ineligible, verified_contacts
from api.models.idv import IdvRequest
from api.models.user import User

log = logging.getLogger("open-ctem.idv")
router = APIRouter(prefix="/api/v1/idv", tags=["idv"])
requester = require_permission("idv", "request")
PER_PERSON = timedelta(minutes=10)
PER_SENDER_HOUR = 30


class Send(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: str = Field(pattern="^(sms|email)$")
    confirm_recent: bool = False   # the sender checked a contact enrolled or changed in the last 7 days


async def _integration(db: AsyncSession, vendor) -> object | None:
    from api.models.integration import IntegrationConfig
    return (await db.execute(select(IntegrationConfig).where(IntegrationConfig.vendor == vendor, IntegrationConfig.is_enabled.is_(True))
                             .order_by(IntegrationConfig.created_at))).scalars().first()


async def _readiness(db: AsyncSession) -> dict:
    """What sending needs, and what's missing, in words for the button."""
    from api.core.email import configured
    from api.models.integration import Vendor
    persona, twilio = await _integration(db, Vendor.persona), await _integration(db, Vendor.twilio)
    pc = (persona.config or {}) if persona else {}
    missing = []
    if persona is None:
        missing.append("connect Persona")
    elif not pc.get("allow_actions"):
        missing.append("turn on Persona actions")
    elif not pc.get("template_id"):
        missing.append("set the Persona template the service desk sends")
    return {"persona": persona if not missing else None, "twilio": twilio, "email": await configured(), "missing": missing}


async def _person(db: AsyncSession, user_id: uuid.UUID) -> User:
    u = (await db.execute(select(User).where(User.id == str(user_id)))).scalar_one_or_none()
    if u is None:
        raise HTTPException(404)
    return u


@router.get("/people/{user_id}/contacts")
async def contacts(user_id: uuid.UUID, _: User = Depends(requester), db: AsyncSession = Depends(get_session)):
    """The verified channels a link can go to (masked), and whether CTEM can send right now."""
    u = await _person(db, user_id)
    ready = await _readiness(db)
    c = verified_contacts(u)
    out = {"channels": [], "missing": list(ready["missing"]), "reference": bool(u.okta_id)}
    why = ineligible(u) or (None if u.okta_id else "the person isn't linked to an identity provider account")
    if why:
        out["missing"].append(why)
    for ch, ok in (("sms", ready["twilio"] is not None), ("email", ready["email"])):
        if c[ch]:
            out["channels"].append({"channel": ch, "shown": c[ch]["shown"], "source": c[ch]["source"],
                                    "since": c[ch]["since"], "recent": c[ch]["recent"],
                                    "available": ok, "why_not": None if ok else ("connect Twilio" if ch == "sms" else "set up Email")})
    return out


@router.post("/people/{user_id}/send")
async def send(user_id: uuid.UUID, body: Send, me: User = Depends(requester), db: AsyncSession = Depends(get_session)):
    """Checks and a reservation row under short locks (sender, then person), committed; then Persona and the message
    with no lock held; then the outcome on that row. Every attempt is recorded and counts toward the limits."""
    from api.integrations.base import get_connector
    from api.integrations.persona import PersonaError
    from api.models.settings import AuditLog
    first, second = sorted({str(me.id), str(user_id)})   # one lock order, so two sends can't deadlock
    for uid in (first, second):
        await db.execute(select(User.id).where(User.id == uid).with_for_update())
    u = (await db.execute(select(User).where(User.id == str(user_id)))).scalar_one_or_none()
    if u is None:
        raise HTTPException(404)
    ready = await _readiness(db)
    if ready["missing"]:
        raise HTTPException(409, detail="Can't send yet: " + "; ".join(ready["missing"]))
    why = ineligible(u) or (None if u.okta_id else "the person isn't linked to an identity provider account")
    if why:
        raise HTTPException(409, detail=f"No link can go to this person: {why}")
    to = verified_contacts(u)[body.channel]
    if to is None:
        raise HTTPException(409, detail=f"No verified {'SMS MFA phone' if body.channel == 'sms' else 'MFA email address'} for this person")
    if to["recent"] and not body.confirm_recent:
        raise HTTPException(409, detail="This MFA contact was enrolled or changed in the last 7 days (or the provider didn't say when). "
                                        "Confirm with the person another way first, then confirm here")
    if body.channel == "sms" and ready["twilio"] is None:
        raise HTTPException(409, detail="Connect Twilio to send texts")
    if body.channel == "email" and not ready["email"]:
        raise HTTPException(409, detail="Set up Email to send email")
    now = datetime.now(timezone.utc)
    recent = (await db.execute(select(func.count()).select_from(IdvRequest).where(
        IdvRequest.user_id == u.id, IdvRequest.origin == "service_desk", IdvRequest.created_at > now - PER_PERSON))).scalar_one()
    if recent:
        raise HTTPException(429, detail="A link went to this person in the last 10 minutes; give them time to use it")
    mine = (await db.execute(select(func.count()).select_from(IdvRequest).where(
        IdvRequest.requested_by == str(me.id), IdvRequest.created_at > now - timedelta(hours=1)))).scalar_one()
    if mine >= PER_SENDER_HOUR:
        raise HTTPException(429, detail="That's the most links one person can send in an hour")
    persona_cfg, twilio_cfg = ready["persona"], ready["twilio"]
    row = IdvRequest(inquiry_id=f"sending_{uuid.uuid4().hex}", integration_id=str(persona_cfg.id), user_id=u.id, okta_id=u.okta_id,
                     state="sending", persona_status=None, created_via="API", origin="service_desk", requested_by=str(me.id),
                     channels=[{"channel": body.channel, "to": to["shown"], "at": now.isoformat(), "status": "sending"}],
                     created_at=now, updated_at=now, template_id=str((persona_cfg.config or {}).get("template_id") or "") or None)
    db.add(row)
    db.add(AuditLog(actor_user_id=str(me.id), actor_username=me.username, action="idv.send", resource_type="user",
                    resource_id=str(u.id), detail=f"{body.channel} requested"))
    await db.commit()   # the locks go; the vendors are called with none held
    okta_id, names = u.okta_id, {"name-first": u.first_name, "name-last": u.last_name}
    sent, iid, link = dict(row.channels[0]), None, None
    try:
        iid, link = await get_connector("persona", persona_cfg.config or {}).start_inquiry(okta_id, names)
    except PersonaError as e:
        log.warning("Persona inquiry for %s failed: %s", u.id, e)
        iid = getattr(e, "inquiry", None)
        sent["status"] = "persona_failed"
    if link:
        text = ("Your security team asks you to verify your identity. Use this link within 24 hours: "
                f"{link} . If you didn't expect this, contact the service desk.")
        try:
            if body.channel == "sms":
                r = await get_connector("twilio", twilio_cfg.config or {}).send(to["to"], text)
                sent.update({"sid": r.get("sid"), "status": r.get("status") or "sent"})
            else:
                from api.core.email import get_email_client
                sent["status"] = "sent" if await get_email_client().send(to["to"], "Please verify your identity", text) else "failed"
        except Exception as e:  # noqa: BLE001 -- the outcome is recorded either way; only the error type is logged
            log.warning("IDV link for %s not delivered by %s: %s", u.id, body.channel, type(e).__name__)
            sent["status"] = "failed"
        del text, link
    delivered = sent["status"] not in ("failed", "persona_failed")
    if iid:
        row.inquiry_id = iid
    row.state = "pending" if delivered else "failed"
    row.persona_status = "created" if iid else None
    row.channels = [sent]
    row.updated_at = datetime.now(timezone.utc)
    db.add(AuditLog(actor_user_id=str(me.id), actor_username=me.username, action="idv.send", resource_type="user",
                    resource_id=str(u.id), detail=f"{body.channel} {sent['status']}"))
    await db.commit()
    if sent["status"] == "persona_failed":
        raise HTTPException(502, detail="Persona didn't start the verification; nothing was sent")
    if not delivered:
        raise HTTPException(502, detail="The verification started, but the message didn't go out; try the other channel")
    return {"sent": True, "channel": body.channel, "to": to["shown"], "expires_hours": 24}
