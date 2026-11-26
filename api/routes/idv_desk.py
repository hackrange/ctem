"""Send a person a Persona re-verification link, by SMS or email, from Discovered Users or a device's detected user.

Who: anyone with idv:request (admin, cyber, IDV Validation). Where it goes: only a contact the person's SSO/MFA
provider verified (api/core/verified_contacts.py), never a number or address typed in, so the link reaches the person
the account belongs to. What happens: CTEM starts a Persona inquiry on the service desk's template with the person's
Okta id as its reference, makes a one-time link (24 hours), and sends it through Twilio (SMS) or CTEM's email
service. The link is never stored, logged or shown to the sender. The request then shows on the IDV page and its
result comes in with the Persona sync, like any other check. Limits: one link per person every 10 minutes, and 30 an
hour per sender."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.core.verified_contacts import ineligible, verified_contacts
from api.models.user import User

router = APIRouter(prefix="/api/v1/idv", tags=["idv"])
requester = require_permission("idv", "request")


class Send(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: str = Field(pattern="^(sms|email)$")
    confirm_recent: bool = False   # the sender checked a contact enrolled or changed in the last 7 days


async def _person(db: AsyncSession, user_id: uuid.UUID) -> User:
    from api.core.accounts import directory_person
    u = (await db.execute(select(User).where(User.id == str(user_id), directory_person()))).scalar_one_or_none()
    if u is None:
        raise HTTPException(404)
    return u


@router.get("/people/{user_id}/contacts")
async def contacts(user_id: uuid.UUID, _: User = Depends(requester), db: AsyncSession = Depends(get_session)):
    """The verified channels a link can go to (masked), and whether CTEM can send right now."""
    u = await _person(db, user_id)
    from api.core.idv_send import readiness
    ready = await readiness(db)
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
    from api.core.idv_send import send_link
    _, out = await send_link(db, str(user_id), body.channel, body.confirm_recent, str(me.id), me.username)
    return out
