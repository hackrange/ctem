"""Settings > Integrations > Twilio > Send test text (admins): one fixed message, with no link, to the number given.

The number must be in international (E.164) form; spaces, dashes, dots and brackets are tidied away first, and
nothing else is guessed (no assumed country code). Five tests an hour per admin, each audited with the number
masked."""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core.db import get_session
from api.models.integration import IntegrationConfig, Vendor
from api.models.settings import AuditLog
from api.models.user import User

log = logging.getLogger("open-ctem.twilio")
router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])
E164 = re.compile(r"^\+[1-9]\d{7,14}$")
PER_HOUR = 5


def e164(raw: str) -> str | None:
    """+1 (555) 010-0199 -> +15550100199; None when it isn't a full international number."""
    v = re.sub(r"[\s\-.()]", "", raw or "")
    return v if E164.match(v) else None


class TestSms(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to: str = Field(min_length=8, max_length=24, pattern=r"^[0-9+\s\-.()]+$")


@router.post("/{integration_id}/sms-test")
async def send_test(integration_id: uuid.UUID, body: TestSms, u: User = Depends(require_admin),
                    db: AsyncSession = Depends(get_session)):
    from api.core.verified_contacts import mask_phone
    from api.integrations.base import get_connector
    from api.integrations.twilio import TwilioError
    cfg = await db.get(IntegrationConfig, str(integration_id))
    if cfg is None or cfg.vendor != Vendor.twilio:
        raise HTTPException(404)
    to = e164(body.to)
    if to is None:
        raise HTTPException(400, detail="Enter the number in international form: + then the country code and number, like +15550100199")
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)   # AuditLog.created_at is naive UTC
    sent = (await db.execute(select(func.count()).select_from(AuditLog).where(
        AuditLog.action == "integration.sms_test", AuditLog.actor_user_id == str(u.id), AuditLog.created_at > since))).scalar_one()
    if sent >= PER_HOUR:
        raise HTTPException(429, detail="That's five test texts this hour; try again later")
    ok, why = True, ""
    try:
        r = await get_connector("twilio", cfg.config or {}).send(to, f"open-ctem test message, sent by {u.username}. SMS delivery works.")
        why = r.get("status") or "sent"
    except TwilioError as e:
        ok, why = False, str(e)
        log.warning("Twilio test text failed: %s", e)
    db.add(AuditLog(actor_user_id=str(u.id), actor_username=u.username, action="integration.sms_test",
                    resource_type="integration", resource_id=str(cfg.id), detail=f"to {mask_phone(to)}: {why}"[:300]))
    await db.commit()
    if not ok:
        raise HTTPException(502, detail=f"{why}. Check the key's Messaging permissions and the sending number.")
    return {"ok": True, "to": mask_phone(to), "status": why}
