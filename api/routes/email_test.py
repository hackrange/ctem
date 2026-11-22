"""Settings > Integrations > Email > Send test email (admins): one short message to the address given."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core.db import get_session
from api.models.integration import IntegrationConfig, Vendor
from api.models.settings import AuditLog
from api.models.user import User

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


class TestMail(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to: str = Field(max_length=254, pattern=r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


@router.post("/{integration_id}/email-test")
async def send_test(integration_id: uuid.UUID, body: TestMail, u: User = Depends(require_admin),
                    db: AsyncSession = Depends(get_session)):
    from api.core.email import EmailClient, EmailConfig
    cfg = await db.get(IntegrationConfig, str(integration_id))
    if cfg is None or cfg.vendor != Vendor.email:
        raise HTTPException(404)
    ok = await EmailClient(config=EmailConfig.from_integration(cfg.config or {})).send(
        to=str(body.to), subject="open-ctem test email",
        body_text=f"This is a test message from open-ctem, sent by {u.username}. Email delivery works.")
    db.add(AuditLog(actor_user_id=str(u.id), actor_username=u.username, action="integration.email_test",
                    resource_type="integration", resource_id=str(cfg.id), detail=f"to {body.to}: {'sent' if ok else 'failed'}"[:300]))
    await db.commit()
    if not ok:
        raise HTTPException(502, detail="The message wasn't accepted. Check the settings and the server log.")
    return {"ok": True}
