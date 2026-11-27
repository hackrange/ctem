"""CrowdStrike Spotlight on or off from the integration's card (admins). Spotlight is pulled by the shipper's
CrowdStrike source, so this is that source's own Spotlight setting: one switch, shown and changed in both places,
saved the way the Shippers page saves it (a new config version the box picks up on its next check-in). Audited."""
from __future__ import annotations

import copy
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, StrictBool
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core.cs_spotlight import owner
from api.core.db import get_session
from api.models.settings import AuditLog
from api.models.user import User

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


class SpotlightBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool


@router.put("/{integration_id}/spotlight")
async def set_spotlight(integration_id: uuid.UUID, body: SpotlightBody, u: User = Depends(require_admin),
                        db: AsyncSession = Depends(get_session)):
    from api.collector import service
    prof = await owner(db, str(integration_id))
    if prof is None:
        raise HTTPException(404)   # only a shipper-fed CrowdStrike integration has Spotlight
    modules = copy.deepcopy(prof.modules or {})
    settings = {**(modules["crowdstrike"].get("settings") or {}), "spotlight": "on" if body.enabled else "off"}
    modules["crowdstrike"] = {**modules["crowdstrike"], "settings": settings}
    await service.save_profile_modules(db, prof, service.clean_modules(modules, prof.modules))
    db.add(AuditLog(actor_user_id=str(u.id), actor_username=u.username, action="integration.spotlight",
                    resource_type="integration", resource_id=str(integration_id),
                    detail=f"CrowdStrike Spotlight turned {'on' if body.enabled else 'off'} on shipper {prof.name}"[:300]))
    await db.commit()
    return {"spotlight": body.enabled}
