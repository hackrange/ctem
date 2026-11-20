"""Risk register edits that go back to FairTPRM: status, review date and treatment plan only."""
from __future__ import annotations

import logging
import re
import uuid
from datetime import date, datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.models.grc import GrcRisk
from api.models.user import User

router = APIRouter(prefix="/api/v1/grc", tags=["grc"])
log = logging.getLogger("open-ctem.grc")
_NOT_NAME = re.compile(r"[^\w .@,()'-]", re.UNICODE)

# Refusals come back as 200 + saved:false, because the load balancer swaps 4xx bodies
REASONS = {
    "not_connected": "FairTPRM isn't connected. Set it up under Settings > Integrations.",
    "read_only": "FairTPRM's token for CTEM is read-only. Give it read_write scope in FairTPRM to save risk edits.",
    "not_found": "FairTPRM didn't accept it: the risk is gone, or FairTPRM needs the update with risk review edits.",
    "rejected": "FairTPRM rejected the change.",
    "unreachable": "Couldn't reach FairTPRM. Nothing was changed; try again.",
}


class RiskReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["identified", "assessing", "treating", "monitoring", "closed"] | None = None
    review_date: date | None = None
    treatment_plan: str | None = Field(None, max_length=10000)
    clear_review_date: bool = False


def acting_user(u: User) -> str:
    """jdoe (Doe, Jane), in the characters FairTPRM accepts."""
    name = getattr(u, "display_name", None)
    label = f"{u.username} ({name})" if name and name != u.username else u.username
    return _NOT_NAME.sub("", label).strip()[:128] or "ctem-user"


@router.put("/risks/{risk_id}/review")
async def review_risk(
    risk_id: uuid.UUID,
    body: RiskReview,
    current_user: User = Depends(require_permission("grc", "write")),
    db: AsyncSession = Depends(get_session),
):
    from api.integrations.fairtprm import FairTPRMConnector, FairTPRMError
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.settings import AuditLog

    risk = (await db.execute(select(GrcRisk).where(GrcRisk.id == str(risk_id)))).scalar_one_or_none()
    if risk is None or risk.source != "fairtprm" or not risk.external_id.isdigit():
        raise HTTPException(404, detail="Risk not found")
    fields: dict = {}
    if body.status is not None:
        fields["status"] = body.status
    if body.review_date is not None or body.clear_review_date:
        fields["review_date"] = None if body.clear_review_date else body.review_date.isoformat()
    if body.treatment_plan is not None:
        fields["treatment_plan"] = body.treatment_plan.strip()
    if not fields:
        raise HTTPException(422, detail="Nothing to change")

    cfg = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.vendor == Vendor.fairtprm,
                                                            IntegrationConfig.is_enabled.is_(True)))).scalars().first()
    if cfg is None:
        return {"saved": False, "reason": "not_connected", "message": REASONS["not_connected"]}
    try:
        data = await FairTPRMConnector(cfg.config).review_risk(risk.external_id, fields, acting_user(current_user))
    except FairTPRMError as exc:
        reason = {403: "read_only", 401: "read_only", 404: "not_found"}.get(exc.status, "rejected")
        db.add(AuditLog(actor_user_id=str(current_user.id), actor_username=current_user.username,
                        action="grc.risk_review_refused", resource_type="grc_risk", resource_id=str(risk.id),
                        detail=f"{risk.risk_ref}: {reason}"))
        await db.commit()
        return {"saved": False, "reason": reason, "message": REASONS[reason]}
    except Exception:  # transport trouble; FairTPRM wasn't changed as far as we know
        log.exception("FairTPRM risk review for %s failed", risk.risk_ref)
        return {"saved": False, "reason": "unreachable", "message": REASONS["unreachable"]}

    # Mirror what FairTPRM now says, so the page doesn't wait for the next sync
    from api.integrations.fairtprm_grc import _date, _text
    risk.status = _text(data.get("status"), 16)
    risk.review_date = _date(data.get("review_date"))
    risk.treatment_plan = _text(data.get("treatment_plan"), 10000)
    risk.synced_at = datetime.now(timezone.utc)
    db.add(AuditLog(actor_user_id=str(current_user.id), actor_username=current_user.username,
                    action="grc.risk_review", resource_type="grc_risk", resource_id=str(risk.id),
                    detail=f"{risk.risk_ref}: {', '.join(sorted(fields))} sent to FairTPRM"))
    await db.commit()
    return {"saved": True, "risk": {"id": str(risk.id), "status": risk.status,
                                    "review_date": risk.review_date.isoformat() if risk.review_date else None,
                                    "treatment_plan": risk.treatment_plan}}
