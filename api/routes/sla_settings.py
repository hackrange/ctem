"""Vulnerabilities > Change SLAs: days to fix by severity, for the whole install. Admins change them; anyone who
can read vulnerabilities can see them."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin, require_permission
from api.core import sla
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/sla", tags=["vulns"])
Days = Field(ge=sla.LIMITS[0], le=sla.LIMITS[1])


class SlaBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    critical: int = Days
    high: int = Days
    medium: int = Days
    low: int = Days


@router.get("")
async def get_sla(u: User = Depends(require_permission("vulns", "read")), db: AsyncSession = Depends(get_session)):
    return {"sla_days": await sla.load(db, force=True), "defaults": sla.DEFAULTS, "limits": list(sla.LIMITS),
            "can_edit": "admin" in u.role_names}


@router.put("")
async def set_sla(body: SlaBody, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from api.core.vuln_dashboard import forget_cached
    from api.routes.admin import _audit
    before = await sla.load(db, force=True)
    try:
        after = await sla.save(db, body.model_dump())
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    changes = ", ".join(f"{k} {before[k]} to {after[k]}" for k in after if before[k] != after[k]) or "no change"
    await _audit(admin, "sla.update", "setting", sla.KEY, f"SLA days: {changes}", db)
    await db.commit()
    await forget_cached()   # the dashboard's past-SLA numbers rebuild with the new days
    return {"ok": True, "sla_days": after}
