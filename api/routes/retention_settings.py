"""Admin > Data retention: when a host counts as gone and loses its findings (api/core/stale_hosts.py), and how long
remediated findings are kept (api/core/finding_history.py). Admins only; every change is in the Audit Log."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core import retention
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/retention", tags=["admin"])


class RetentionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool
    stale_host_days: StrictInt = Field(ge=retention.LIMITS["stale_host_days"][0], le=retention.LIMITS["stale_host_days"][1])
    probe_within_days: StrictInt = Field(ge=retention.LIMITS["probe_within_days"][0], le=retention.LIMITS["probe_within_days"][1])
    remediated_days: StrictInt = Field(90, ge=retention.LIMITS["remediated_days"][0], le=retention.LIMITS["remediated_days"][1])
    ip_history_days: StrictInt = Field(730, ge=retention.LIMITS["ip_history_days"][0], le=retention.LIMITS["ip_history_days"][1])


@router.get("")
async def get_retention(admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import exists, func, select

    from api.core.stale_hosts import silent_for, unseen
    from api.models.device import Device
    from api.models.vuln import Finding
    cfg = await retention.load(db)
    cut = datetime.now(timezone.utc) - timedelta(days=cfg["stale_host_days"])
    has = exists(select(Finding.id).where(Finding.device_id == Device.id))
    confirmed = silent_for(cut, datetime.now(timezone.utc) - timedelta(days=cfg["probe_within_days"]))
    count = lambda *w: select(func.count()).select_from(Device).where(*w)   # noqa: E731
    from api.models.vuln import FindingStatus
    fixed_cut = datetime.now(timezone.utc) - timedelta(days=cfg["remediated_days"])
    from api.models.ip_history import IpSighting
    oldest = (await db.execute(select(func.min(IpSighting.first_seen)))).scalar_one_or_none()
    return {**cfg, "limits": retention.LIMITS, "defaults": retention.defaults(),
            "ip_history": {"spans": (await db.execute(select(func.count()).select_from(IpSighting))).scalar_one(),
                           "oldest": oldest.isoformat() if oldest else None},
            "remediated_due": (await db.execute(select(func.count()).select_from(Finding).where(
                Finding.status == FindingStatus.remediated, Finding.last_seen < fixed_cut))).scalar_one(),
            "now": {"unseen_with_findings": (await db.execute(count(unseen(cut), has))).scalar_one(),
                    "confirmed_offline": (await db.execute(count(unseen(cut), has, confirmed))).scalar_one()}}


@router.put("")
async def set_retention(body: RetentionBody, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from api.routes.admin import _audit
    before = await retention.load(db)
    try:
        after = await retention.save(db, body.model_dump())
    except ValueError as e:
        raise HTTPException(400, detail=str(e)) from None
    changes = ", ".join(f"{k} {before[k]} to {after[k]}" for k in after if before.get(k) != after[k]) or "no change"
    await _audit(admin, "retention.update", "setting", retention.KEY, f"Data retention: {changes}", db)
    await db.commit()
    return {"ok": True, **after}
