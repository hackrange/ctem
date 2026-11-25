"""Admin > Risk model: the risk-based finding score's weights and reachability ladder (api/scoring/risk_model.py),
on or off, and reset to defaults. Admins only; every change is audited and rescores the whole fleet."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, StrictFloat
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core.db import get_session
from api.models.settings import AppSetting, AuditLog
from api.models.user import User
from api.scoring import risk_model

router = APIRouter(prefix="/api/v1/admin/risk-model", tags=["admin"])
Unit = Field(ge=0.0, le=1.0)


class Weights(BaseModel):
    model_config = ConfigDict(extra="forbid")
    likelihood: StrictFloat = Unit
    reachability: StrictFloat = Unit
    impact: StrictFloat = Unit


class Likelihood(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kev: StrictFloat = Unit
    pentest_proved: StrictFloat = Unit
    threat_actors: StrictFloat = Unit
    epss_full: StrictFloat = Field(ge=0.01, le=1.0)
    epss_curve: StrictFloat = Field(ge=0.05, le=1.0)
    no_epss_cvss: StrictFloat = Unit


class Reachability(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pentest_proved: StrictFloat = Unit
    internet_listening: StrictFloat = Unit
    listening: StrictFloat = Unit
    client_workstation: StrictFloat = Unit
    client_server: StrictFloat = Unit
    adjacent: StrictFloat = Unit
    local: StrictFloat = Unit
    physical: StrictFloat = Unit
    unknown: StrictFloat = Unit
    not_reachable: StrictFloat = Unit
    internet_unknown: StrictFloat = Unit


class Impact(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity: StrictFloat = Unit
    criticality: StrictFloat = Unit


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    weights: Weights
    likelihood: Likelihood
    reachability: Reachability
    impact: Impact


def _view(cfg: dict) -> dict:
    return {"settings": cfg, "defaults": risk_model.DEFAULTS, "is_default": cfg == risk_model.merged(None)}


@router.get("")
async def get_model(_: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    risk_model.forget()
    return _view(await risk_model.load(db))


async def _changed(db: AsyncSession, admin: User, detail: str) -> dict:
    db.add(AuditLog(actor_user_id=str(admin.id), actor_username=admin.username, action="risk_model.changed",
                    resource_type="setting", resource_id=risk_model.KEY, detail=detail[:1000]))
    await db.commit()
    risk_model.forget()
    from api.core.tasks import post_sync_pipeline
    post_sync_pipeline.delay(None)   # every score is worked out again with the new model
    return _view(await risk_model.load(db))


@router.put("")
async def put_model(body: Settings, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from fastapi import HTTPException
    cfg = risk_model.merged(body.model_dump())
    if sum(body.weights.model_dump().values()) <= 0 or sum(body.impact.model_dump().values()) <= 0:
        raise HTTPException(400, detail="At least one weight, and one impact part, must be above 0")
    before = await risk_model.load(db)
    changes = [f"enabled {before['enabled']}->{cfg['enabled']}"] if before["enabled"] != cfg["enabled"] else []
    changes += [f"{g}.{k} {before[g][k]}->{v}" for g in risk_model.LIMITS for k, v in cfg[g].items() if before[g][k] != v]
    row = (await db.execute(select(AppSetting).where(AppSetting.key == risk_model.KEY))).scalar_one_or_none()
    if row is None:
        db.add(AppSetting(key=risk_model.KEY, value=json.dumps(cfg), is_sensitive=False))
    else:
        row.value = json.dumps(cfg)
    return await _changed(db, admin, "; ".join(changes) or "saved, no change")


@router.post("/reset")
async def reset_model(admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    await db.execute(delete(AppSetting).where(AppSetting.key == risk_model.KEY))
    return await _changed(db, admin, "reset to defaults")
