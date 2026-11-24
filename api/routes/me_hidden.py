"""Hide a dashboard finding or a Threat page alert for yourself only (api/core/hidden.py)."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.core import hidden
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/me/hidden", tags=["threat"])


class HideBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["watch", "alert"]
    id: str = Field(min_length=16, max_length=300)
    hidden: StrictBool


@router.get("")
async def my_hidden(u: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    have = await hidden.load(db, str(u.id))
    return {k: sorted(v) for k, v in have.items()}


@router.put("")
async def hide(body: HideBody, u: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    try:
        have = await hidden.set_hidden(db, str(u.id), body.kind, body.id, body.hidden)
    except ValueError as e:
        raise HTTPException(400, detail=str(e)) from None
    return {"ok": True, "hidden": body.hidden, "count": {k: len(v) for k, v in have.items()}}
