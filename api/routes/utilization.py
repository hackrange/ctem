"""Admin > Utilization: CPU, memory and disk now and over time, and where the storage goes. Admin only."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core import utilization as ut
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/admin/utilization", tags=["admin"])


@router.get("/live")
async def live(_: User = Depends(require_admin)):
    return await asyncio.to_thread(ut.sample, 0.5)


@router.get("/storage")
async def storage(_: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    return await ut.storage(db)


@router.get("/history")
async def history(_: User = Depends(require_admin), db: AsyncSession = Depends(get_session),
                  range: str = Query("24h", pattern="^(1h|24h|7d|30d|365d)$")):  # noqa: A002
    return await ut.history(db, range)
