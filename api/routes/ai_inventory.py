"""The AI inventory (the AI page): every AI agent, app, browser extension and installed AI tool, for cyber and admin
(api/core/ai_inventory.py)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/ai", tags=["ai"])


@router.get("/inventory")
async def ai_inventory(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    from api.core.ai_inventory import inventory
    return await inventory(db)
