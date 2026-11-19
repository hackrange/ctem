"""Tag listing endpoint -- used by dashboard and device filters."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.middleware import get_current_user
from api.core.db import get_session
from api.models.tag import Tag
from api.models.user import User

router = APIRouter(prefix="/api/v1/tags", tags=["tags"])


@router.get("")
async def list_tags(
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
    source: str | None = None,
    limit: int = 500,
):
    """Return all tags (or filtered by source). Any authenticated user can read."""
    stmt = select(Tag).order_by(Tag.name).limit(limit)
    if source:
        stmt = stmt.where(Tag.source == source)
    result = await db.execute(stmt)
    tags = result.scalars().all()
    return {
        "tags": [
            {"id": str(t.id), "name": t.name, "source": t.source, "description": t.description}
            for t in tags
        ],
        "total": len(tags),
    }
