"""Tag listing endpoint -- used by dashboard and device filters."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
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
    source: str | None = Query(None, max_length=64),
    prefix: list[str] | None = Query(None, max_length=10),
    in_use: bool = False,
    limit: int = Query(500, ge=1, le=2000),
):
    """Return all tags, or only those from a source / starting with any of the prefixes / on a device."""
    from sqlalchemy import exists, or_

    from api.models.device import DeviceTag
    stmt = select(Tag).order_by(Tag.name).limit(limit)
    if source:
        stmt = stmt.where(Tag.source == source)
    wanted = [p for p in (prefix or []) if p and len(p) <= 64]
    if wanted:
        esc = [p.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") for p in wanted]
        stmt = stmt.where(or_(*(Tag.name.like(f"{e}%", escape="\\") for e in esc)))
    if in_use:
        stmt = stmt.where(exists().where(DeviceTag.tag_id == Tag.id))
    result = await db.execute(stmt)
    tags = result.scalars().all()
    return {
        "tags": [
            {"id": str(t.id), "name": t.name, "source": t.source, "description": t.description}
            for t in tags
        ],
        "total": len(tags),
    }
