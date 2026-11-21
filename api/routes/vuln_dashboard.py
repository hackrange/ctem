"""Vulnerability dashboard API: fleet-wide posture and trends, for the roles that see every device."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.middleware import get_current_user
from api.core import vuln_dashboard as vd
from api.core.db import get_session
from api.models.device import DeviceType
from api.models.user import User

router = APIRouter(prefix="/api/v1/vuln-dashboard", tags=["vulns"])
_ROLES = {"admin", "cyber", "read_only"}   # the Vulnerabilities page's roles; the numbers cover every device


def _viewer(u: User = Depends(get_current_user)) -> User:
    if not _ROLES.intersection(u.role_names):
        raise HTTPException(404)
    return u


@router.get("")
async def dashboard(_: User = Depends(_viewer), db: AsyncSession = Depends(get_session),
                    range: str = Query("90d", pattern="^(30d|90d|180d|365d|all)$"),  # noqa: A002
                    source: str | None = Query(None, max_length=64),
                    device_type: str | None = Query(None, max_length=32)):
    if source and source not in vd.SOURCES:
        raise HTTPException(422, detail="unknown source")
    if device_type and device_type not in DeviceType.__members__:
        raise HTTPException(422, detail="unknown device type")
    out = await vd.cached(db, range, source or None, device_type or None)
    return {**out, "filters": {"sources": list(vd.SOURCES), "device_types": list(DeviceType.__members__)}}
