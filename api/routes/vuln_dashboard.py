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
_ROLES = {"admin", "cyber", "read_only"}   # the Vulnerabilities page's roles


def _viewer(u: User = Depends(get_current_user)) -> User:
    if not _ROLES.intersection(u.role_names):
        raise HTTPException(404)
    return u


@router.get("")
async def dashboard(u: User = Depends(_viewer), db: AsyncSession = Depends(get_session),
                    range: str = Query("90d", pattern="^(30d|90d|180d|365d|all)$"),  # noqa: A002
                    source: str | None = Query(None, max_length=64),
                    device_type: str | None = Query(None, max_length=32),
                    kind: str = Query("infra", pattern="^(infra|code|web)$")):
    if source and source not in vd.SOURCES:
        raise HTTPException(422, detail="unknown source")
    if device_type and device_type not in DeviceType.__members__:
        raise HTTPException(422, detail="unknown device type")
    if kind != "infra":
        device_type = None   # Code is all repositories and Web apps all sites; a host type left in a link matches nothing
    from api.auth.device_scope import device_scope
    scope = await device_scope(u, db)   # None for fleet-wide roles; otherwise only the devices this person may see
    out = await vd.cached(db, range, source or None, device_type or None, scope=scope, viewer=str(u.id), kind=kind)
    # Only sources this install uses: a configured integration, or open findings left from one
    used = set(await vd.configured_sources(db)) | {r["source"] for r in out.get("by_source") or []} | ({source} if source else set())
    from api.core.finding_domain import sources_by_domain
    srcs = [s for s in vd.SOURCES if s in used]
    return {**out, "scoped": scope is not None, "kind": kind,
            "filters": {"sources": srcs, "by_type": sources_by_domain(srcs), "device_types": list(DeviceType.__members__)}}
