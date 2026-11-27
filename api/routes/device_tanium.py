"""An asset's Tanium tab: last patch installed and by what, patch scan age, pending reboot, disk encryption, hardware,
and Tanium's vulnerability count. Anyone who can see the asset sees it; the users on it only admins and cyber."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])
STALE_PATCH_DAYS = 30


def patch_view(t: dict | None) -> dict | None:
    """The last patch date and how old it is, for the asset's info grid and the Tanium tab."""
    p = (t or {}).get("patch") or {}
    if not p.get("last_installed"):
        return None
    try:
        days = (datetime.now(timezone.utc).date() - datetime.strptime(p["last_installed"], "%Y-%m-%d").date()).days
    except ValueError:
        return None
    return {"date": p["last_installed"], "days": days, "source": p.get("last_source"), "title": p.get("last_title"),
            "stale": days > STALE_PATCH_DAYS}


@router.get("/{device_id}/tanium")
async def device_tanium(device_id: uuid.UUID, u: User = Depends(require_permission("devices", "read")),
                        db: AsyncSession = Depends(get_session)):
    from api.models.vuln import Finding, FindingStatus
    from api.routes.devices import _visible_device
    d = await _visible_device(device_id, u, db)
    t = d.tanium or {}
    if not t:
        return {"available": False}
    people = bool({"admin", "cyber"} & set(u.role_names))
    open_n, merged_n = (await db.execute(select(
        func.count().filter(Finding.status.in_((FindingStatus.open, FindingStatus.in_progress))),
        func.count().filter(Finding.status == FindingStatus.merged, Finding.closed_at.is_(None)))
        .where(Finding.device_id == d.id, Finding.source == "tanium"))).one()
    p = t.get("patch") or {}
    return {"available": True, "seen": t.get("seen"), "at": t.get("at"),
            "hardware": {k: t.get(k) for k in ("manufacturer", "model", "serial", "chassis", "virtual", "os", "platform")},
            "users": {"primary": t.get("primary_user"), "primary_email": t.get("primary_email"), "last": t.get("last_user")} if people else None,
            "patch": {**{k: p.get(k) for k in ("last_installed", "last_title", "last_source", "in_90_days", "scan_age_days",
                                                 "scan_note", "reboot_required", "last_reboot")},
                      "recent": p.get("recent") or [], "view": patch_view(t)},
            "encryption": {"encrypted": t.get("encrypted"), "bitlocker": t.get("bitlocker") or []} if "encrypted" in t else None,
            "vulns": {"open": open_n, "also_by_scanner": merged_n}}
