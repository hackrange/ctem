"""Admin exports: the full audit log as a CSV download."""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core.csv_export import csv_paged_response
from api.core.db import get_session
from api.models.settings import AuditLog
from api.models.user import User

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])
log = logging.getLogger("open-ctem.admin")

_HEADER = ["Time (UTC)", "Actor", "Action", "Resource type", "Resource ID", "Detail", "IP address"]


def _day(raw: str | None, field: str) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        raise HTTPException(400, detail=f"{field} must be a date like 2026-11-01") from None


@router.get("/audit/export")
async def export_audit(
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_session),
    since: str | None = Query(None, max_length=32),
    until: str | None = Query(None, max_length=32),
):
    """Every audit entry (newest first), optionally between two dates. Sent as an attachment."""
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    if (start := _day(since, "since")) is not None:
        stmt = stmt.where(AuditLog.created_at >= start)
    if (end := _day(until, "until")) is not None:
        stmt = stmt.where(AuditLog.created_at <= end)

    async def fetch(offset: int, limit: int) -> list[list]:
        rows = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
        out = [[r.created_at.isoformat(timespec="seconds"), r.actor_username, r.action, r.resource_type,
                r.resource_id, r.detail, r.ip_address] for r in rows]
        db.expunge_all()
        return out

    resp = await csv_paged_response("audit-log", _HEADER, fetch)
    # Exporting the audit trail is itself an audited action
    db.add(AuditLog(actor_user_id=str(admin.id), actor_username=admin.username, action="audit.export",
                    resource_type="audit", resource_id=None, detail=f"exported {resp.headers['X-Export-Rows']} rows"))
    await db.commit()
    log.info("audit export by %s: %s rows", admin.username, resp.headers["X-Export-Rows"])
    return resp
