"""Ticket helpers for the UI: which delivery methods exist, and copy-ready text for a manual email."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.config import get_settings
from api.core.db import get_session
from api.models.integration import IntegrationConfig, Vendor
from api.models.user import User
from api.routes.tickets import _build_plain_text, _build_title, _get_authorized_finding

router = APIRouter(prefix="/api/v1/vulns/findings", tags=["tickets"])


@router.get("/ticket-options")
async def ticket_options(
    _: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
):
    """Only offer delivery methods that are actually set up; copy-to-clipboard always works."""
    snow = (await db.execute(select(IntegrationConfig.id).where(
        IntegrationConfig.vendor == Vendor.servicenow, IntegrationConfig.is_enabled.is_(True)).limit(1))).first()
    s = get_settings()
    email = bool(s.servicenow_inbound_email) and s.email_mode != "disabled"
    return {"api": snow is not None, "email": email, "copy": True}


@router.get("/{finding_id}/ticket/preview")
async def ticket_preview(
    finding_id: uuid.UUID,
    current_user: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
    notes: str | None = Query(None, max_length=2000),
    assignment_group: str | None = Query(None, max_length=128),
):
    """Subject and plain-text body for pasting into a manual email. Same device access rule as creating one."""
    finding = await _get_authorized_finding(finding_id, current_user, db)
    body = _build_plain_text(finding, finding.vuln, finding.device, current_user, notes)
    if assignment_group:
        body = f"Assignment group: {assignment_group.strip()}\n\n{body}"
    return {"subject": _build_title(finding, finding.vuln, finding.device), "body": body}
