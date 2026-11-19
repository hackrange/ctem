"""Create ServiceNow tickets from findings -- via API or inbound email."""
from __future__ import annotations

import html
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.middleware import get_current_user
from api.auth.rbac import can_access_device
from api.core.db import get_session
from api.models.user import User
from api.models.vuln import Finding, TicketRef, Vulnerability

router = APIRouter(prefix="/api/v1/vulns/findings", tags=["tickets"])


@router.post("/{finding_id}/ticket", status_code=201)
async def create_ticket(
    finding_id: uuid.UUID,
    body: CreateTicketRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    """
    Create a ServiceNow ticket for a finding.
    Method 'api': uses the configured ServiceNow integration directly.
    Method 'email': sends a formatted email to the ServiceNow inbound address.
    Either way, the ticket reference is recorded on the finding.
    """
    finding = await _get_authorized_finding(finding_id, current_user, db)
    vuln = finding.vuln
    device = finding.device

    severity = _score_to_severity(finding.composite_score)
    title = f"[open-ctem] {vuln.cve_id or vuln.title} on {device.hostname}"
    description = _build_description(finding, vuln, device, body.notes)

    if body.method == "api":
        ticket_info = await _create_via_api(title, description, severity, device, vuln, body, db)
    else:
        ticket_info = await _create_via_email(title, description, severity, device, vuln, body, db)

    # Record the ticket reference so it shows up on the finding
    ref = TicketRef(
        finding_id=finding.id,
        ticket_number=ticket_info.get("number", ""),
        ticket_url=ticket_info.get("url"),
        ticket_system="servicenow",
        method=body.method,
        created_by=current_user.id,
    )
    db.add(ref)
    await db.commit()

    return {"created": True, **ticket_info}


@router.get("/{finding_id}/tickets")
async def list_tickets(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_session),
):
    """List all ticket references for a finding."""
    finding = await _get_authorized_finding(finding_id, current_user, db)
    result = await db.execute(
        select(TicketRef).where(TicketRef.finding_id == finding.id).order_by(TicketRef.created_at.desc())
    )
    refs = result.scalars().all()
    return {
        "tickets": [
            {
                "id": str(r.id),
                "ticket_number": r.ticket_number,
                "ticket_url": r.ticket_url,
                "method": r.method,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in refs
        ]
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _get_authorized_finding(
    finding_id: uuid.UUID, user: User, db: AsyncSession
) -> Finding:
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.vuln), selectinload(Finding.device))
        .where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(404)
    if not await can_access_device(user, finding.device, db):
        raise HTTPException(404)  # 404 not 403 -- no enumeration oracle
    return finding


async def _create_via_api(
    title: str, description: str, severity: str,
    device, vuln, body: "CreateTicketRequest", db: AsyncSession,
) -> dict:
    from api.models.integration import IntegrationConfig, Vendor
    from api.integrations.servicenow import ServiceNowConnector

    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.vendor == Vendor.servicenow,
            IntegrationConfig.is_enabled == True,  # noqa: E712
        )
    )
    config_row = result.scalar_one_or_none()
    if config_row is None:
        raise HTTPException(422, detail="No active ServiceNow integration configured")

    connector = ServiceNowConnector(config_row.id, config_row.config or {})
    return await connector.create_ticket(
        title=title,
        description=description,
        severity=severity,
        affected_device=device.hostname,
        cve_id=vuln.cve_id,
        assignment_group=body.assignment_group,
    )


async def _create_via_email(
    title: str, description: str, severity: str,
    device, vuln, body: "CreateTicketRequest", db: AsyncSession,
) -> dict:
    from api.core.config import get_settings
    from api.core.email import get_email_client

    settings = get_settings()
    snow_email = getattr(settings, "servicenow_inbound_email", None)
    if not snow_email:
        raise HTTPException(422, detail="SERVICENOW_INBOUND_EMAIL not configured")

    client = get_email_client()
    html = _ticket_email_html(title, description, severity, device.hostname, vuln.cve_id)
    sent = await client.send(
        to=snow_email,
        subject=title,
        body_text=description,
        body_html=html,
    )
    if not sent:
        raise HTTPException(503, detail="Email delivery failed -- check email configuration")

    return {
        "number": "pending",  # ServiceNow assigns the number via inbound email action
        "url": None,
        "sent_to": snow_email,
        "note": "Ticket will be created by ServiceNow inbound email action",
    }


def _build_description(finding, vuln, device, extra_notes: str | None) -> str:
    lines = [
        f"Finding: {vuln.cve_id or vuln.title}",
        f"Device: {device.hostname}",
        f"Risk Score: {finding.composite_score or 'N/A'} (Grade {finding.risk_grade or '?'})",
        f"CVSS Base: {vuln.cvss_base or 'N/A'}",
        f"EPSS: {vuln.epss_score or 'N/A'}",
        f"KEV: {'Yes' if vuln.is_kev else 'No'}",
        f"Reachable: {finding.is_reachable}",
        f"Status: {finding.status}",
        "",
        f"Description: {vuln.description or 'See CVE database for details.'}",
        "",
        "Source: open-ctem",
    ]
    if extra_notes:
        lines += ["", f"Additional notes: {extra_notes}"]
    return "\n".join(lines)


def _ticket_email_html(title: str, body: str, severity: str, host: str, cve: str | None) -> str:
    # html.escape() all untrusted values -- vuln.description is scanner-sourced
    sev_color = {"critical": "#cc0000", "high": "#e65c00", "medium": "#e6a817", "low": "#2e7d32"}.get(
        severity, "#555"
    )
    t = html.escape(title)
    h = html.escape(host)
    c = html.escape(cve or "N/A")
    b = html.escape(body).replace("\n", "<br>")
    return f"""<html><body style="font-family:Arial,sans-serif;font-size:14px;">
<h2 style="color:{sev_color};">[{severity.upper()}] {t}</h2>
<table style="border-collapse:collapse;width:100%;max-width:600px;">
<tr><td style="padding:4px 8px;font-weight:bold;">Host</td><td style="padding:4px 8px;">{h}</td></tr>
<tr><td style="padding:4px 8px;font-weight:bold;">CVE</td><td style="padding:4px 8px;">{c}</td></tr>
<tr><td style="padding:4px 8px;font-weight:bold;">Severity</td><td style="padding:4px 8px;color:{sev_color};">{severity.upper()}</td></tr>
</table>
<hr>
<pre style="background:#f5f5f5;padding:12px;border-radius:4px;">{b}</pre>
<p style="color:#888;font-size:12px;">Created by open-ctem</p>
</body></html>"""


def _score_to_severity(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


class CreateTicketRequest(BaseModel):
    method: Literal["api", "email"] = "api"
    assignment_group: str | None = None
    notes: str | None = None
    priority_override: Literal["critical", "high", "medium", "low"] | None = None
