"""Create ServiceNow tickets from findings -- via API or inbound email."""
from __future__ import annotations

import html as html_lib
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.rbac import can_access_device, require_permission
from api.core.db import get_session
from api.models.user import User
from api.models.vuln import Finding, TicketRef, Vulnerability

router = APIRouter(prefix="/api/v1/vulns/findings", tags=["tickets"])


@router.post("/{finding_id}/ticket", status_code=201)
async def create_ticket(
    finding_id: uuid.UUID,
    body: CreateTicketRequest,
    current_user: User = Depends(require_permission("findings", "write")),
    db: AsyncSession = Depends(get_session),
):
    finding = await _get_authorized_finding(finding_id, current_user, db)
    vuln    = finding.vuln
    device  = finding.device

    severity = _score_to_severity(finding.composite_score)
    effective_severity = body.priority_override or severity

    title = _build_title(finding, vuln, device)
    plain = _build_plain_text(finding, vuln, device, current_user, body.notes)

    if body.method == "api":
        ticket_info = await _create_via_api(title, plain, effective_severity, finding, vuln, device, body, db)
    else:
        ticket_info = await _create_via_email(title, plain, effective_severity, finding, vuln, device, body, db)

    db.add(TicketRef(
        finding_id=finding.id,
        ticket_number=ticket_info.get("number", ""),
        ticket_url=ticket_info.get("url"),
        ticket_system="servicenow",
        method=body.method,
        created_by=current_user.id,
    ))
    await db.commit()

    return {"created": True, **ticket_info}


@router.get("/{finding_id}/tickets")
async def list_tickets(
    finding_id: uuid.UUID,
    current_user: User = Depends(require_permission("vulns", "read")),
    db: AsyncSession = Depends(get_session),
):
    finding = await _get_authorized_finding(finding_id, current_user, db)
    result  = await db.execute(
        select(TicketRef)
        .where(TicketRef.finding_id == finding.id)
        .order_by(TicketRef.created_at.desc())
    )
    return {
        "tickets": [
            {
                "id":            str(r.id),
                "ticket_number": r.ticket_number,
                "ticket_url":    r.ticket_url,
                "method":        r.method,
                "created_at":    r.created_at.isoformat() if r.created_at else None,
            }
            for r in result.scalars().all()
        ]
    }


# ── Authorization ─────────────────────────────────────────────────────────────

async def _get_authorized_finding(
    finding_id: uuid.UUID, user: User, db: AsyncSession
) -> Finding:
    from api.models.device import Device
    result = await db.execute(
        select(Finding)
        .options(
            selectinload(Finding.vuln),
            selectinload(Finding.device).selectinload(Device.owner),
            selectinload(Finding.device).selectinload(Device.tags),
        )
        .where(Finding.id == str(finding_id))
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(404)
    if not await can_access_device(user, finding.device, db):
        raise HTTPException(404)   # 404 not 403 -- no enumeration oracle
    return finding


# ── Ticket delivery ───────────────────────────────────────────────────────────

async def _create_via_api(
    title: str, description: str, severity: str,
    finding, vuln, device, body: "CreateTicketRequest", db: AsyncSession,
) -> dict:
    from api.integrations.servicenow import ServiceNowConnector
    from api.models.integration import IntegrationConfig, Vendor

    result = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.vendor == Vendor.servicenow,
            IntegrationConfig.is_enabled.is_(True),
        )
    )
    cfg = result.scalar_one_or_none()
    if cfg is None:
        raise HTTPException(422, detail="No active ServiceNow integration configured")

    connector = ServiceNowConnector(cfg.config or {})
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
    finding, vuln, device, body: "CreateTicketRequest", db: AsyncSession,
) -> dict:
    from api.core.config import get_settings
    from api.core.email import get_email_client

    settings   = get_settings()
    snow_email = getattr(settings, "servicenow_inbound_email", None)
    if not snow_email:
        raise HTTPException(422, detail="SERVICENOW_INBOUND_EMAIL not configured")

    client = get_email_client()
    sent   = await client.send(
        to=snow_email,
        subject=title,
        body_text=description,
        body_html=_build_html_email(finding, vuln, device, severity),
    )
    if not sent:
        raise HTTPException(503, detail="Email delivery failed -- check email configuration")

    return {
        "number":   "pending",
        "url":      None,
        "sent_to":  snow_email,
        "note":     "Ticket will be created by the ServiceNow inbound email action",
    }


# ── Content builders ──────────────────────────────────────────────────────────

def _build_title(finding, vuln, device) -> str:
    kev_flag = " [KEV]" if vuln.is_kev else ""
    grade    = finding.risk_grade or "?"
    cve_or_title = vuln.cve_id or vuln.title[:60]
    return f"[open-ctem] {cve_or_title} on {device.hostname} -- Grade {grade}{kev_flag}"


def _build_plain_text(finding, vuln, device, requestor: User, notes: str | None) -> str:
    now    = datetime.now(timezone.utc)
    age    = _age(finding.first_detected, now)
    owner  = _owner_line(device)
    sev    = _score_to_severity(finding.composite_score)
    kev    = "YES -- CISA Known Exploited Vulnerability (patch immediately)" if vuln.is_kev else "No"
    epss   = f"{vuln.epss_score * 100:.1f}% probability of exploitation" if vuln.epss_score else "N/A"
    reach  = _reachability_line(finding)
    exploit_line = _exploit_line(vuln)
    remediation  = _remediation_steps(vuln, device)

    lines = [
        "=" * 70,
        "  OPEN-CTEM SECURITY INCIDENT",
        "=" * 70,
        "",
        f"  PRIORITY : {sev.upper()}  (Score: {finding.composite_score or 'N/A'}/100  Grade: {finding.risk_grade or '?'})",
        f"  CREATED  : {now.strftime('%Y-%m-%d %H:%M UTC')}  by {requestor.username}",
        f"  OPEN FOR : {age}",
        "",
        "── VULNERABILITY " + "─" * 54,
        f"  CVE         : {vuln.cve_id or 'N/A'}",
        f"  Title       : {vuln.title}",
        f"  CVSS Base   : {vuln.cvss_base or 'N/A'}  Vector: {vuln.cvss_vector or 'N/A'}",
        f"  EPSS        : {epss}",
        f"  KEV         : {kev}",
        f"  Exploit     : {exploit_line}",
        f"  Attack Vec  : {vuln.attack_vector or 'N/A'}",
        "",
        "  Description:",
        f"  {vuln.description or 'No description available. See NVD for details.'}",
        "",
        "── AFFECTED SYSTEM " + "─" * 51,
        f"  Hostname    : {device.hostname}",
        f"  FQDN        : {device.fqdn or 'N/A'}",
        f"  Device Type : {device.device_type.value if hasattr(device.device_type, 'value') else device.device_type}",
        f"  OS          : {_os_line(device)}",
        f"  AD Joined   : {'Yes -- ' + device.ad_dn if device.ad_joined and device.ad_dn else ('Yes' if device.ad_joined else 'No')}",
        f"  Internet    : {'EXPOSED (high risk)' if device.is_internet_exposed else 'Internal only'}",
        f"  EDR         : {_edr_line(device)}",
        f"  Source      : {device.source or 'N/A'}",
        "",
        "── WHO / CONTACTS " + "─" * 52,
        f"  Device Owner: {owner}",
        f"  Last User   : {device.last_login_user or 'Unknown'}",
        f"  AD Last Logon: {_dt(device.ad_last_logon)}",
        "",
        "── RISK CONTEXT " + "─" * 54,
        f"  Risk Score  : {finding.composite_score or 'N/A'}/100  Grade: {finding.risk_grade or '?'}",
        f"  Reachable   : {reach}",
        f"  Attack Chain: {'YES -- part of a detected multi-step exploit chain' if finding.in_attack_chain else 'No'}",
        f"  First Seen  : {_dt(finding.first_detected)}  ({age} ago)",
        f"  Last Seen   : {_dt(finding.last_seen)}",
        f"  Status      : {finding.status.value if hasattr(finding.status, 'value') else finding.status}",
        "",
        "── REMEDIATION STEPS " + "─" * 49,
    ]
    for i, step in enumerate(remediation, 1):
        lines.append(f"  {i}. {step}")

    if notes:
        lines += [
            "",
            "── NOTES FROM REQUESTOR " + "─" * 46,
            f"  {notes}",
        ]

    lines += [
        "",
        "── TICKET DETAILS " + "─" * 52,
        f"  Finding ID  : {finding.id}",
        f"  Requested by: {requestor.username} (open-ctem)",
        "=" * 70,
        "  This ticket was created automatically by open-ctem.",
        "  Update the finding status in open-ctem once remediated.",
        "=" * 70,
    ]
    return "\n".join(lines)


def _build_html_email(finding, vuln, device, severity: str) -> str:
    """HTML body for the ServiceNow inbound email action."""
    sev_color = {"critical": "#cc0000", "high": "#cc5500", "medium": "#cc8800", "low": "#336600"}.get(severity, "#555")
    kev       = "YES" if vuln.is_kev else "No"
    kev_color = "#cc0000" if vuln.is_kev else "inherit"
    epss      = f"{vuln.epss_score * 100:.1f}%" if vuln.epss_score else "N/A"
    reach_txt = _reachability_line(finding)
    owner_txt = _owner_line(device)
    age_txt   = _age(finding.first_detected, datetime.now(timezone.utc))
    score_txt = f"{finding.composite_score or 'N/A'}/100 (Grade {finding.risk_grade or '?'})"
    remediation = _remediation_steps(vuln, device)

    def esc(v: object) -> str:
        return html_lib.escape(str(v or "N/A"))

    rows_vuln = [
        ("CVE",           esc(vuln.cve_id or "N/A")),
        ("Title",         esc(vuln.title)),
        ("CVSS Base",     esc(f"{vuln.cvss_base or 'N/A'}  ({vuln.cvss_vector or 'N/A'})")),
        ("EPSS",          esc(epss)),
        ("KEV",           f'<span style="color:{kev_color};font-weight:bold;">{esc(kev)}</span>'),
        ("Exploit",       esc(_exploit_line(vuln))),
        ("Attack Vector", esc(vuln.attack_vector or "N/A")),
    ]
    rows_device = [
        ("Hostname",      esc(device.hostname)),
        ("FQDN",          esc(device.fqdn or "N/A")),
        ("Device Type",   esc(device.device_type.value if hasattr(device.device_type, "value") else device.device_type)),
        ("OS",            esc(_os_line(device))),
        ("Internet",      esc("EXPOSED" if device.is_internet_exposed else "Internal only")),
        ("EDR",           esc(_edr_line(device))),
        ("AD Joined",     esc("Yes" if device.ad_joined else "No")),
    ]
    rows_risk = [
        ("Risk Score",    esc(score_txt)),
        ("Reachable",     esc(reach_txt)),
        ("Attack Chain",  esc("YES" if finding.in_attack_chain else "No")),
        ("First Seen",    esc(_dt(finding.first_detected))),
        ("Open For",      esc(age_txt)),
        ("Status",        esc(finding.status.value if hasattr(finding.status, "value") else finding.status)),
    ]
    rows_contacts = [
        ("Device Owner",  esc(owner_txt)),
        ("Last User",     esc(device.last_login_user or "Unknown")),
        ("AD Last Logon", esc(_dt(device.ad_last_logon))),
    ]

    def table(rows: list[tuple[str, str]], bg: str = "#fafafa") -> str:
        trs = "".join(
            f'<tr><td style="padding:5px 10px;font-weight:600;color:#444;width:160px;white-space:nowrap;">{k}</td>'
            f'<td style="padding:5px 10px;">{v}</td></tr>'
            for k, v in rows
        )
        return f'<table style="border-collapse:collapse;width:100%;background:{bg};border-radius:4px;">{trs}</table>'

    desc_html = html_lib.escape(vuln.description or "No description available.").replace("\n", "<br>")
    remed_html = "".join(f"<li>{html_lib.escape(s)}</li>" for s in remediation)

    sev_label = severity.upper()
    title_html = esc(_build_title(finding, vuln, device))

    return f"""<!DOCTYPE html>
<html><body style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#222;max-width:700px;margin:0 auto;">
<div style="background:{sev_color};color:#fff;padding:14px 20px;border-radius:6px 6px 0 0;">
  <span style="font-size:1.3em;font-weight:bold;">[{sev_label}] open-ctem Security Incident</span>
</div>
<div style="border:1px solid #ddd;padding:16px 20px;border-radius:0 0 6px 6px;">

  <p style="font-size:1.05em;font-weight:600;margin:0 0 16px;">{title_html}</p>

  <h3 style="color:{sev_color};margin:16px 0 6px;">Vulnerability</h3>
  {table(rows_vuln)}
  <div style="margin:8px 0;padding:10px;background:#f0f0f0;border-left:4px solid {sev_color};border-radius:2px;font-size:.9em;">
    {desc_html}
  </div>

  <h3 style="color:#333;margin:16px 0 6px;">Affected System</h3>
  {table(rows_device)}

  <h3 style="color:#333;margin:16px 0 6px;">Contacts / Ownership</h3>
  {table(rows_contacts)}

  <h3 style="color:#333;margin:16px 0 6px;">Risk Context</h3>
  {table(rows_risk)}

  <h3 style="color:{sev_color};margin:16px 0 6px;">Remediation Steps</h3>
  <ol style="margin:0;padding-left:20px;line-height:1.8;">{remed_html}</ol>

  <p style="margin:20px 0 0;font-size:.8em;color:#888;">
    Created automatically by open-ctem &bull; Finding ID: {esc(str(finding.id))}
    &bull; Update finding status in open-ctem once remediated.
  </p>
</div>
</body></html>"""


# ── Formatting helpers ────────────────────────────────────────────────────────

def _age(first_detected, now: datetime) -> str:
    if not first_detected:
        return "unknown"
    td = now - first_detected.replace(tzinfo=timezone.utc) if first_detected.tzinfo is None else now - first_detected
    days = td.days
    if days == 0:
        return "less than 1 day"
    if days == 1:
        return "1 day"
    if days < 30:
        return f"{days} days"
    months = days // 30
    return f"{months} month{'s' if months != 1 else ''} ({days} days)"


def _dt(dt: datetime | None) -> str:
    if not dt:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _os_line(device) -> str:
    parts = [p for p in [device.os, device.os_version] if p]
    return " ".join(parts) or "Unknown"


def _edr_line(device) -> str:
    if not device.edr_vendor:
        return "None detected -- increased risk"
    status = "Active" if device.edr_active else "INACTIVE (check immediately)"
    last   = f", last seen {_dt(device.edr_last_seen)}" if device.edr_last_seen else ""
    return f"{device.edr_vendor} ({status}{last})"


def _owner_line(device) -> str:
    owner = getattr(device, "owner", None)
    if not owner:
        return "Unassigned -- check CMDB"
    name  = getattr(owner, "display_name", None) or owner.username
    email = getattr(owner, "email", None)
    return f"{name}  <{email}>" if email else str(name)


def _reachability_line(finding) -> str:
    if finding.is_reachable is None:
        return "Not yet validated"
    if finding.is_reachable:
        src = f" (confirmed by {finding.reachability_source})" if finding.reachability_source else ""
        return f"YES -- network reachable{src}"
    return "No -- not reachable from current network scans"


def _exploit_line(vuln) -> str:
    if not vuln.exploit_available:
        return "No known exploit"
    maturity = vuln.exploit_maturity or "available"
    labels   = {
        "poc":        "Proof-of-concept (PoC) code available publicly",
        "functional": "Functional exploit available -- exploitation straightforward",
        "weaponized": "WEAPONIZED exploit -- actively used in attacks",
    }
    return labels.get(maturity, f"Exploit available ({maturity})")


def _remediation_steps(vuln, device) -> list[str]:
    """Heuristic remediation based on CVE/OS/device context."""
    steps: list[str] = []

    if vuln.cve_id:
        steps.append(
            f"Search the vendor bulletin for {vuln.cve_id} and apply the latest security patch "
            f"or update. Prioritize based on the CVSS score ({vuln.cvss_base or 'see NVD'})."
        )
    else:
        steps.append(f"Apply the vendor-recommended fix for: {vuln.title}.")

    if vuln.is_kev:
        steps.append(
            "This is a CISA Known Exploited Vulnerability (KEV). "
            "CISA mandates federal agencies patch KEVs within defined timelines. "
            "Treat this as urgent regardless of environment."
        )

    if device.is_internet_exposed:
        steps.append(
            "This device is internet-exposed. Consider implementing a temporary firewall "
            "or WAF rule to block exploit traffic while the patch is prepared."
        )

    if vuln.exploit_available:
        steps.append(
            "A public exploit exists for this vulnerability. "
            "Expedite patching and monitor endpoint detection logs for exploitation indicators."
        )

    if not device.edr_active:
        steps.append(
            "EDR is inactive or not installed on this device. "
            "Deploy and activate endpoint protection immediately -- this increases exposure risk."
        )

    if vuln.attack_vector and vuln.attack_vector.lower() == "network":
        steps.append(
            "This vulnerability is exploitable over the network with no physical access required. "
            "Verify network segmentation and firewall rules restrict access to this device."
        )

    steps.append(
        "After patching, run a targeted vulnerability scan to confirm the finding is resolved, "
        "then update the status in open-ctem to close this ticket."
    )

    return steps


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


# ── Request schema ────────────────────────────────────────────────────────────

class CreateTicketRequest(BaseModel):
    method:           Literal["api", "email"] = "api"
    assignment_group: str | None = None
    notes:            str | None = None
    priority_override: Literal["critical", "high", "medium", "low"] | None = None
