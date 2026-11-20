"""Hand an issue off: printable report data and ServiceNow tickets (API or email)."""
from __future__ import annotations

import html
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.integration import IntegrationConfig, Vendor


async def load_issue(db: AsyncSession, source: str, index: int, owner_of, user_id: str) -> tuple[dict, dict]:
    """(whole result, the one issue). 404 for anything the caller may not see or that is gone."""
    if source == "watch":
        from api.hunt.watch import load_watch
        result = ((await load_watch(db)) or {}).get("result") or {}
    else:
        if owner_of(source) != user_id:
            raise HTTPException(404)
        from api.core.tasks import celery_app
        task = celery_app.AsyncResult(source)
        result = task.result if task.state == "SUCCESS" and isinstance(task.result, dict) else {}
    issues = result.get("issues") or []
    if not 0 <= index < len(issues):
        raise HTTPException(404)
    return result, issues[index]


def ticket_text(issue: dict) -> tuple[str, str, str]:
    """(subject, plain body, html body) for a ticket or an email."""
    sev = issue["severity"].upper()
    subject = f"[open-ctem] [{sev}] {issue['title']}"[:160]
    who = issue.get("involved") or {}
    lines = [
        f"SEVERITY: {sev}   CONFIDENCE: {issue['confidence']}",
        f"WINDOW:   {issue.get('window_label') or 'n/a'}",
        "", "WHAT HAPPENED", issue["what_happened"], "", "WHY IT MATTERS", issue["why_it_matters"], "",
        "HOW IT UNFOLDED",
        *[f"  {t['time']}  [{t['source']}]  {t['what']}" for t in issue.get("timeline", [])],
        "", "INVOLVED",
        f"  Computers: {', '.join(who.get('hosts', [])) or 'none'}",
        f"  Accounts:  {', '.join(who.get('users', [])) or 'none'}",
        f"  IPs:       {', '.join(who.get('ips', [])) or 'none'}",
        "", "MITRE ATT&CK",
        *[f"  {a['id']}  {a['name']}" for a in issue.get("attack", [])],
        "", "WHAT TO DO NOW",
        *[f"  {n}. {s}" for n, s in enumerate(issue.get("what_to_do", []), 1)],
        "", f"Raised by open-ctem Threat Hunt at {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC",
    ]
    plain = "\n".join(lines)
    return subject, plain, f"<pre style=\"font-family:monospace\">{html.escape(plain)}</pre>"


async def ticket_options(db: AsyncSession) -> dict:
    from api.core.config import get_settings
    cfg = await _servicenow(db)
    s = get_settings()
    inbound = ((cfg.config or {}).get("inbound_email") if cfg else None) or s.servicenow_inbound_email
    return {"api": bool(cfg and (cfg.config or {}).get("base_url")),
            "email": bool(inbound and s.email_mode != "disabled"), "inbound_email": inbound}


async def _servicenow(db: AsyncSession):
    return (await db.execute(select(IntegrationConfig).where(
        IntegrationConfig.vendor == Vendor.servicenow, IntegrationConfig.is_enabled.is_(True)))).scalars().first()


async def create_ticket(db: AsyncSession, issue: dict, method: str) -> dict:
    subject, plain, body_html = ticket_text(issue)
    opts = await ticket_options(db)
    if method == "api":
        if not opts["api"]:
            raise HTTPException(400, "ServiceNow is not connected")
        from api.integrations.servicenow import ServiceNowConnector
        cfg = await _servicenow(db)
        hosts = (issue.get("involved") or {}).get("hosts") or [None]
        try:
            out = await ServiceNowConnector(cfg.config or {}).create_ticket(
                title=subject, description=plain, severity=issue["severity"], affected_device=hosts[0])
        except Exception as exc:
            import logging
            logging.getLogger("open-ctem.hunt").warning("ServiceNow ticket failed", exc_info=True)
            raise HTTPException(502, "ServiceNow did not accept the ticket. Check the integration.") from exc
        return {"method": "api", "number": out.get("number"), "url": out.get("url")}
    if not opts["email"]:
        raise HTTPException(400, "Ticket by email is not set up (ServiceNow inbound email and email sending)")
    from api.core.email import get_email_client
    if not await get_email_client().send(to=opts["inbound_email"], subject=subject, body_text=plain, body_html=body_html):
        raise HTTPException(503, "The email could not be sent. Check the email settings.")
    return {"method": "email", "sent_to": opts["inbound_email"],
            "note": "ServiceNow will open the ticket from this email."}
