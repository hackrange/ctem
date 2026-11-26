"""Live status of a caller verification for the service desk panel: Persona's progress and the text's delivery,
read on demand (at most every few seconds per check) while the analyst watches, turned into steps and a result.

Reads only (GET): the inquiry with its sessions and verifications (the approved outline only, as the sync keeps),
and the Twilio message. What is learned is saved on the IdvRequest the same way the hourly sync would."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.idv")
REFRESH = timedelta(seconds=3)
DONE = ("approved", "rejected", "expired", "review", "superseded", "failed")


async def refresh(db: AsyncSession, row, force: bool = False) -> None:
    """Ask Persona (and Twilio) how this check is going, unless asked in the last few seconds or it is settled."""
    from api.integrations.base import get_connector
    from api.integrations.persona import INQUIRY_FIELDS, PersonaError
    from api.integrations.persona_ingest import apply, detail_facts, detail_params, link_people
    from api.models.integration import IntegrationConfig
    now = datetime.now(timezone.utc)
    seen = (row.facts or {}).get("desk_checked_at")
    if row.state in DONE or not row.inquiry_id.startswith("inq_"):
        return
    if not force and seen and now - datetime.fromisoformat(seen) < REFRESH:
        return
    cfg = await db.get(IntegrationConfig, row.integration_id) if row.integration_id else None
    if cfg is None:
        return
    persona = get_connector("persona", cfg.config or {})
    try:
        async with persona.client() as client:
            body = await persona.request("GET", f"/api/v1/inquiries/{row.inquiry_id}", client,
                                         {**detail_params(), "fields[inquiry]": INQUIRY_FIELDS})
    except PersonaError as e:
        log.warning("Desk status read for %s failed: %s", row.id, e)
        return
    item = body.get("data") or {}
    origin, via = row.origin, row.created_via
    apply(row, item, {}, now)
    row.origin, row.created_via = origin, via   # the service desk's request stays the service desk's
    included = body.get("included") or []
    sessions = [x for x in included if isinstance(x, dict) and x.get("type") == "inquiry-session"]
    row.facts = {**detail_facts(row.facts, included, now), "desk_checked_at": now.isoformat(), "desk_opened": bool(sessions)}
    await _delivery(db, row)
    if row.state in DONE:
        await link_people(db)   # a pass shows on the person's badge at once
    await db.commit()


async def _delivery(db: AsyncSession, row) -> None:
    from api.integrations.base import get_connector
    from api.integrations.twilio import TwilioError
    from api.models.integration import IntegrationConfig, Vendor
    from sqlalchemy import select
    ch = list(row.channels or [])
    if not ch or ch[0].get("channel") != "sms" or not ch[0].get("sid") or ch[0].get("status") in ("delivered", "undelivered", "failed"):
        return
    cfg = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.vendor == Vendor.twilio,
                                                            IntegrationConfig.is_enabled.is_(True)))).scalars().first()
    if cfg is None:
        return
    try:
        status = await get_connector("twilio", cfg.config or {}).status(ch[0]["sid"])
    except TwilioError:
        return
    if status:
        ch[0] = {**ch[0], "status": str(status)[:20]}
        row.channels = ch


def view(row) -> dict:
    """Steps and the result, in words the analyst reads at a glance."""
    from api.integrations.persona_checks import explain, gov_id_passed
    if row is None:
        return {"stage": "idle"}
    ch = (row.channels or [{}])[0]
    f = row.facts or {}
    sent = ch.get("status") not in (None, "sending", "failed", "persona_failed")
    delivered = ch.get("status") in ("delivered", "sent", "read") or (ch.get("channel") == "email" and sent)
    opened = bool(f.get("desk_opened")) or row.persona_status not in (None, "created")
    started = row.persona_status in ("pending", "completed", "approved", "failed", "needs_review", "declined")
    x = explain(f)
    result = None
    if row.state == "failed":
        result = {"kind": "error", "title": "The link didn't go out", "detail": "Try the other channel, or try again in 10 minutes."}
    elif row.state == "approved":
        from api.integrations.persona_checks import id_and_face, selfie_matched
        if row.check_kind == "selfie":   # sent because a valid ID was on file: the face must match the verified one
            ok = selfie_matched(f)
        else:
            ok = gov_id_passed(f) is True and id_and_face(f)   # the same bar as a revoke: a government ID and a matching face
        ids = [p for p in x["presented"] if p["kind"].startswith("Government ID") and p["status"] == "passed"]
        selfie = any(k["check"] == "selfie_id_comparison" and k["status"] == "passed" for k in x["passed_key_checks"])
        what = ", ".join(filter(None, [f"{ids[-1]['id_type'] or 'Government ID'} ({ids[-1]['country']})" if ids else None,
                                        "selfie matches the ID" if selfie else None,
                                        "selfie matches their verified ID on file" if row.check_kind == "selfie" and ok and not selfie else None]))
        result = ({"kind": "verified", "title": "Identity verified", "detail": what or "Passed in Persona"} if ok
                  else {"kind": "warning", "title": "Passed, but the face wasn't matched to a verified ID" if row.check_kind == "selfie"
                        else "Passed, but not a government ID with a matching face",
                        "detail": "Treat as not verified; use another method."} if (f.get("verifications") is not None)
                  else None)   # not read yet: the next status read fills it in
    elif row.state in ("review", "rejected", "superseded"):
        reasons = [fl["means"] for fl in x["failed"]][:3] or x["notes"][:2]
        result = {"kind": "failed", "title": "Not verified", "detail": " ".join(reasons) or "Persona didn't pass this check.",
                  "next": "Don't proceed on this call. Ask the caller to try again, or escalate to security."}
    elif row.state == "expired":
        result = {"kind": "failed", "title": "The link expired", "detail": "Send a new one if the caller is still there."}
    steps = [{"key": "sent", "label": f"Sent by {'text' if ch.get('channel') == 'sms' else 'email'} to {ch.get('to') or ''}".strip(), "done": sent},
             {"key": "delivered", "label": "Delivered", "done": delivered or opened},
             {"key": "opened", "label": "Caller opened the link", "done": opened},
             {"key": "started", "label": "Verifying ID and selfie", "done": started or result is not None},
             {"key": "result", "label": result["title"] if result else "Result", "done": result is not None}]
    expires = (row.created_at + timedelta(hours=24)).isoformat() if row.created_at else None
    return {"stage": "done" if result else "waiting", "steps": steps, "result": result, "sent_at": ch.get("at"),
            "link_expires_at": expires, "request_id": row.id}
