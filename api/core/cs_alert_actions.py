"""CrowdStrike alert updates from CTEM (Cyber Threats > alert): close, reopen, put in progress, classify, comment.

Only cyber and admin may ask (api/routes/threat_actions.py). The update goes one of two ways:
  direct   a CrowdStrike integration in CTEM holds its own API client: sent at once, the answer shown right away
  shipper  CrowdStrike is read by an on-prem shipper with "Alert updates" turned on and approved on the box: queued,
           and the shipper sends it with its own API client on its next check-in (within about 5 minutes)
Either way the API client needs "Alerts: Write", only the four actions in collector_cs_actions are ever sent, and the
next pull brings Falcon's own copy back, so CTEM always ends up showing what Falcon has.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.alert_action import AlertAction

log = logging.getLogger("open-ctem.cs_alert_actions")
_PATH = Path(__file__).resolve().parent.parent / "collector" / "agent" / "collector_cs_actions.py"
_spec = importlib.util.spec_from_file_location("ctem_cs_actions", _PATH)
csx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(csx)

API_BASE = "https://api.crowdstrike.com"   # the direct connector's cloud (api/integrations/crowdstrike.py)
SENT_TIMEOUT = timedelta(minutes=30)
_KEY = re.compile(r"^threat_alert_([A-Za-z0-9:_.-]{1,200})$")
_LINK = re.compile(r"^(https://falcon(?:\.[a-z0-9-]+)*\.crowdstrike\.com/activity-v2/detections/)[^?#\s]+(\?[^#\s]*)?$")


class Unavailable(ValueError):
    """Nothing can send updates right now (the reason says what to set up)."""


def composite_id(alert_key: str) -> str | None:
    m = _KEY.match(alert_key or "")
    return m.group(1) if m else None


def console_link(cid: str, links: list[str]) -> str | None:
    """A Falcon console link for an alert saved without one, in the same form as the links Falcon gave the others."""
    for link in links:
        m = _LINK.match(link or "")
        if m:
            return f"{m.group(1)}{quote(cid, safe=':')}{m.group(2) or ''}"
    return None


async def route(db: AsyncSession) -> dict:
    """How an update would go now: {"via": "direct" | "shipper" | None, "integration_id", "why"}."""
    from api.models.collector import CollectorProfile, CollectorToken
    from api.models.integration import IntegrationConfig, Vendor
    profiles = list((await db.execute(select(CollectorProfile))).scalars())
    cfgs = list((await db.execute(select(IntegrationConfig).where(IntegrationConfig.vendor == Vendor.crowdstrike))).scalars())
    toks = {str(t.profile_id): t for t in (await db.execute(select(CollectorToken).where(
        CollectorToken.is_active == True))).scalars()}  # noqa: E712
    return decide(cfgs, profiles, toks)


def decide(cfgs, profiles, toks: dict) -> dict:
    """A CrowdStrike integration with its own API client wins; else the shipper whose CrowdStrike source has Alert
    updates turned on and approved on its box."""
    from api.collector.profile import dest_digest
    owned = {str(m.get("integration_id")) for p in profiles for m in (p.modules or {}).values() if m.get("integration_id")}
    for cfg in cfgs:
        conf = cfg.config or {}
        if cfg.is_enabled and str(cfg.id) not in owned and conf.get("client_id") and conf.get("client_secret"):
            return {"via": "direct", "integration_id": str(cfg.id), "why": None}
    why = "No CrowdStrike integration or shipper can send updates."
    for p in profiles:
        m = (p.modules or {}).get("crowdstrike")
        if not m or not m.get("enabled", True) or not m.get("integration_id"):
            continue
        settings = m.get("settings") or {}
        tok = toks.get(str(p.id))
        if settings.get("alert_updates") != "on":
            why = ("Turn on Alert updates for the shipper's CrowdStrike source (Settings > Integrations > Shippers), "
                   "then run open-ctem-collector approve on the box.")
        elif tok is None or (tok.approved or {}).get("crowdstrike") != dest_digest("crowdstrike", settings):
            why = ("Alert updates are on but not approved on the shipper yet: run open-ctem-collector approve on the box "
                   "(shipper 1.8.0 or later).")
        else:
            return {"via": "shipper", "integration_id": str(m["integration_id"]), "why": None}
    return {"via": None, "integration_id": None, "why": why}


async def request(db: AsyncSession, keys: list[str], params: dict, user) -> list[AlertAction]:
    """Record the update for each alert and send it (direct) or queue it (shipper). Raises ValueError if refused."""
    r = await route(db)
    if not r["via"]:
        raise Unavailable(r["why"])
    who = user.username   # in Falcon's comment, so the console shows who did it
    now = datetime.now(timezone.utc)
    cids = [composite_id(k) for k in keys]
    if None in cids:
        raise ValueError("Only CrowdStrike alerts can be updated from CTEM.")
    for cid in cids:
        csx.body([cid], who=who[:256], **params)   # every one is checked before anything is recorded
    out = []
    for key, cid in zip(keys, cids):
        a = AlertAction(alert_key=key, composite_id=cid, integration_id=r["integration_id"], via=r["via"], state="queued",
                        params={**params, "who": who[:256]}, requested_by=str(user.id), requested_by_name=user.username,
                        created_at=now)
        db.add(a)
        out.append(a)
    await db.flush()
    if r["via"] == "direct":
        await _send_direct(db, r["integration_id"], out)
    return out


def _body(a: AlertAction) -> dict:
    p = dict(a.params or {})
    who = p.pop("who", a.requested_by_name)
    return csx.body([a.composite_id], who=who, **p)


async def _send_direct(db: AsyncSession, integration_id: str, actions: list[AlertAction]) -> None:
    from api.core.ssrf import safe_client
    from api.models.integration import IntegrationConfig
    cfg = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == integration_id))).scalar_one()
    now = datetime.now(timezone.utc)
    try:
        async with safe_client() as client:
            tok = await client.post(f"{API_BASE}/oauth2/token", data={"client_id": cfg.config["client_id"],
                                                                      "client_secret": cfg.config["client_secret"]})
            tok.raise_for_status()
            auth = {"Authorization": f"Bearer {tok.json()['access_token']}"}
            for a in actions:
                a.sent_at = now
                resp = await client.patch(f"{API_BASE}{csx.PATH}", headers=auth, json=_body(a))
                if resp.status_code < 300:
                    await _done(db, a, None)
                else:
                    log.warning("CrowdStrike alert update refused: HTTP %s", resp.status_code)
                    await _done(db, a, csx.refused(resp.status_code))
    except Exception as e:  # noqa: BLE001 -- recorded on each update; details stay in the server log
        log.warning("CrowdStrike alert update failed: %s", type(e).__name__)
        for a in actions:
            if a.state == "queued":
                await _done(db, a, "Couldn't reach CrowdStrike with the integration's API client")


async def _done(db: AsyncSession, a: AlertAction, error: str | None) -> None:
    a.state, a.error, a.done_at = ("failed", error[:500], datetime.now(timezone.utc)) if error else ("done", None, datetime.now(timezone.utc))
    if not error and (a.params or {}).get("status"):
        await _cache_status(db, a.alert_key, a.params["status"])


async def _cache_status(db: AsyncSession, key: str, status: str) -> None:
    """Show the new status now; the next pull replaces the row with Falcon's own copy anyway."""
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
    if row is None or not row.value:
        return
    try:
        data = json.loads(row.value)
    except ValueError:
        return
    if isinstance(data, dict):
        data["status"] = status
        row.value = json.dumps(data)


async def claim(db: AsyncSession, integration_id: str, limit: int = 50) -> list[dict]:
    """The shipper's queued updates, marked sent. One sent but never reported back fails after 30 minutes, so a
    person can try again rather than wait forever (it is never resent on its own: a comment mustn't land twice)."""
    now = datetime.now(timezone.utc)
    stale = (await db.execute(select(AlertAction).where(AlertAction.integration_id == integration_id,
                                                        AlertAction.state == "sent",
                                                        AlertAction.sent_at < now - SENT_TIMEOUT))).scalars()
    for a in stale:
        a.state, a.done_at, a.error = "failed", now, "The shipper took it but never said whether CrowdStrike accepted it"
    rows = list((await db.execute(select(AlertAction).where(AlertAction.integration_id == integration_id,
                                                            AlertAction.via == "shipper", AlertAction.state == "queued")
                                  .order_by(AlertAction.created_at).limit(limit))).scalars())
    out = []
    for a in rows:
        try:
            out.append({"id": str(a.id), "body": _body(a)})
            a.state, a.sent_at = "sent", now
        except ValueError:
            a.state, a.done_at, a.error = "failed", now, "Not a valid update"
    return out


async def report(db: AsyncSession, integration_id: str, results: list[dict]) -> int:
    """What the shipper says CrowdStrike answered. Only this integration's updates that were sent count."""
    n = 0
    for r in results:
        a = (await db.execute(select(AlertAction).where(AlertAction.id == r["id"], AlertAction.integration_id == integration_id,
                                                        AlertAction.state == "sent"))).scalar_one_or_none()
        if a is not None:
            await _done(db, a, None if r["ok"] else (r.get("error") or "CrowdStrike refused the update"))
            n += 1
    return n


async def history(db: AsyncSession, key: str, limit: int = 20) -> list[dict]:
    rows = (await db.execute(select(AlertAction).where(AlertAction.alert_key == key)
                             .order_by(AlertAction.created_at.desc()).limit(limit))).scalars()
    return [{"id": str(a.id), "state": a.state, "via": a.via, "by": a.requested_by_name,
             "status": (a.params or {}).get("status"), "classification": (a.params or {}).get("classification"),
             "comment": (a.params or {}).get("comment"), "at": a.created_at.isoformat() if a.created_at else None,
             "done_at": a.done_at.isoformat() if a.done_at else None, "error": a.error} for a in rows]
