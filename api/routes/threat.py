"""Cyber Threat module -- cyber role only. Correlates SIEM/EDR data with active CVE findings."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.middleware import get_current_user
from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/threat", tags=["threat"])


async def _alerts(db: AsyncSession, key: str | None = None) -> list[dict]:
    """Every cached alert in one shape (or just one by key)."""
    import json
    from api.core.threat_view import normalize
    from api.models.settings import AppSetting

    stmt = select(AppSetting).where(AppSetting.key == key) if key else \
        select(AppSetting).where(AppSetting.key.like("threat\\_alert\\_%", escape="\\")).limit(20000)
    out = []
    for row in (await db.execute(stmt)).scalars():
        try:
            data = json.loads(row.value) if row.value else None
        except ValueError:
            continue
        items = [x for x in (data if isinstance(data, list) else [data]) if isinstance(x, dict)]
        for i, item in enumerate(items):
            out.append(normalize(row.key if len(items) == 1 else f"{row.key}#{i}", item, row.created_at))
    return out


async def _link_devices(db: AsyncSession, alerts: list[dict]) -> None:
    """Point each alert at its CTEM device so the host is clickable."""
    from api.core.device_match import host_key
    from api.models.device import Device

    keys = {host_key(a["hostname"]) for a in alerts if a.get("hostname")} - {None}
    found = {}
    if keys:
        found = dict((await db.execute(select(Device.host_key, Device.id).where(Device.host_key.in_(keys)))).all())
    for a in alerts:
        a["device_id"] = found.get(host_key(a.get("hostname")))


@router.get("/alerts")
async def list_threat_alerts(
    me: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    q: str | None = Query(None, max_length=200),
    source: str | None = Query(None, max_length=64, description="Source name or code: crowdstrike / CS"),
    severity: str | None = Query(None, max_length=32),
    status: str | None = Query(None, max_length=32),
    sort: str = Query("severity", max_length=32),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    hidden: str = Query("hide", pattern="^(hide|show|only)$", description="Alerts you hid for yourself: hide, show or only"),
    accepted: str = Query("show", pattern="^(hide|show|only)$", description="Alerts on the allow list: hide, show or only"),
):
    """Threat alerts from connected EDR, SIEM and firewall tools; worst first by default."""
    from api.core import hidden as mine
    from api.core.threat_view import SORTS, matches, sort_key

    alerts = await _alerts(db)
    gone = (await mine.load(db, str(me.id)))["alert"]
    for a in alerts:
        a["hidden"] = a["id"] in gone
    hidden_count = sum(a["hidden"] for a in alerts)
    if hidden != "show":
        alerts = [a for a in alerts if a["hidden"] == (hidden == "only")]
    from api.core.alert_allow import accepted as allow_list
    ok = await allow_list(db, alerts)
    for a in alerts:
        a["accepted"] = a["id"] in ok
    if accepted != "show":
        alerts = [a for a in alerts if a["accepted"] == (accepted == "only")]
    sources = sorted({(a["source"], a["source_code"]) for a in alerts if a["source"]}, key=lambda s: s[1])
    statuses = sorted({a["status"] for a in alerts if a["status"]})
    if source:
        s = source.strip().lower()
        alerts = [a for a in alerts if s in ((a["source"] or ""), a["source_code"].lower())]
    if severity:
        alerts = [a for a in alerts if (a["severity"] or "") == severity.strip().lower()]
    if status:
        alerts = [a for a in alerts if (a["status"] or "") == status.strip().lower()]
    if q and q.strip():
        alerts = [a for a in alerts if matches(a, q.strip())]
    alerts.sort(key=sort_key(sort if sort in SORTS else "severity"), reverse=order == "desc")
    page = alerts[offset:offset + limit]
    await _link_devices(db, page)
    return {"alerts": page, "total": len(alerts), "limit": limit, "offset": offset, "hidden_count": hidden_count,
            "sources": [{"source": s, "code": c} for s, c in sources], "statuses": statuses}


@router.get("/alerts/detail")
async def get_threat_alert(
    id: str = Query(..., min_length=14, max_length=300, pattern=r"^threat_alert_[^#\s]+(#\d{1,4})?$"),
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    key = id.partition("#")[0]
    found = [a for a in await _alerts(db, key) if a["id"] == id]
    if not found:
        raise HTTPException(404, detail="Alert not found")
    await _link_devices(db, found)
    alert = found[0]
    detail = await _detail(db, key) if alert.get("has_detail") else {}
    everything = await _alerts(db)
    related = await _related(db, alert, everything)
    from api.core import threat_graph
    from api.core.threat_timeline import actions_text, story, timeline
    return {**alert, "detail": detail, "story": story(alert, detail) if detail else None,
            "actions_text": actions_text(detail) if detail else [],
            "timeline": timeline(alert, detail, related), "related": related,
            "steps": (steps := threat_graph.steps(alert, related, _console_links(alert, related, everything))),
            "graph": threat_graph.build(alert, detail),
            "ai": await _ai_read(db, alert, detail, steps),
            "accepted_by": await _accepted_by(db, alert),
            "ctem_device": await _ctem_device(db, alert.get("device_id")),
            **await _updates(db, alert, everything)}


def _console_links(alert: dict, related: list[dict], everything: list[dict]) -> dict:
    """Each story step's own CrowdStrike console link (made like the others' when it was saved without one)."""
    from api.core import cs_alert_actions as act
    by_id = {a["id"]: a for a in everything}
    known = [a["link"] for a in everything if a.get("link") and a.get("source") == "crowdstrike"][:5]
    out = {}
    for r in [alert, *related]:
        a = by_id.get(r["id"], r)
        cid = act.composite_id(a["id"]) if a.get("source") == "crowdstrike" else None
        if cid:
            out[a["id"]] = a.get("link") or act.console_link(cid, known)
    return out


async def _accepted_by(db: AsyncSession, alert: dict) -> dict | None:
    """The allow-list entry that accepts this alert, if one does (api/core/alert_allow.py)."""
    from api.core.alert_allow import accepted, view
    hit = (await accepted(db, [alert])).get(alert["id"])
    return view(hit) if hit else None


async def _ai_read(db: AsyncSession, alert: dict, detail: dict, steps: list[dict]) -> dict:
    from api.core import threat_explain
    from api.hunt.ai import get_ai
    if await get_ai(db) is None:
        return {"available": False, "read": None}
    return {"available": True, "read": await threat_explain.cached(db, alert, detail, steps)}


async def story_of(db: AsyncSession, alert_key: str) -> tuple[dict, dict, list[dict]] | None:
    """An alert, its opened detail and its story steps (for the AI read; the caller checks the role)."""
    from api.core import threat_graph
    key = alert_key.partition("#")[0]
    found = [a for a in await _alerts(db, key) if a["id"] == alert_key]
    if not found:
        return None
    alert = found[0]
    detail = await _detail(db, key) if alert.get("has_detail") else {}
    return alert, detail, threat_graph.steps(alert, await _related(db, alert))


@router.get("/alerts/graph")
async def get_threat_alert_graph(
    id: str = Query(..., min_length=14, max_length=300, pattern=r"^threat_alert_[^#\s]+(#\d{1,4})?$"),
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """One alert's attack map, for the story on another alert's page (clicking one of its steps)."""
    from api.core import threat_graph
    key = id.partition("#")[0]
    found = [a for a in await _alerts(db, key) if a["id"] == id]
    if not found:
        raise HTTPException(404, detail="Alert not found")
    a = found[0]
    detail = await _detail(db, key) if a.get("has_detail") else {}
    return {"id": a["id"], "title": a.get("title"), "severity": a.get("severity"), "status": a.get("status"),
            "detected_at": a.get("detected_at"), "hostname": a.get("hostname"), "tactic": a.get("tactic"),
            "technique": a.get("technique"), "has_detail": bool(detail), "graph": threat_graph.build(a, detail)}


async def _updates(db: AsyncSession, alert: dict, everything: list[dict]) -> dict:
    """For a CrowdStrike alert: its console link (made from the others' when it was saved without one), whether it can
    be updated from here and how, and the updates already made (api/core/cs_alert_actions.py)."""
    if alert.get("source") != "crowdstrike":
        return {}
    from api.core import cs_alert_actions as act
    cid = act.composite_id(alert["id"])
    if cid is None:
        return {}
    link = alert.get("link") or act.console_link(cid, [a["link"] for a in everything if a.get("link") and a["source"] == "crowdstrike"])
    r = await act.route(db)
    return {"link": link, "link_made": bool(link and not alert.get("link")),
            "can_update": {"ok": bool(r["via"]), "via": r["via"], "why": r["why"]},
            "updates": await act.history(db, alert["id"])}


async def _detail(db: AsyncSession, key: str) -> dict:
    """The encrypted detail, opened and rebuilt from known keys again (it came from outside)."""
    import json
    import logging

    from api.core.cs_alert import csa
    from api.core.encryption import decrypt
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == key))).scalar_one_or_none()
    try:
        raw = json.loads(row.value) if row and row.value else {}
        return csa.clean(json.loads(decrypt(raw["detail_enc"]))) if isinstance(raw, dict) and raw.get("detail_enc") else {}
    except Exception:  # noqa: BLE001 -- a bad row shows the alert without its detail
        logging.getLogger("open-ctem.threat").warning("alert detail unreadable for %s", key[:80])
        return {}


async def _related(db: AsyncSession, alert: dict, everything: list[dict] | None = None, days: int = 7) -> list[dict]:
    """The alert's story: other alerts on the same host, for the same person on any host, or from the same process
    tree, within a week either side (the same process tree at any time). Each says why it's tied in."""
    from datetime import timedelta
    host, agg, who = (alert.get("hostname") or "").lower(), alert.get("aggregate_id"), alert.get("user_key")
    try:
        at = datetime.fromisoformat(alert["detected_at"]) if alert.get("detected_at") else None
    except ValueError:
        at = None
    out = []
    for a in everything if everything is not None else await _alerts(db):
        if a["id"] == alert["id"]:
            continue
        why = ("same process tree" if agg and a.get("aggregate_id") == agg
               else "same host" if host and (a.get("hostname") or "").lower() == host
               else "same user" if who and a.get("user_key") == who else None)
        if why is None:
            continue
        if at and a.get("detected_at") and why != "same process tree":
            try:
                if abs(datetime.fromisoformat(a["detected_at"]) - at) > timedelta(days=days):
                    continue
            except (ValueError, TypeError):   # unparseable, or one side has no time zone
                continue
        out.append({**{k: a.get(k) for k in ("id", "title", "severity", "status", "detected_at", "technique_id", "technique",
                                             "tactic", "source", "source_code", "hostname")}, "why": why})
    out.sort(key=lambda r: r.get("detected_at") or "")
    return out[:200]


async def _ctem_device(db: AsyncSession, device_id: str | None) -> dict | None:
    """What CTEM knows about the host: risk, open and KEV findings, who it's assigned to."""
    if not device_id:
        return None
    from api.models.device import Device
    from api.routes import device_query as dq
    d = (await db.execute(dq.with_relations(select(Device).where(Device.id == device_id)))).scalars().first()
    if d is None:
        return None
    a = dq.assigned_user(d)
    return {"id": str(d.id), "risk_grade": d.risk_grade.value if d.risk_grade else None, "risk_score": d.risk_score,
            "open_findings": d.open_findings or 0, "kev_findings": d.kev_findings or 0, "criticality": d.criticality,
            "assigned_to": a["name"] if a else None, "user": dq.user_label(d), "edr_contained": bool(d.edr_contained),
            "internet_exposed": bool(d.is_internet_exposed), "device_type": d.device_type.value if d.device_type else None}


@router.post("/analyze")
async def ai_analyze_threat(
    body: ThreatAnalysisRequest,
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """
    Queue AI analysis of a set of alert IDs against active CVE findings.
    Returns immediately with a task ID; result is available at /threat/analysis/{task_id}.
    AI runs async via Celery to avoid blocking and to batch token usage efficiently.
    """
    from api.core.tasks import analyze_threat_alerts
    task = analyze_threat_alerts.delay(body.alert_ids, body.device_id)
    return {"task_id": task.id, "status": "queued", "message": "AI analysis queued. Check back in ~30 seconds."}


@router.get("/analysis/{task_id}")
async def get_analysis_result(
    task_id: str,
    _: User = Depends(require_cyber_or_admin),
):
    """Poll for the result of an AI threat analysis task."""
    from api.core.tasks import celery_app
    result = celery_app.AsyncResult(task_id)
    if result.state == "PENDING":
        return {"status": "pending"}
    if result.state == "SUCCESS":
        return {"status": "complete", "result": result.result}
    if result.state in ("STARTED", "RETRY", "RECEIVED"):
        return {"status": "running"}
    return {"status": "failed", "error": "Analysis failed"}


@router.post("/push-to-siem")
async def push_to_siem(
    body: SIEMPushRequest,
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """
    Push enriched risk context back to Splunk (or other configured SIEMs).
    Uses the SSRF-safe httpx client -- no internal IP targets allowed.
    """
    from api.core.tasks import push_siem_context
    task = push_siem_context.delay(body.target_integration_id, body.payload)
    return {"task_id": task.id, "status": "queued"}


class ThreatAnalysisRequest(BaseModel):
    alert_ids: list[str]
    device_id: str | None = None
    context: str | None = None     # optional freeform context for the AI prompt


class SIEMPushRequest(BaseModel):
    target_integration_id: str
    payload: dict
