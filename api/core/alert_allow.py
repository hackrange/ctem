"""Accepted alerts (the allow list): once cyber or admin accept a detection, matching alerts stop raising hunt and
hourly-check findings, Threat Curated Rule hits and Splunk feed alerts, and show as Accepted in Cyber Threats. Each
entry is the detection's name plus whatever narrows it (host, process, file, hash), with a reason and an end date
(a year at most), and every change is audited. Alerts stay stored and visible: accepting never deletes anything."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.alert_allow import AlertAllow


def _base(name) -> str:
    return str(name or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


async def active(db: AsyncSession) -> list[AlertAllow]:
    now = datetime.now(timezone.utc)
    rows = (await db.execute(select(AlertAllow).where(AlertAllow.enabled.is_(True)))).scalars().all()
    return [r for r in rows if (r.expires_at if r.expires_at.tzinfo else r.expires_at.replace(tzinfo=timezone.utc)) > now]


def _needs_detail(r: AlertAllow) -> bool:
    return bool(r.process or r.file or r.sha256)


def matches(r: AlertAllow, alert: dict, summary: dict | None = None) -> bool:
    """alert: a normalized alert (api/core/threat_view.py); summary: its detail summary (api/hunt/alert_detail.py)."""
    if r.source and (alert.get("source") or "") != r.source:
        return False
    if (alert.get("title") or "").strip().lower() != r.title.strip().lower():
        return False
    if r.hostname and (alert.get("hostname") or "").strip().lower() != r.hostname.strip().lower():
        return False
    s = summary or {}
    if r.process and _base(s.get("process")) != _base(r.process):
        return False
    if r.file and r.file.lower() not in str(s.get("file") or "").lower():
        return False
    return not (r.sha256 and (s.get("sha256") or "").lower() != r.sha256.lower())


async def accepted(db: AsyncSession, alerts: list[dict], rules: list[AlertAllow] | None = None, count: bool = False) -> dict:
    """{alert id: the entry that accepts it} for the normalized alerts given. Opens an alert's detail only when an
    entry with the same detection needs its process, file or hash."""
    from api.hunt.alert_detail import summarize
    from api.routes.threat import _detail
    rules = await active(db) if rules is None else rules
    if not rules:
        return {}
    by_title: dict[str, list[AlertAllow]] = {}
    for r in rules:
        by_title.setdefault(r.title.strip().lower(), []).append(r)
    out: dict[str, AlertAllow] = {}
    for a in alerts:
        cands = by_title.get((a.get("title") or "").strip().lower())
        if not cands:
            continue
        summary = None
        if any(_needs_detail(r) for r in cands) and a.get("has_detail"):
            summary = summarize(await _detail(db, a["id"].partition("#")[0]))
        hit = next((r for r in cands if matches(r, a, summary)), None)
        if hit:
            out[a["id"]] = hit
    if count and out:
        now = datetime.now(timezone.utc)
        for r in set(out.values()):
            r.hits, r.last_hit_at = (r.hits or 0) + sum(1 for v in out.values() if v is r), now
    return out


async def accepted_keys(db: AsyncSession, rows: list[tuple[str, dict]]) -> set[str]:
    """For callers holding stored rows ((key, raw alert)): the keys of the accepted ones."""
    from api.core.threat_view import normalize
    alerts = [normalize(k, a) for k, a in rows if isinstance(a, dict)]
    return set(await accepted(db, alerts))


def view(r: AlertAllow) -> dict:
    return {"id": str(r.id), "source": r.source, "title": r.title, "hostname": r.hostname, "process": r.process, "file": r.file,
            "sha256": r.sha256, "reason": r.reason, "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "enabled": r.enabled, "created_by": r.created_by, "hits": r.hits,
            "last_hit_at": r.last_hit_at.isoformat() if r.last_hit_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None}
