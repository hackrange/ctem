"""Admin > Threat Curated Rules (api/hunt/curated.py): list, add, edit, review, test and remove. Admins only; every
change is in the Audit Log, and a rule is checked to stay generic whoever writes it."""
from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core.db import get_session
from api.models.threat_rule import ThreatRule
from api.models.user import User

router = APIRouter(prefix="/api/v1/threat-rules", tags=["admin"])
Text = Field(min_length=1, max_length=120, pattern=r"^[^\x00-\x1f<>]+$")


class RuleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Text
    kind: Literal["alert", "splunk"] = "alert"
    match: dict
    severity: Literal["critical", "high", "medium", "low"] = "high"
    description: str | None = Field(None, max_length=600, pattern=r"^[^\x00-\x08\x0b-\x1f<>]*$")
    what_to_do: list[str] = Field(default_factory=list, max_length=8)
    enabled: StrictBool = True


class RulePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, min_length=1, max_length=120, pattern=r"^[^\x00-\x1f<>]+$")
    match: dict | None = None
    severity: Literal["critical", "high", "medium", "low"] | None = None
    description: str | None = Field(None, max_length=600, pattern=r"^[^\x00-\x08\x0b-\x1f<>]*$")
    what_to_do: list[str] | None = Field(None, max_length=8)
    enabled: StrictBool | None = None
    reviewed: StrictBool | None = None


def _view(r: ThreatRule) -> dict:
    return {"id": str(r.id), "name": r.name, "kind": r.kind, "match": r.match, "severity": r.severity,
            "description": r.description, "what_to_do": r.what_to_do or [], "attack": r.attack or [], "enabled": r.enabled,
            "status": r.status, "learned_from": r.learned_from, "hits": r.hits,
            "last_hit_at": r.last_hit_at.isoformat() if r.last_hit_at else None, "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None}


async def _rule(db, rule_id: uuid.UUID) -> ThreatRule:
    r = (await db.execute(select(ThreatRule).where(ThreatRule.id == str(rule_id)))).scalar_one_or_none()
    if r is None:
        raise HTTPException(404)
    return r


async def _checked(db, kind: str, match: dict, skip_id: str | None = None) -> tuple[dict, str]:
    from api.hunt import curated
    try:
        clean = curated.validate(kind, match, await curated.known_names(db))
    except (ValueError, TypeError) as e:
        raise HTTPException(400, detail=str(e)) from None
    fp = curated.fingerprint(kind, clean)
    dupe = (await db.execute(select(ThreatRule.id).where(ThreatRule.fingerprint == fp))).scalar_one_or_none()
    if dupe and str(dupe) != skip_id:
        raise HTTPException(409, detail="A rule with the same pattern already exists")
    return clean, fp


@router.get("")
async def list_rules(_: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from api.hunt import curated_pack
    await curated_pack.sync(db)   # the built-in pack appears as soon as CrowdStrike is enabled
    rows = (await db.execute(select(ThreatRule).order_by(ThreatRule.status, ThreatRule.hits.desc(), ThreatRule.name))).scalars()
    return {"rules": [_view(r) for r in rows]}


@router.post("")
async def add_rule(body: RuleBody, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from api.routes.admin import _audit
    clean, fp = await _checked(db, body.kind, body.match)
    r = ThreatRule(name=body.name, kind=body.kind, match=clean, fingerprint=fp, severity=body.severity,
                   description=body.description, what_to_do=[s[:300] for s in body.what_to_do], enabled=body.enabled,
                   status="manual", created_by=admin.username, updated_by=admin.username)
    db.add(r)
    await db.flush()
    await _audit(admin, "threat_rule.create", "threat_rule", str(r.id), f"Threat curated rule added: {r.name}", db)
    await db.commit()
    return _view(r)


@router.put("/{rule_id}")
async def edit_rule(rule_id: uuid.UUID, body: RulePatch, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from api.routes.admin import _audit
    r = await _rule(db, rule_id)
    changed = []
    if body.match is not None:
        r.match, r.fingerprint = await _checked(db, r.kind, body.match, skip_id=str(r.id))
        changed.append("match")
    for field in ("name", "severity", "description", "enabled"):
        v = getattr(body, field)
        if v is not None and v != getattr(r, field):
            setattr(r, field, v)
            changed.append(field)
    if body.what_to_do is not None:
        r.what_to_do = [s[:300] for s in body.what_to_do]
        changed.append("what_to_do")
    if body.reviewed and r.status == "learned":
        r.status = "reviewed"
        changed.append("reviewed")
    r.updated_by = admin.username
    await _audit(admin, "threat_rule.update", "threat_rule", str(r.id),
                 f"Threat curated rule {r.name}: {', '.join(changed) or 'no change'}", db)
    await db.commit()
    return _view(r)


@router.delete("/{rule_id}")
async def delete_rule(rule_id: uuid.UUID, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from api.routes.admin import _audit
    r = await _rule(db, rule_id)
    from api.hunt import curated_pack
    await _audit(admin, "threat_rule.delete", "threat_rule", str(r.id), f"Threat curated rule removed: {r.name}", db)
    await curated_pack.forget(db, r)   # a deleted built-in rule stays deleted
    await db.delete(r)
    await db.commit()
    return {"ok": True}


@router.post("/{rule_id}/test")
async def test_rule(rule_id: uuid.UUID, _: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    """What this rule matches in the last 7 days of alerts, without touching its hit count."""
    from datetime import datetime, timedelta, timezone

    from api.hunt.curated import alert_matches
    from api.routes.threat import _alerts
    r = await _rule(db, rule_id)
    if r.kind != "alert":
        return {"supported": False, "note": "Splunk rules are tried on the next hunt; test them on the Hunt page."}
    since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    hits = [a for a in await _alerts(db) if (a.get("detected_at") or "") >= since and alert_matches(r.match, a)]
    hosts = sorted({a["hostname"] for a in hits if a.get("hostname")})
    return {"supported": True, "alerts": len(hits), "hosts": len(hosts), "would_fire": len(hits) >= r.match["min_alerts"] and len(hosts) >= r.match["min_hosts"],
            "sample": [{"when": a.get("detected_at"), "host": a.get("hostname"), "title": a.get("title")} for a in hits[:10]]}
