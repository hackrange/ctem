"""Threat Curated Rules: generic, learned once from the AI's high-fidelity findings, then run first for free."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import delete, select

from api.hunt import curated


def test_rules_stay_generic():
    names = {"desktop001", "jdoe"}
    m = curated.validate("alert", {"technique_ids": ["t1482", "bad"], "title_any": ["nltest", "DESKTOP001", "10.1.2.3", "ACME\\jdoe"],
                                   "sources": ["crowdstrike", "evil"], "min_hosts": 0}, names)
    assert m["technique_ids"] == ["T1482"] and m["title_any"] == ["nltest"] and m["sources"] == ["crowdstrike"] and m["min_hosts"] == 1
    with pytest.raises(ValueError):
        curated.validate("alert", {"sources": ["crowdstrike"]})            # nothing reusable to match on
    with pytest.raises(ValueError):
        curated.validate("alert", {"title_any": ["desktop001"]}, names)   # only a host name: not generic
    with pytest.raises(ValueError):
        curated.validate("splunk", {"spl": "search index=main host=desktop001"}, names)
    with pytest.raises(ValueError):
        curated.validate("splunk", {"spl": "search index=main src=192.0.2.7"})
    with pytest.raises(ValueError):
        curated.validate("splunk", {"spl": "| delete"})
    a = curated.validate("alert", {"title_any": ["NLTEST", "trust"], "technique_ids": ["T1482"]})
    b = curated.validate("alert", {"technique_ids": ["T1482"], "title_any": ["trust", "nltest"]})
    assert curated.fingerprint("alert", a) == curated.fingerprint("alert", b)


async def _alert(db, tag, host, title="AD Enum: Domain Trusts - nltest (Mandiant)", tech="T1482"):
    from api.models.settings import AppSetting
    key = f"threat_alert_cr{tag}{host}"
    db.add(AppSetting(key=key, value=json.dumps({"id": key, "title": title, "source": "crowdstrike", "hostname": host,
                                                 "technique_id": tech, "detected_at": datetime.now(timezone.utc).isoformat()})))
    return key


@pytest.mark.asyncio
async def test_learned_once_then_matched_for_free(db):
    from api.models.settings import AppSetting
    from api.models.threat_rule import ThreatRule
    tag = uuid.uuid4().hex[:8]
    keys = [await _alert(db, tag, f"ws{tag}{i}", title=f"Recon nltest {tag}") for i in range(3)]
    await db.commit()
    word = f"nltest {tag}"
    ai_issue = {"title": "Domain trust discovery", "severity": "high", "confidence": "high", "timeline": [], "what_to_do": ["Check who ran it"],
                "involved": {"hosts": [f"ws{tag}0", f"ws{tag}1"], "users": [], "ips": []},
                "attack": [{"id": "T1482", "name": "Domain Trust Discovery"}], "why_it_matters": "Attackers map trusts before moving",
                "rule_draft": {"kind": "alert", "name": "Domain trust discovery", "match": {"title_any": [word, f"ws{tag}0"], "min_hosts": 2}}}
    weak = {**ai_issue, "title": "Odd one-off", "confidence": "low", "severity": "medium", "rule_draft": {"kind": "alert", "match": {"title_any": ["something"]}}}
    assert await curated.learn(db, [dict(ai_issue), dict(weak)], "What is happening?") == 1
    rule = (await db.execute(select(ThreatRule).where(ThreatRule.name == "Domain trust discovery", ThreatRule.status == "learned"))).scalars().first()
    assert rule.match["title_any"] == [word] and rule.created_by == "ai"     # the host word was dropped
    assert await curated.learn(db, [dict(ai_issue)], "again") == 0           # same pattern: not learned twice

    issues, lookups, explained = await curated.run(db, None, "7d", first_lookup=4)
    mine = [i for i in issues if i["from_rule"] == str(rule.id)]
    assert mine and mine[0]["confidence"] == "high" and len(mine[0]["involved"]["hosts"]) == 3 and mine[0]["lookups"][0] >= 4
    assert set(keys) <= explained and any(lk["source_label"] == "Curated rule" for lk in lookups)
    await db.refresh(rule)
    assert rule.hits == 1 and rule.last_hit_at
    await db.execute(delete(AppSetting).where(AppSetting.key.in_(keys)))
    await db.execute(delete(ThreatRule).where(ThreatRule.id == rule.id))
    await db.commit()


@pytest.mark.asyncio
async def test_a_second_hunt_on_the_same_pattern_skips_the_ai(db, monkeypatch):
    from api.hunt import ai as hunt_ai
    from api.hunt import engine
    from api.models.settings import AppSetting
    from api.models.threat_rule import ThreatRule
    tag = uuid.uuid4().hex[:8]
    keys = [await _alert(db, tag, f"pc{tag}{i}", title=f"certreq misuse {tag}") for i in range(2)]
    m = curated.validate("alert", {"title_any": [f"certreq misuse {tag}"]})
    db.add(ThreatRule(name=f"Certreq misuse {tag}", kind="alert", match=m, fingerprint=curated.fingerprint("alert", m), severity="high", status="manual"))
    await db.commit()
    calls = {"write": 0}

    class _AI:
        pass

    async def get_ai(_db):
        return _AI()

    async def plan(*a, **k):
        return [{"source": "ctem", "table": "alerts", "filters": {"text": tag}, "title": "Alerts"}]

    async def follow(*a, **k):
        return []

    async def write(*a, **k):
        calls["write"] += 1
        return {"summary": "x", "issues": []}

    async def none(_db, vendors, live=False):
        return []
    monkeypatch.setattr(hunt_ai, "get_ai", get_ai)
    monkeypatch.setattr(hunt_ai, "plan", plan)
    monkeypatch.setattr(hunt_ai, "follow_leads", follow)
    monkeypatch.setattr(hunt_ai, "write_up", write)
    monkeypatch.setattr(engine, "_enabled", none)
    from api.core import ai_usage

    async def ok():
        return None
    monkeypatch.setattr(ai_usage, "guard", ok)
    out = await engine.investigate(db, f"anything about {tag}?", "7d")
    assert calls["write"] == 0                                                   # the rule explained it all
    assert any(i["title"] == f"Certreq misuse {tag}" and i["from_rule"] for i in out["issues"])
    assert any("Curated Rule" in n for n in out["notes"])
    await db.execute(delete(AppSetting).where(AppSetting.key.in_(keys)))
    await db.execute(delete(ThreatRule).where(ThreatRule.name == f"Certreq misuse {tag}"))
    await db.commit()


@pytest.mark.asyncio
async def test_admin_api(client_admin, client_cyber):
    tag = uuid.uuid4().hex[:8]
    body = {"name": f"Kerberoasting {tag}", "kind": "alert", "match": {"technique_ids": ["T1558.003"], "title_any": [f"kerberoast {tag}"]},
            "severity": "high", "description": "Service ticket harvesting", "what_to_do": ["Rotate service account passwords"]}
    r = await client_admin.post("/api/v1/threat-rules", json=body)
    assert r.status_code == 200 and r.json()["status"] == "manual"
    rid = r.json()["id"]
    assert (await client_admin.post("/api/v1/threat-rules", json=body)).status_code == 409   # same pattern
    assert (await client_admin.post("/api/v1/threat-rules", json={**body, "match": {"spl": "x"}, "kind": "alert"})).status_code == 400
    assert (await client_admin.post("/api/v1/threat-rules/" + rid + "/test")).json()["supported"] is True
    assert (await client_admin.put(f"/api/v1/threat-rules/{rid}", json={"enabled": False})).json()["enabled"] is False
    assert any(x["id"] == rid for x in (await client_admin.get("/api/v1/threat-rules")).json()["rules"])
    assert (await client_cyber.get("/api/v1/threat-rules")).status_code == 403
    assert (await client_cyber.delete(f"/api/v1/threat-rules/{rid}")).status_code == 403
    assert (await client_admin.delete(f"/api/v1/threat-rules/{rid}")).status_code == 200
