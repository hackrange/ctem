"""Accepted alerts (the allow list): narrow matching, cyber and admin only, a reason and an end date, and accepted
alerts stop raising findings while staying visible."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone

import pytest

from tests.test_threat_detail import RAW


def _rule(**kw):
    from api.models.alert_allow import AlertAllow
    base = {"title": "LsassHandle", "reason": "backup agent by design", "created_by": "t", "enabled": True,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=30)}
    return AlertAllow(**{**base, **kw})


def test_an_entry_matches_its_detection_and_only_as_narrowly_as_it_says():
    from api.core.alert_allow import matches
    a = {"title": "LsassHandle", "source": "crowdstrike", "hostname": "WS-1"}
    s = {"process": "C:\\Program Files\\Backup\\agent.exe", "file": "C:\\Windows\\System32\\lsass.exe", "sha256": "a" * 64}
    assert matches(_rule(), a, s) and matches(_rule(title="lsasshandle"), a, s)
    assert not matches(_rule(title="Other"), a, s)
    assert matches(_rule(hostname="ws-1"), a, s) and not matches(_rule(hostname="WS-2"), a, s)
    assert matches(_rule(process="agent.exe"), a, s) and not matches(_rule(process="evil.exe"), a, s)
    assert matches(_rule(file="system32\\lsass"), a, s) and not matches(_rule(file="temp"), a, s)
    assert matches(_rule(sha256="A" * 64), a, s) and not matches(_rule(sha256="b" * 64), a, s)
    assert not matches(_rule(process="agent.exe"), a, None)          # a process condition needs the detail to say so
    assert not matches(_rule(source="sentinelone"), a, s)


async def _alert(db, tag, **extra):
    from api.core.cs_alert import csa
    from api.integrations.base import get_connector
    raw = {**RAW, "composite_id": f"cid:ind:{tag}:1", "display_name": f"LsassHandle{tag}", "severity_name": "High",
           "created_timestamp": datetime.now(timezone.utc).isoformat(), "filename": "agent.exe",
           "filepath": "\\Device\\HarddiskVolume3\\Program Files\\Backup\\agent.exe", **extra}
    await get_connector("crowdstrike", {"client_id": "x", "client_secret": "y"})._cache_threats([csa.summary(raw)], db)
    return f"threat_alert_cid:ind:{tag}:1"


@pytest.mark.asyncio
async def test_only_cyber_and_admin_accept_with_a_reason_and_a_bounded_end_date(db, client_cyber, client_read_only, client_it_user):
    tag = uuid.uuid4().hex[:8]
    key = await _alert(db, tag)
    until = str(date.today() + timedelta(days=30))
    body = {"title": f"LsassHandle{tag}", "source": "crowdstrike", "process": "agent.exe", "reason": "Backup agent reads LSASS by design",
            "expires_on": until}
    for c in (client_read_only, client_it_user):
        assert (await c.post("/api/v1/threat/allow", json=body)).status_code == 403
        assert (await c.get("/api/v1/threat/allow")).status_code == 403
    for bad in ({**body, "reason": "short"}, {**body, "expires_on": str(date.today())},
                {**body, "expires_on": str(date.today() + timedelta(days=400))}, {**body, "title": "<script>"},
                {**body, "sha256": "zz"}, {**body, "extra": 1}):
        assert (await client_cyber.post("/api/v1/threat/allow", json=bad)).status_code == 422
    s = (await client_cyber.get("/api/v1/threat/allow/suggest", params={"id": key})).json()
    assert s["title"] == f"LsassHandle{tag}" and s["process"].endswith("agent.exe") and s["hostname"] == "DESKTOP001"
    r = await client_cyber.post("/api/v1/threat/allow", json=body)
    assert r.status_code == 201
    allow_id = r.json()["id"]
    d = (await client_cyber.get("/api/v1/threat/alerts/detail", params={"id": key})).json()
    assert d["accepted_by"]["id"] == allow_id
    listed = (await client_cyber.get("/api/v1/threat/alerts", params={"q": tag, "accepted": "only"})).json()
    assert [a["id"] for a in listed["alerts"]] == [key] and listed["alerts"][0]["accepted"]
    assert (await client_cyber.get("/api/v1/threat/alerts", params={"q": tag, "accepted": "hide"})).json()["total"] == 0
    assert (await client_cyber.put(f"/api/v1/threat/allow/{allow_id}", json={"enabled": False})).status_code == 200
    assert (await client_cyber.get("/api/v1/threat/alerts/detail", params={"id": key})).json()["accepted_by"] is None
    assert (await client_cyber.delete(f"/api/v1/threat/allow/{allow_id}")).status_code == 200


@pytest.mark.asyncio
async def test_accepted_alerts_raise_no_rule_hunt_or_siem_findings(db):
    from api.core import alert_feed
    from api.hunt import ctem_data, curated
    from api.models.alert_allow import AlertAllow
    from api.models.threat_rule import ThreatRule
    tag = uuid.uuid4().hex[:8]
    key = await _alert(db, tag)
    m = curated.validate("alert", {"title_any": [f"LsassHandle{tag}"]})
    rule = ThreatRule(name=f"Lsass {tag}", kind="alert", match=m, fingerprint=curated.fingerprint("alert", m), severity="high",
                      status="manual", enabled=True)
    allow = _rule(title=f"LsassHandle{tag}", process="agent.exe")
    db.add_all([rule, allow])
    await db.commit()
    try:
        issues, _, _ = await curated.run(db, None, "all", 1)
        assert not any(i["title"] == rule.name for i in issues)
        rows = await ctem_data._alerts(db, {"text": tag}, 50)
        assert key not in [r["alert_key"] for r in rows]
        have: set = set()
        await alert_feed._edr_alerts(db, have, datetime.now(timezone.utc) - timedelta(hours=1))
        assert not any(tag in str(k) for k in have)
        allow.enabled = False
        await db.commit()
        issues, _, _ = await curated.run(db, None, "all", 1)
        assert any(i["title"] == rule.name for i in issues)      # turned off: it raises findings again
    finally:
        await db.delete(rule)
        await db.delete(allow)
        await db.commit()
