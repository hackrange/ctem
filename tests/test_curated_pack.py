"""The built-in Threat Curated Rules: every rule is valid and generic, added once CrowdStrike is enabled, never twice,
and an admin's deletes and edits stick."""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select


def test_every_built_in_rule_is_valid_generic_and_unique():
    from api.hunt.curated import fingerprint, validate
    from api.hunt.curated_pack import load
    pack = load()
    assert pack["requires"] == "crowdstrike" and len(pack["rules"]) >= 30
    fps, keys = set(), set()
    for r in pack["rules"]:
        m = validate(r["kind"], r["match"])
        for k in ("technique_ids", "title_any", "title_all"):
            assert len(m[k]) == len(r["match"].get(k) or []), f"{r['key']}: the validator dropped a {k} word"
        fps.add(fingerprint(r["kind"], m))
        keys.add(r["key"])
        assert r["severity"] in ("critical", "high", "medium", "low") and 2 <= len(r["what_to_do"]) <= 6
        assert len(r["name"]) <= 120 and "—" not in json.dumps(r)
    assert len(fps) == len(keys) == len(pack["rules"])


def test_the_pack_catches_real_falcon_alert_names():
    from api.hunt.curated import alert_matches, validate
    from api.hunt.curated_pack import load
    rules = [validate("alert", r["match"]) for r in load()["rules"]]
    seen = [{"source": "crowdstrike", "title": t, "technique_id": tid, "technique": tech} for t, tid, tech in (
        ("VolumeShadowSnapshotDeleted", "T1490", "Inhibit System Recovery"), ("LinFalconSensorTamper", "T1562.001", "Disable or Modify Tools"),
        ("PShellDownload", "T1059.001", "PowerShell"), ("BypassUACPrivEsc", "T1548.002", "Bypass User Account Control"))]
    for a in seen:
        assert any(alert_matches(m, a) for m in rules), a["title"]
    noise = {"source": "crowdstrike", "title": "OnWriteOfficeMacroMLLow", "technique_id": None, "technique": "Cloud-based ML"}
    assert not any(alert_matches(m, noise) and m["min_hosts"] == 1 and m["min_alerts"] == 1 for m in rules)


@pytest.mark.asyncio
@pytest.mark.builtin_pack
async def test_added_when_crowdstrike_is_on_and_deletes_stick(db, client_admin):
    from api.hunt import curated_pack
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.threat_rule import ThreatRule
    from sqlalchemy import delete

    from api.models.settings import AppSetting
    cs = IntegrationConfig(vendor=Vendor.crowdstrike, name=f"cs-{uuid.uuid4().hex[:6]}", is_enabled=True, config={})
    db.add(cs)
    await db.commit()
    try:
        await _added_and_deletes_stick(db, client_admin, curated_pack, ThreatRule)
    finally:   # the test database is shared: leave no built-in rules for other tests' hunts
        await db.execute(delete(ThreatRule).where(ThreatRule.status == "builtin"))
        await db.execute(delete(AppSetting).where(AppSetting.key == curated_pack.REMOVED_KEY))
        await db.delete(cs)
        await db.commit()


async def _added_and_deletes_stick(db, client_admin, curated_pack, ThreatRule):
    await curated_pack.sync(db)
    rules = (await client_admin.get("/api/v1/threat-rules")).json()["rules"]
    built = [r for r in rules if r["status"] == "builtin"]
    assert len(built) >= 30
    assert await curated_pack.sync(db) == 0                                  # never twice
    gone = built[0]
    assert (await client_admin.delete(f"/api/v1/threat-rules/{gone['id']}")).status_code == 200
    assert await curated_pack.sync(db) == 0                                  # a deleted built-in stays deleted
    names = {r.name for r in (await db.execute(select(ThreatRule).where(ThreatRule.status == "builtin"))).scalars()}
    assert gone["name"] not in names
    off = built[1]
    await client_admin.put(f"/api/v1/threat-rules/{off['id']}", json={"enabled": False})
    await curated_pack.sync(db)
    again = [r for r in (await client_admin.get("/api/v1/threat-rules")).json()["rules"] if r["id"] == off["id"]]
    assert again and again[0]["enabled"] is False                            # an admin's disable is kept
