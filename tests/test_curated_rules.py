"""Curated rules: one JSON standard, validated, scoped by allow-listed filters, previewed, audited, admin only."""
from __future__ import annotations

import contextlib
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.models.base import Base

NOW = datetime.now(timezone.utc)
EDR_RULE = {"schema": "open-ctem/curated-rule@1", "name": "EDR: workstations and servers only",
            "check": "ctem_edr_coverage", "scope": {"include": {"device_types": ["workstation", "server"]}}}


@pytest_asyncio.fixture
async def gdb():
    path = tempfile.mktemp(prefix="ctem_rules_", suffix=".db")
    eng = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(eng, expire_on_commit=False)() as s:
        yield s
    await eng.dispose()
    with contextlib.suppress(OSError):
        os.unlink(path)


async def _fleet(db):
    from api.models.device import Device, DeviceType
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    cfg = IntegrationConfig(vendor=Vendor.crowdstrike, name="cs", is_enabled=True, config={})
    db.add(cfg)
    await db.flush()
    db.add(SyncJob(integration_id=str(cfg.id), vendor="crowdstrike", status=SyncStatus.success, started_at=NOW, finished_at=NOW))
    rows = [("desktop001", DeviceType.workstation, True, "Windows 11"), ("server001", DeviceType.server, True, "Ubuntu 24.04"),
            ("switch001", DeviceType.network_device, False, None), ("switch002", DeviceType.network_device, False, "IOS"),
            ("vm001", DeviceType.cloud_instance, False, "Amazon Linux")]
    for h, t, edr, os_ in rows:
        db.add(Device(hostname=h, device_type=t, edr_active=edr, os=os_, last_seen=NOW))
    await db.commit()


def _row(doc):
    from api.models.rules import CuratedRule
    from api.rules.doc import RuleDoc
    d = RuleDoc.model_validate(doc)
    return CuratedRule(id=str(uuid.uuid4()), name=d.name, check_type=d.check, document=d.dump(), version=1), d


@pytest.mark.asyncio
async def test_edr_example_changes_what_the_check_counts(gdb):
    from api.grc.checks import REGISTRY, evaluate
    await _fleet(gdb)
    check = REGISTRY["ctem_edr_coverage"]
    before, _ = await evaluate(gdb, check, {})
    assert before["details"]["active_devices"] == 5 and before["result"] == "fail"
    after, _ = await evaluate(gdb, check, {}, rules=[_row(EDR_RULE)])
    assert after["details"] == {"active_devices": 2, "with_edr": 2, "without_edr": 0, "coverage_pct": 100.0}
    assert after["result"] == "pass" and after["curated_rules"][0]["name"] == EDR_RULE["name"]
    assert after["evidence_data"]["curated_rules"] == after["curated_rules"]  # the evidence says it was scoped


@pytest.mark.asyncio
async def test_exclude_keeps_devices_with_no_os_and_thresholds_move_within_bounds(gdb):
    from api.grc.checks import REGISTRY, evaluate
    await _fleet(gdb)
    check = REGISTRY["ctem_edr_coverage"]
    rule = {**EDR_RULE, "name": "No IOS", "scope": {"exclude": {"os_contains": ["ios"]}}, "thresholds": {"pass_at": 50}}
    body, _ = await evaluate(gdb, check, {}, rules=[_row(rule)])
    assert body["details"]["active_devices"] == 4  # switch001 (no OS) stays; switch002 (IOS) goes
    assert body["thresholds"]["pass_at"] == 50 and body["result"] == "pass"  # 2 of 4 = 50%
    body, _ = await evaluate(gdb, check, {"pass_at": "90"}, rules=[_row(rule)])
    assert body["thresholds"]["pass_at"] == 90  # an explicit caller parameter still wins


@pytest.mark.parametrize("doc,msg", [
    ({**EDR_RULE, "check": "ctem_shadow_ai"}, "can't be scoped by device"),
    ({**EDR_RULE, "check": "ctem_nope"}, "unknown check"),
    ({**EDR_RULE, "scope": {"include": {"device_types": ["toaster"]}}}, "device_types"),
    ({**EDR_RULE, "scope": {"include": {"sql": "1=1"}}}, "Extra inputs"),
    ({**EDR_RULE, "scope": {"include": {"sources": ["evil'--"]}}}, "unknown source"),
    ({**EDR_RULE, "scope": {"include": {"hostname_patterns": ["a%b"]}}}, "hostname_patterns"),
    ({**EDR_RULE, "scope": {}, "thresholds": {}}, "needs a scope or a threshold"),
    ({**EDR_RULE, "thresholds": {"pass_at": 500}}, "between"),
    ({**EDR_RULE, "schema": "something-else"}, "schema"),
])
def test_rule_validation(doc, msg):
    from pydantic import ValidationError

    from api.rules.doc import RuleDoc
    with pytest.raises(ValidationError) as exc:
        RuleDoc.model_validate(doc)
    assert msg in str(exc.value)


@pytest.mark.asyncio
async def test_glob_and_like_characters_are_literal(gdb):
    from sqlalchemy import func

    from api.models.device import Device
    from api.rules.apply import rule_clause
    await _fleet(gdb)
    _r, doc = _row({**EDR_RULE, "scope": {"include": {"hostname_patterns": ["switch00?", "desk*"]}}})
    hosts = (await gdb.execute(select(Device.hostname).where(rule_clause(doc)).order_by(Device.hostname))).scalars().all()
    assert hosts == ["desktop001", "switch001", "switch002"]
    _r, doc = _row({**EDR_RULE, "scope": {"include": {"os_contains": ["%"]}}})
    assert (await gdb.execute(select(func.count()).select_from(Device).where(rule_clause(doc)))).scalar_one() == 0


@pytest.mark.asyncio
async def test_api_admin_only_validate_preview_save_conflict_audit(client_admin, client_cyber, db):
    from api.models.settings import AuditLog
    assert (await client_cyber.get("/api/v1/rules")).status_code == 403
    assert (await client_cyber.post("/api/v1/rules", json={"document": EDR_RULE})).status_code == 403
    schema = (await client_admin.get("/api/v1/rules/schema")).json()
    assert schema["$id"] == "open-ctem/curated-rule@1" and schema["x-checks"]["ctem_edr_coverage"]["device_scoped"]

    bad = (await client_admin.post("/api/v1/rules/validate", json={"document": {**EDR_RULE, "check": "ctem_nope"}})).json()
    assert bad["valid"] is False and any("unknown check" in e for e in bad["errors"])
    pv = (await client_admin.post("/api/v1/rules/preview", json={"document": EDR_RULE})).json()
    assert {"before", "after", "devices"} <= set(pv) and pv["devices"]["total"] >= pv["devices"]["in_scope"]

    name = f"pass at 70 {uuid.uuid4().hex[:6]}"
    first = {**EDR_RULE, "name": name, "scope": {}, "thresholds": {"pass_at": 70}}
    r = await client_admin.post("/api/v1/rules", json={"document": first})
    assert r.status_code == 201 and r.json()["measured"]["result"]
    rid = r.json()["id"]
    from api.models.grc import GrcCheckResult
    # saving re-measured the check, so the GRC page shows the rule's effect now
    assert (await db.execute(select(GrcCheckResult).where(GrcCheckResult.check_type == "ctem_edr_coverage"))).scalars().first()
    clash = {**first, "name": "other", "thresholds": {"pass_at": 80}}
    assert (await client_admin.post("/api/v1/rules/validate", json={"document": clash})).json()["valid"] is False
    assert (await client_admin.post("/api/v1/rules", json={"document": clash})).status_code == 409
    up = (await client_admin.put(f"/api/v1/rules/{rid}", json={"document": {**first, "thresholds": {"pass_at": 75}}})).json()
    assert up["version"] == 2
    assert (await client_admin.put(f"/api/v1/rules/{rid}/enabled", json={"enabled": False})).json()["enabled"] is False
    assert (await client_admin.delete(f"/api/v1/rules/{rid}")).status_code == 204
    acts = (await db.execute(select(AuditLog.action).where(AuditLog.resource_id == rid))).scalars().all()
    assert {"rule.create", "rule.update", "rule.disable", "rule.delete"} <= set(acts)


@pytest.mark.asyncio
async def test_ai_draft_without_ai_and_with_untrusted_reply(client_admin, monkeypatch):
    import api.hunt.ai as hunt_ai

    async def none(_db):
        return None
    monkeypatch.setattr(hunt_ai, "get_ai", none)
    assert (await client_admin.post("/api/v1/rules/draft", json={"text": "EDR only for servers"})).json() == {"available": False}

    class FakeAI:
        async def complete(self, *a, **kw):
            return '```json\n{"schema": "open-ctem/curated-rule@1", "name": "x", "check": "ctem_edr_coverage", "scope": {"include": {"sql": "drop"}}}\n```'

    async def fake(_db):
        return FakeAI()
    monkeypatch.setattr(hunt_ai, "get_ai", fake)
    d = (await client_admin.post("/api/v1/rules/draft", json={"text": "EDR only for servers"})).json()
    assert d["available"] and d["errors"]  # shown for fixing, never saved as-is


@pytest.mark.asyncio
async def test_a_rule_that_stops_validating_blocks_the_check(gdb):
    from api.grc.checks import REGISTRY, evaluate
    from api.models.rules import CuratedRule
    await _fleet(gdb)
    gdb.add(CuratedRule(name="broken", check_type="ctem_edr_coverage", document={"check": "ctem_edr_coverage"}, enabled=True))
    await gdb.commit()
    body, _ = await evaluate(gdb, REGISTRY["ctem_edr_coverage"], {})
    assert body["result"] == "error" and "no longer fits" in body["summary"]


@pytest.mark.parametrize("code,body,expect", [
    (400, '{"error":{"message":"Your credit balance is too low to access the Anthropic API."}}', "out of credit"),
    (401, '{"error":{"message":"invalid x-api-key sk-ant-SECRET"}}', "API key"),
    (429, "{}", "rate limiting"),
    (529, "{}", "trouble"),
    (400, '{"error":{"message":"model: claude-nope"}}', "model"),
])
def test_ai_failures_say_why_without_echoing_the_provider(code, body, expect):
    import httpx

    from api.rules.ai_draft import _why
    req = httpx.Request("POST", "https://ai.example/v1/messages")
    msg = _why(httpx.HTTPStatusError("x", request=req, response=httpx.Response(code, text=body, request=req)))
    assert expect in msg and "SECRET" not in msg and "claude-nope" not in msg
    assert "reach" in _why(httpx.ConnectError("boom"))


@pytest.mark.asyncio
async def test_exclude_leaves_out_a_device_matching_any_condition(gdb):
    from api.grc.checks import REGISTRY, evaluate
    from api.models.device import Device, DeviceType
    from api.rules.ai_draft import _PRINTERS_OUT
    await _fleet(gdb)
    gdb.add_all([Device(hostname="prn001", device_type=DeviceType.unknown, os="Generic Printer", last_seen=NOW),
                 Device(hostname="prn002", device_type=DeviceType.workstation, os="Ricoh MP 2555", last_seen=NOW)])
    await gdb.commit()
    body, _ = await evaluate(gdb, REGISTRY["ctem_edr_coverage"], {}, rules=[_row(_PRINTERS_OUT)])
    # both switches (network_device) and both printers (unknown / mistyped workstation) are left out
    assert body["details"]["active_devices"] == 3 and body["details"]["with_edr"] == 2


def test_source_names_take_any_case_and_common_names():
    from api.rules.doc import RuleDoc
    d = RuleDoc.model_validate({**EDR_RULE, "scope": {"include": {"sources": ["CrowdStrike", "Rapid7 InsightVM", "Defender"]}}})
    assert d.scope.include.sources == ["crowdstrike", "rapid7_insightvm", "msdefender"]


@pytest.mark.asyncio
async def test_contained_devices_can_be_left_out(gdb):
    from api.grc.checks import REGISTRY, evaluate
    from api.models.device import Device, DeviceType
    from api.rules.ai_draft import _NOT_CONTAINED
    await _fleet(gdb)
    gdb.add(Device(hostname="desktop002", device_type=DeviceType.workstation, edr_active=False, edr_contained=True,
                   os="Windows 11", last_seen=NOW))
    await gdb.commit()
    body, _ = await evaluate(gdb, REGISTRY["ctem_edr_coverage"], {}, rules=[_row(_NOT_CONTAINED)])
    # desktop002 is isolated mid-incident: not counted; desktop001 / server001 (contained unknown) still are
    assert body["details"]["active_devices"] == 2 and body["details"]["coverage_pct"] == 100.0


@pytest.mark.asyncio
async def test_exclude_blocks_need_every_condition_of_one_block(gdb):
    from api.grc.checks import REGISTRY, evaluate
    from api.models.device import Device, DeviceType
    from api.rules.ai_draft import _SCAN_GHOSTS
    await _fleet(gdb)
    old = NOW - timedelta(days=12)
    gdb.add_all([
        Device(hostname="ghost", device_type=DeviceType.workstation, sources=",rapid7_insightvm,", last_seen=old),
        Device(hostname="r7-fresh", device_type=DeviceType.workstation, sources=",rapid7_insightvm,", last_seen=NOW),
        Device(hostname="both-old", device_type=DeviceType.workstation, sources=",crowdstrike,rapid7_insightvm,",
               last_seen=old)])
    await gdb.commit()
    body, out = await evaluate(gdb, REGISTRY["ctem_edr_coverage"], {}, detail=True, rules=[_row(_SCAN_GHOSTS)])
    left = {r["hostname"].lower() for r in out.rows}
    # only the stale scanner-only record goes; scanner-only but fresh, and stale but EDR-reported, stay
    assert "ghost" not in left and {"r7-fresh", "both-old"} <= left
    assert body["details"]["active_devices"] == 7


@pytest.mark.asyncio
async def test_os_starts_with_matches_only_the_start(gdb):
    from api.grc.checks import REGISTRY, evaluate
    from api.models.device import Device, DeviceType
    await _fleet(gdb)
    gdb.add_all([Device(hostname="esx001", device_type=DeviceType.server, os="VMware ESXi Server 8.0.3", last_seen=NOW),
                 Device(hostname="lnx001", device_type=DeviceType.server, os="Ubuntu on VMware ESXi", last_seen=NOW)])
    await gdb.commit()
    rule = {**EDR_RULE, "scope": {"exclude": {"os_starts_with": ["vmware esxi"]}}}
    body, _ = await evaluate(gdb, REGISTRY["ctem_edr_coverage"], {}, rules=[_row(rule)])
    # esx001 is left out (case-insensitive start); lnx001 only contains the words, so it still counts
    assert body["details"]["active_devices"] == 6


@pytest.mark.asyncio
async def test_ai_draft_note_is_shown_not_saved(client_admin, monkeypatch):
    import json

    import api.hunt.ai as hunt_ai

    class FakeAI:
        async def complete(self, *a, **kw):
            return json.dumps({**EDR_RULE, "scope": {"exclude": {"os_starts_with": ["VMware ESXi"]}},
                               "note": "Matched the OS name\nfrom its start."})

    async def fake(_db):
        return FakeAI()
    monkeypatch.setattr(hunt_ai, "get_ai", fake)
    d = (await client_admin.post("/api/v1/rules/draft", json={"text": "ESXi out of EDR coverage"})).json()
    assert d["errors"] == [] and "note" not in d["document"] and d["note"] == "Matched the OS name from its start."
