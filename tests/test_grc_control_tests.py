"""GRC control testing: attestations, the testing cadence, sending to FairTPRM, and the deprovisioning check."""
from __future__ import annotations

import contextlib
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.core import control_cadence as cad
from api.grc.checks import REGISTRY, evaluate
from api.models.base import Base

NOW = datetime.now(timezone.utc)
GOOD = {"what_tested": "Pulled 25 leavers from HR; checked each AD account was disabled within 24 hours",
        "expected_result": "All 25 disabled within 24 hours", "outcome": "All 25 disabled in time", "result": "pass"}


async def _control(db, risk="high", frequency=None):
    from api.models.grc import GrcControl
    c = GrcControl(source="fairtprm", external_id=str(uuid.uuid4().int % 100000), control_ref=f"IC-{uuid.uuid4().hex[:3]}",
                   title="Automated Deprovision of Account Triggers", risk_level=risk, frequency=frequency, is_active=True)
    db.add(c)
    await db.commit()
    return c


def test_cadence_order():
    rules = cad.clean({"by_risk": {"high": 60}, "default_days": 200, "controls": {"c1": 14}, "use_control_frequency": True})
    S = SimpleNamespace
    assert cad.interval(rules, S(id="c1", frequency="monthly", risk_level="high")) == (14, "set for this control")
    assert cad.interval(rules, S(id="c2", frequency="Quarterly", risk_level="high"))[0] == 90
    assert cad.interval(rules, S(id="c3", frequency=None, risk_level="High"))[0] == 60
    assert cad.interval(rules, S(id="c4", frequency=None, risk_level=None)) == (200, "the default")
    off = cad.clean({**rules, "use_control_frequency": False})
    assert cad.interval(off, S(id="c2", frequency="quarterly", risk_level="high"))[0] == 60
    d = cad.due(rules, S(id="c3", frequency=None, risk_level="high"), NOW - timedelta(days=70))
    assert d["overdue"] and d["days_left"] < 0
    assert cad.due(rules, S(id="c3", frequency=None, risk_level="high"), None)["overdue"]   # never tested


@pytest.mark.asyncio
async def test_record_a_test_and_see_it(db, client_admin, client_it_user, client_read_only, admin_user):
    c = await _control(db)
    url = f"/api/v1/grc/controls/{c.id}/tests"
    first = (await client_admin.get(url)).json()
    assert first["testing"]["overdue"] and first["testing"]["interval_days"] == 90 and first["can_test"]
    r = (await client_admin.post(url, json=GOOD)).json()
    assert r["ok"] and r["test"]["tested_by"].startswith(admin_user.username) and r["fairtprm"]["status"] == "not_connected"
    seen = (await client_read_only.get(url)).json()
    assert seen["can_test"] is False and seen["tests"][0]["what_tested"] == GOOD["what_tested"]
    assert seen["testing"]["overdue"] is False and seen["testing"]["last_result"] == "pass"
    assert seen["testing"]["next_due"] == (NOW + timedelta(days=90)).date().isoformat()
    listed = (await client_admin.get("/api/v1/grc/controls")).json()["controls"]
    assert next(x for x in listed if x["id"] == str(c.id))["testing"]["last_result"] == "pass"
    # a fail needs its reason, and it makes the control ineffective
    bad = {**GOOD, "result": "fail", "outcome": "1 of 25 disabled 3 days late"}
    assert (await client_admin.post(url, json=bad)).status_code == 422
    assert (await client_admin.post(url, json={**bad, "failure_reason": "The HR feed was down for 3 days"})).json()["ok"]
    assert (await client_admin.get(url)).json()["control"]["effectiveness"] == "ineffective"
    # who may record, and what is accepted
    assert (await client_read_only.post(url, json=GOOD)).status_code in (403, 404)
    assert (await client_it_user.get(url)).status_code in (403, 404)
    assert (await client_admin.post(url, json={**GOOD, "tested_at": (NOW + timedelta(days=5)).isoformat()})).status_code == 422
    assert (await client_admin.post(url, json={**GOOD, "tested_by": "someone else"})).status_code == 422   # it's always you
    assert (await client_admin.post(url, json={**GOOD, "what_tested": "x\x00y"})).status_code == 422
    assert (await client_admin.get(f"/api/v1/grc/controls/{uuid.uuid4()}/tests")).status_code == 404


class _Resp:
    def __init__(self, code):
        self.status_code = code


class _Client:
    """Stands in for FairTPRM: POST /tests answers `post`, PUT /controls answers `put`."""
    calls: list = []

    def __init__(self, post, put=200):
        self.post_code, self.put_code = post, put

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, headers=None, json=None):
        _Client.calls.append(("POST", url, json))
        return _Resp(self.post_code)

    async def put(self, url, headers=None, json=None):
        _Client.calls.append(("PUT", url, json))
        return _Resp(self.put_code)


@pytest.mark.asyncio
async def test_sending_to_fairtprm(db, client_admin, monkeypatch):
    from api.models.integration import IntegrationConfig, Vendor
    db.add(IntegrationConfig(vendor=Vendor.fairtprm, name="FairTPRM", is_enabled=True,
                             config={"base_url": "https://tprm.acme.example", "api_key": "k"}))
    await db.commit()
    c = await _control(db)
    url = f"/api/v1/grc/controls/{c.id}/tests"
    for post, put, want in ((201, 200, "sent"), (404, 200, "summary"), (403, 200, "failed"), (404, 403, "failed")):
        _Client.calls = []
        monkeypatch.setattr("api.core.ssrf.safe_client", lambda **kw: _Client(post, put))
        r = (await client_admin.post(url, json=GOOD)).json()
        assert r["fairtprm"]["status"] == want, (post, put, r)
        method, target, body = _Client.calls[0]
        assert target == f"https://tprm.acme.example/api/v2/grc/controls/{int(c.external_id)}/tests"
        assert body["source"] == "open-ctem" and body["result"] == "pass" and body["external_ref"] == r["test"]["id"]
        if post == 404:
            assert _Client.calls[1][0] == "PUT" and _Client.calls[1][2]["effectiveness"] == "effective"
    assert "read-only" in r["fairtprm"]["detail"]
    # send again, once FairTPRM is fixed
    monkeypatch.setattr("api.core.ssrf.safe_client", lambda **kw: _Client(200))
    again = (await client_admin.post(f"/api/v1/grc/control-tests/{r['test']['id']}/send")).json()
    assert again["ok"] and again["fairtprm"]["status"] == "sent"
    await db.execute(IntegrationConfig.__table__.delete().where(IntegrationConfig.vendor == Vendor.fairtprm))
    await db.commit()


@pytest.mark.asyncio
async def test_testing_rules_are_admin_only(db, client_admin, client_cyber):
    c = await _control(db, risk="low")
    body = {"by_risk": {"critical": 14, "high": 60, "medium": 120, "low": 365}, "default_days": 365,
            "use_control_frequency": True, "controls": {str(c.id): 7}}
    assert (await client_cyber.put("/api/v1/grc/test-cadence", json=body)).status_code in (403, 404)
    r = (await client_admin.put("/api/v1/grc/test-cadence", json=body)).json()
    assert r["ok"] and r["rules"]["controls"][str(c.id)] == 7
    assert (await client_admin.get(f"/api/v1/grc/controls/{c.id}/tests")).json()["testing"]["interval_days"] == 7
    assert (await client_admin.put("/api/v1/grc/test-cadence", json={**body, "default_days": 0})).status_code == 422
    assert (await client_admin.put("/api/v1/grc/test-cadence", json={**body, "controls": {"nope": 7}})).json()["ok"] is False
    assert (await client_cyber.get("/api/v1/grc/test-cadence")).json()["can_edit"] is False
    await client_admin.put("/api/v1/grc/test-cadence", json={"by_risk": {}, "default_days": 365})


@pytest_asyncio.fixture
async def gdb():
    path = tempfile.mktemp(prefix="ctem_deprov_", suffix=".db")
    eng = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(eng, expire_on_commit=False)() as s:
        yield s
    await eng.dispose()
    with contextlib.suppress(OSError):
        os.unlink(path)


@pytest.mark.asyncio
async def test_deprovisioning_check(gdb):
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    from api.models.user import User
    cfg = IntegrationConfig(vendor=Vendor("ldap"), name="ldap", is_enabled=True, config={})
    gdb.add(cfg)
    await gdb.flush()
    gdb.add(SyncJob(integration_id=str(cfg.id), vendor="ldap", status=SyncStatus.success, started_at=NOW, finished_at=NOW))
    old = (NOW - timedelta(days=900)).replace(tzinfo=None)
    for name, dn, disabled, groups, days in (
            ("gone", "CN=gone,OU=Disabled Users,DC=acme", True, ["CN=Domain Users,CN=Users,DC=acme", "CN=Finance,OU=Groups,DC=acme"], 400),
            ("clean", "CN=clean,OU=Disabled Users,DC=acme", True, ["CN=Domain Users,CN=Users,DC=acme"], 400),
            ("moved", "CN=moved,OU=Terminated,OU=People,DC=acme", False, [], 5),
            ("stale", "CN=stale,OU=People,DC=acme", False, [], 200),
            ("active", "CN=active,OU=People,DC=acme", False, ["CN=Finance,OU=Groups,DC=acme"], 3)):
        gdb.add(User(username=name, ad_username=name, is_local=False, ad_dn=dn, ad_disabled=disabled, ad_groups=groups,
                     ad_last_logon=NOW - timedelta(days=days), created_at=old))
    await gdb.commit()
    body, out = await evaluate(gdb, REGISTRY["ctem_deprovisioning"], {}, detail=True)
    d = body["details"]
    assert (d["disabled_still_in_groups"], d["enabled_in_leaver_ou"], d["enabled_idle"]) == (1, 1, 1)
    assert body["result"] == "fail"
    issues = {(r["account"], r["issue"]) for r in out.rows}
    assert issues == {("gone", "disabled, still in groups"), ("moved", "enabled in a leaver OU"),
                      ("stale", "enabled, no logon in 90 days")}
    assert next(r for r in out.rows if r["account"] == "gone")["detail"] == "Finance"
    only = (await evaluate(gdb, REGISTRY["ctem_deprovisioning"], {"include_idle": "0"}))[0]["details"]
    assert only["enabled_idle"] is None and "no logon" not in (await evaluate(gdb, REGISTRY["ctem_deprovisioning"], {"include_idle": "0"}))[0]["summary"]


@pytest.mark.asyncio
async def test_due_checks_are_the_missing_and_the_day_old(db):
    from api.grc.evidence import due_checks
    from api.models.grc import GrcCheckResult
    from sqlalchemy import delete
    await db.execute(delete(GrcCheckResult))
    db.add(GrcCheckResult(check_type="ctem_edr_coverage", check_version=1, result="pass", summary="x", measured_at=NOW))
    db.add(GrcCheckResult(check_type="ctem_vuln_sla", check_version=1, result="pass", summary="x", measured_at=NOW - timedelta(hours=30)))
    await db.commit()
    due = await due_checks(db)
    assert "ctem_edr_coverage" not in due and "ctem_vuln_sla" in due and "ctem_vuln_age" in due   # day-old and never run


@pytest.mark.asyncio
async def test_run_schedule(db, client_admin, client_cyber):
    from api.grc.evidence import due_checks
    from api.models.grc import GrcCheckResult
    from sqlalchemy import delete
    await db.execute(delete(GrcCheckResult))
    db.add(GrcCheckResult(check_type="ctem_vuln_sla", check_version=1, result="pass", summary="x", measured_at=NOW - timedelta(hours=3)))
    await db.commit()
    assert "ctem_vuln_sla" not in await due_checks(db)                       # daily by default: 3 hours is fine
    assert (await client_cyber.put("/api/v1/grc/check-schedule", json={"default_hours": 1})).status_code in (403, 404)
    r = (await client_admin.put("/api/v1/grc/check-schedule", json={"default_hours": 24, "checks": {"ctem_vuln_sla": 2}})).json()
    assert r["ok"] and r["rules"]["checks"] == {"ctem_vuln_sla": 2}
    assert "ctem_vuln_sla" in await due_checks(db)                           # now every 2 hours: it's due
    got = (await client_cyber.get("/api/v1/grc/check-schedule")).json()
    assert got["can_edit"] is False and next(c for c in got["checks"] if c["check_type"] == "ctem_vuln_sla")["hours"] == 2
    assert (await client_admin.put("/api/v1/grc/check-schedule", json={"default_hours": 3})).status_code == 422
    assert (await client_admin.put("/api/v1/grc/check-schedule", json={"default_hours": 24, "checks": {"ctem_nope": 1}})).json()["ok"] is False
    await client_admin.put("/api/v1/grc/check-schedule", json={"default_hours": 24})
