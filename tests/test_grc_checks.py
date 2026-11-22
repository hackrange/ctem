"""CTEM control checks: grading, stale-data rule, thresholds, signed reports, history, access."""
from __future__ import annotations

import base64
import contextlib
import os
import tempfile
import uuid
from datetime import date, datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.grc.checks import REGISTRY, evaluate
from api.models.base import Base

NOW = datetime.now(timezone.utc)


@pytest_asyncio.fixture
async def gdb():
    """A private database so device and user counts are exact."""
    path = tempfile.mktemp(prefix="ctem_grc_", suffix=".db")
    eng = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(eng, expire_on_commit=False)() as s:
        yield s
    await eng.dispose()
    with contextlib.suppress(OSError):
        os.unlink(path)


async def _source(db, vendor: str, hours_ago: float = 1):
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    cfg = IntegrationConfig(vendor=Vendor(vendor), name=vendor, is_enabled=True, config={})
    db.add(cfg)
    await db.flush()
    at = NOW - timedelta(hours=hours_ago)
    db.add(SyncJob(integration_id=str(cfg.id), vendor=vendor, status=SyncStatus.success, started_at=at, finished_at=at))
    await db.commit()


def _device(**kw):
    from api.models.device import Device, DeviceType
    return Device(hostname=kw.pop("hostname", f"server{uuid.uuid4().hex[:5]}"), device_type=DeviceType.server,
                  last_seen=kw.pop("last_seen", NOW), **kw)


def test_catalog_has_every_check_with_bounded_thresholds():
    assert len(REGISTRY) == 21
    for c in REGISTRY.values():
        assert c.check_type.startswith("ctem_") and c.controls and c.version >= 1
        for t in c.thresholds.values():
            assert t.lo <= t.default <= t.hi


@pytest.mark.parametrize("params,msg", [({"bogus": "1"}, "unknown"), ({"pass_at": "x"}, "integer"), ({"pass_at": "101"}, "between")])
def test_threshold_validation(params, msg):
    with pytest.raises(ValueError, match=msg):
        REGISTRY["ctem_edr_coverage"].parse(params)


@pytest.mark.asyncio
async def test_no_source_or_stale_source_is_an_error_never_a_pass(gdb):
    body, _ = await evaluate(gdb, REGISTRY["ctem_edr_coverage"], {})
    assert body["result"] == "error" and "no data source" in body["summary"]
    await _source(gdb, "crowdstrike", hours_ago=72)
    gdb.add(_device(edr_active=True))
    await gdb.commit()
    body, _ = await evaluate(gdb, REGISTRY["ctem_edr_coverage"], {})
    assert body["result"] == "error" and "older than" in body["summary"]
    assert body["data_freshness"]["crowdstrike"]


@pytest.mark.asyncio
async def test_edr_coverage_grades_and_report_rows(gdb):
    await _source(gdb, "crowdstrike")
    gdb.add_all([_device(edr_active=True) for _ in range(9)] + [_device(hostname="server-noedr", edr_active=False),
                _device(edr_active=False, last_seen=NOW - timedelta(days=200))])  # inactive, not counted
    await gdb.commit()
    body, out = await evaluate(gdb, REGISTRY["ctem_edr_coverage"], {}, detail=True)
    assert body["result"] == "warning" and body["details"]["coverage_pct"] == 90.0
    assert [r["hostname"] for r in out.rows] == ["server-noedr"]
    assert "hostname" not in str(body["evidence_data"])  # counts only in the summary evidence
    body, _ = await evaluate(gdb, REGISTRY["ctem_edr_coverage"], {"warn_at": "95"})
    assert body["result"] == "fail"


@pytest.mark.asyncio
async def test_kev_deadline(gdb):
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    await _source(gdb, "qualys")
    d = _device()
    v = Vulnerability(cve_id="CVE-2026-1111", title="Example KEV", source="qualys", is_kev=True, kev_added_date=(NOW - timedelta(days=60)).date())
    gdb.add_all([d, v])
    await gdb.flush()
    gdb.add(Finding(device_id=d.id, vuln_id=v.id, source="qualys", status=FindingStatus.open, first_detected=NOW - timedelta(days=30)))
    await gdb.commit()
    body, _ = await evaluate(gdb, REGISTRY["ctem_kev_remediation"], {})
    assert body["result"] == "fail" and body["details"]["overdue"] == 1
    body, _ = await evaluate(gdb, REGISTRY["ctem_kev_remediation"], {"due_days": "60"})
    assert body["result"] == "warning"
    # Not In Scope: the device's KEV findings stop counting until the exclusion ends
    d.scope_exempt_until = NOW + timedelta(days=10)
    await gdb.commit()
    body, _ = await evaluate(gdb, REGISTRY["ctem_kev_remediation"], {})
    assert body["details"]["open_kev_findings"] == 0 and body["result"] == "pass"


@pytest.mark.asyncio
async def test_privileged_disabled_member_fails(gdb):
    from api.models.user import User
    await _source(gdb, "ldap")
    gdb.add_all([
        User(username="admin1", is_local=False, ad_dn="CN=a1,DC=acme", ad_groups=["CN=Domain Admins,CN=Users,DC=acme"],
             ad_last_logon=NOW),
        User(username="leaver", is_local=False, ad_dn="CN=l,DC=acme", ad_disabled=True,
             ad_groups=["CN=Enterprise Admins,CN=Users,DC=acme"]),
    ])
    await gdb.commit()
    body, out = await evaluate(gdb, REGISTRY["ctem_privileged_accounts"], {}, detail=True)
    assert body["result"] == "fail" and body["details"]["privileged_disabled"] == 1
    assert {r["account"] for r in out.rows} == {"admin1", "leaver"}


@pytest.mark.asyncio
async def test_expired_exception_fails_and_internal_checks_need_no_source(gdb):
    from api.models.risk import RiskException
    gdb.add(RiskException(cve_id="CVE-2026-2222", reason="vendor fix pending", approved_by="admin", approved_at=NOW,
                          expires_at=NOW - timedelta(days=1)))
    await gdb.commit()
    body, _ = await evaluate(gdb, REGISTRY["ctem_risk_exceptions"], {})
    assert body["result"] == "fail" and body["data_freshness"] == {}


@pytest.mark.asyncio
async def test_run_all_records_every_check_and_history_rolls_up(gdb):
    from api.grc.evidence import history, run_all
    from api.models.grc import GrcCheckResult
    results = await run_all(gdb)
    assert set(results) == set(REGISTRY)
    gdb.add(GrcCheckResult(check_type="ctem_edr_coverage", check_version=1, result="fail", summary="x",
                           measured_at=NOW - timedelta(days=3)))
    await gdb.commit()
    h = await history(gdb, "ctem_edr_coverage", (NOW - timedelta(days=5)).date(), NOW.date())
    assert h["days_in_window"] == 6 and h["days_measured"] == 2 and h["tally"]["fail"] == 1
    assert (NOW - timedelta(days=3)).date().isoformat() in h["failing_dates"]
    with pytest.raises(ValueError):
        await history(gdb, "ctem_edr_coverage", date(2024, 1, 1), date(2026, 1, 1))


# ── HTTP: access, validation, signed reports ──────────────────────────────────

@pytest.mark.asyncio
async def test_catalog_and_errors_over_http(client_cyber, client_it_user):
    r = await client_cyber.get("/api/v1/grc/checks")
    assert r.status_code == 200 and len(r.json()["checks"]) == 21
    assert (await client_cyber.get("/api/v1/grc/checks/ctem_nope")).status_code == 404
    assert (await client_cyber.get("/api/v1/grc/checks/ctem_edr_coverage?pass_at=500")).status_code == 400
    assert (await client_cyber.get("/api/v1/grc/checks/ctem_edr_coverage?pass_at=90&pass_at=91")).status_code == 400
    assert (await client_it_user.get("/api/v1/grc/checks")).status_code == 403
    r = await client_cyber.get("/api/v1/grc/checks/ctem_risk_exceptions")
    assert r.status_code == 200 and r.json()["result"] in ("pass", "warning", "fail")


@pytest.mark.asyncio
async def test_grc_integration_role_reads_checks_but_nothing_else(db):
    from tests.conftest import _authed_client, _make_user

    from api.main import create_app
    user = await _make_user(db, "grc_integration")
    async with _authed_client(create_app(), db, user) as c:
        assert (await c.get("/api/v1/grc/checks")).status_code == 200
        assert (await c.get("/api/v1/grc/evidence-key")).status_code == 200
        assert (await c.post("/api/v1/grc/exceptions", json={"cve_id": "CVE-2026-1", "reason": "x" * 12})).status_code == 403


@pytest.mark.asyncio
async def test_report_is_signed_formula_safe_and_audited(client_cyber, db):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from sqlalchemy import select

    from api.models.risk import RiskException
    from api.models.settings import AuditLog
    db.add(RiskException(cve_id="=HYPERLINK(1)", reason="formula probe", approved_by="admin", approved_at=NOW,
                         expires_at=NOW - timedelta(days=1)))
    await db.commit()
    key = (await client_cyber.get("/api/v1/grc/evidence-key")).json()
    r = await client_cyber.get("/api/v1/grc/checks/ctem_risk_exceptions/report?format=csv")
    assert r.status_code == 200 and r.headers["x-ctem-evidence-kid"] == key["kid"]
    Ed25519PublicKey.from_public_bytes(base64.b64decode(key["public_key"])).verify(
        base64.b64decode(r.headers["x-ctem-evidence-signature"]), r.content)
    assert "'=HYPERLINK(1)" in r.text and "\n=HYPERLINK" not in r.text and ",=HYPERLINK" not in r.text
    assert r.text.startswith("# generated_at:")
    j = await client_cyber.get("/api/v1/grc/checks/ctem_risk_exceptions/report?format=json")
    assert j.json()["meta"]["check_type"] == "ctem_risk_exceptions"
    assert (await client_cyber.get("/api/v1/grc/checks/ctem_risk_exceptions/report?format=xml")).status_code == 400
    logged = (await db.execute(select(AuditLog).where(AuditLog.action == "grc_evidence_report"))).scalars().all()
    assert logged


@pytest.mark.asyncio
async def test_fairtprm_service_token(client_admin, client_cyber, client):
    assert (await client_cyber.post("/api/v1/grc/fairtprm-token", json={"allowed_ips": ["127.0.0.1"]})).status_code == 403
    assert (await client_admin.post("/api/v1/grc/fairtprm-token", json={"allowed_ips": ["0.0.0.0/0"]})).status_code == 422
    assert (await client_admin.post("/api/v1/grc/fairtprm-token", json={"allowed_ips": []})).status_code == 422
    first = (await client_admin.post("/api/v1/grc/fairtprm-token", json={"allowed_ips": ["127.0.0.1"]})).json()
    h = {"Authorization": f"Bearer {first['token']}"}
    assert (await client.get("/api/v1/grc/checks", headers=h)).status_code == 200
    assert (await client.get("/api/v1/grc/checks/ctem_monitoring_health", headers=h)).status_code == 200
    assert (await client.get("/api/v1/devices", headers=h)).status_code == 403  # GRC read only
    assert (await client.post("/api/v1/grc/exceptions", headers=h, json={"cve_id": "CVE-2026-1", "reason": "x" * 12})).status_code == 403
    second = (await client_admin.post("/api/v1/grc/fairtprm-token", json={"allowed_ips": ["127.0.0.1"]})).json()
    assert (await client.get("/api/v1/grc/checks", headers=h)).status_code == 401  # replaced
    assert (await client.get("/api/v1/grc/checks", headers={"Authorization": f"Bearer {second['token']}"})).status_code == 200
    assert (await client_admin.delete("/api/v1/grc/fairtprm-token")).json()["revoked"] == 1


@pytest.mark.asyncio
async def test_fairtprm_token_ip_binding(client_admin, client):
    tok = (await client_admin.post("/api/v1/grc/fairtprm-token", json={"allowed_ips": ["198.51.100.20"]})).json()["token"]
    assert (await client.get("/api/v1/grc/checks", headers={"Authorization": f"Bearer {tok}"})).status_code == 401


@pytest.mark.asyncio
async def test_no_exposure_data_is_not_a_pass(gdb):
    await _source(gdb, "qualys")
    gdb.add(_device())
    await gdb.commit()
    body, _ = await evaluate(gdb, REGISTRY["ctem_exposed_criticals"], {})
    assert body["result"] == "error"


@pytest.mark.asyncio
async def test_stale_tool_records_flags_machines_no_tool_has_seen(gdb):
    await _source(gdb, "rapid7_insightvm")
    old = NOW - timedelta(days=60)
    gdb.add_all([_device(sources=",rapid7_insightvm,crowdstrike,", edr_last_seen=NOW) for _ in range(48)]
                + [_device(hostname="ghost-r7", sources=",rapid7_insightvm,", last_seen=old),
                   _device(hostname="ghost-cs-ad", sources=",crowdstrike,ldap,", last_seen=None, edr_last_seen=old,
                           ad_last_logon=old),
                   # an old scan but a fresh EDR heartbeat is alive, not stale
                   _device(hostname="alive-edr", sources=",rapid7_insightvm,crowdstrike,", last_seen=old, edr_last_seen=NOW)])
    await gdb.commit()
    body, out = await evaluate(gdb, REGISTRY["ctem_stale_tool_records"], {}, detail=True)
    d = body["details"]
    assert (d["records"], d["stale"], d["stale_in_scanner"], d["stale_in_edr"], d["stale_in_directory"]) == (51, 2, 1, 1, 1)
    assert body["result"] == "fail" and "scanner 1, EDR 1, directory 1" in body["summary"]   # 3.9% is over 2%
    rows = {r["hostname"]: r for r in out.rows}
    assert set(rows) == {"ghost-r7", "ghost-cs-ad"} and rows["ghost-cs-ad"]["still_in"] == "CS AD"
    assert rows["ghost-cs-ad"]["scanner_last_seen"] == "never"
    body, _ = await evaluate(gdb, REGISTRY["ctem_stale_tool_records"], {"fail_pct": "5"})
    assert body["result"] == "warning"


@pytest.mark.asyncio
async def test_orphan_ad_computers_only_counts_ad_only_objects(gdb):
    from api.models.device import DeviceType
    await _source(gdb, "ldap")
    old = NOW - timedelta(days=40)
    gdb.add_all([_device(sources=",ldap,", ad_joined=True, ad_last_logon=NOW, last_seen=None) for _ in range(18)]
                + [_device(hostname="orphan", sources=",ldap,", ad_joined=True, ad_last_logon=old, last_seen=None,
                           ad_dn="CN=orphan,OU=Workstations,DC=acme,DC=example"),
                   _device(hostname="in-r7-too", sources=",ldap,rapid7_insightvm,", ad_joined=True, ad_last_logon=old)])
    for d in gdb.new:
        d.device_type = DeviceType.workstation
    await gdb.commit()
    body, out = await evaluate(gdb, REGISTRY["ctem_orphan_ad_computers"], {}, detail=True)
    assert (body["details"]["ad_computers"], body["details"]["orphaned"]) == (20, 1)
    assert [r["hostname"] for r in out.rows] == ["orphan"] and out.rows[0]["ad_dn"].startswith("CN=orphan")
    assert body["result"] == "fail"   # 5% is over the 2% default


@pytest.mark.asyncio
async def test_edr_silent_and_scan_gap(gdb):
    await _source(gdb, "crowdstrike")
    await _source(gdb, "rapid7_insightvm")
    quiet = NOW - timedelta(days=30)
    gdb.add_all([_device(edr_last_seen=NOW, last_seen=NOW) for _ in range(8)]
                + [_device(hostname="edr-quiet", edr_last_seen=quiet, last_seen=NOW, edr_hidden=True),
                   _device(hostname="never-edr", edr_last_seen=None, last_seen=NOW),        # EDR coverage's job, not this
                   _device(hostname="scan-stale", edr_last_seen=NOW, last_seen=quiet),
                   _device(hostname="never-scanned", ad_last_logon=NOW, last_seen=None)])
    await gdb.commit()
    body, out = await evaluate(gdb, REGISTRY["ctem_edr_silent_on_network"], {}, detail=True)
    assert body["details"]["edr_silent"] == 1 and [r["hostname"] for r in out.rows] == ["edr-quiet"]
    assert out.rows[0]["edr_hidden"] == "yes"
    body, out = await evaluate(gdb, REGISTRY["ctem_scan_gap"], {}, detail=True)
    d = body["details"]
    assert (d["scan_gap"], d["never_scanned"]) == (2, 1)
    assert {r["hostname"] for r in out.rows} == {"scan-stale", "never-scanned"}



@pytest.mark.asyncio
async def test_hygiene_checks_work_with_any_vendor(gdb):
    """Written per tool category: SentinelOne for EDR and Qualys for scanning count like CrowdStrike and Rapid7."""
    await _source(gdb, "sentinelone")
    await _source(gdb, "qualys")
    old = NOW - timedelta(days=40)
    gdb.add_all([_device(sources=",qualys,sentinelone,", edr_last_seen=NOW) for _ in range(9)]
                + [_device(hostname="ghost", sources=",qualys,sentinelone,", last_seen=old, edr_last_seen=old)])
    await gdb.commit()
    body, out = await evaluate(gdb, REGISTRY["ctem_stale_tool_records"], {}, detail=True)
    assert body["details"]["stale"] == 1 and out.rows[0]["still_in"] == "QL S1"
    assert body["result"] != "error"
