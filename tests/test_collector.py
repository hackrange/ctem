"""Shippers: profiles, enrollment with a box key, sealed secrets, approvals, scoped push ingest."""
from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))
import collector_common as cc  # noqa: E402
import collector_crypto as crypto  # noqa: E402

_KEY = crypto.new_identity()  # one RSA-3072 pair for the whole module; generating is slow
LDAP = {"ldap": {"settings": {"host": "dc001.acme.example", "bind_user": "ACME\\svc-ctem"}}}


def _code_from(script: str) -> str:
    return next(ln for ln in script.splitlines() if ln.startswith("ENROLL_CODE=")).split("'")[1]


async def _profile(client_admin, modules=None, name=None):
    r = await client_admin.post("/api/v1/collectors", json={
        "name": name or f"srv-{uuid.uuid4().hex[:6]}", "schedule_minutes": 60, "modules": modules or LDAP})
    assert r.status_code == 201, r.text
    return r.json()


async def _enroll(client, client_admin, modules=None, cidrs=None):
    p = await _profile(client_admin, modules)
    r = await client_admin.post(f"/api/v1/collectors/{p['id']}/installer", json={"allowed_cidrs": cidrs or []})
    assert r.status_code == 200
    code = _code_from(r.text)
    r = await client.post("/api/v1/collector/enroll", json={
        "code": code, "hostname": "server001", "agent_version": "1.0.1", "public_key": _KEY[1]})
    return p, r, code


def _auth(tok):
    return {"Authorization": f"Bearer {tok}"}


def _checkin(**extra):
    return {"hostname": "server001", "agent_version": "1.0.1", **extra}


# ── installer ─────────────────────────────────────────────────────────────────

def test_rendered_installer_is_valid_bash_and_fully_filled():
    from api.collector.installer import render_installer
    script = render_installer("https://ctem.acme.example", "a" * 64, "server001")
    assert "@@EMBEDDED_FILES@@" not in script and "@@CTEM_URL@@" not in script
    assert "CTEM_URL_DEFAULT='https://ctem.acme.example'" in script
    subprocess.run(["bash", "-n"], input=script.encode(), check=True)


@pytest.mark.parametrize("url,code,name", [
    ("http://ctem.acme.example", "", ""),
    ("https://ctem.acme.example/'; rm -rf /", "", ""),
    ("https://ctem.acme.example", "zz", ""),
    ("https://ctem.acme.example", "", "bad name'"),
])
def test_installer_refuses_values_that_could_break_out_of_bash(url, code, name):
    from api.collector.installer import render_installer
    with pytest.raises(ValueError):
        render_installer(url, code, name)


# ── profiles (admin) ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_profiles_are_admin_only(client_cyber):
    assert (await client_cyber.get("/api/v1/collectors")).status_code == 403
    assert (await client_cyber.post("/api/v1/collectors", json={"name": "x", "modules": LDAP})).status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("modules", [
    {"ldap": {"settings": {"host": "bad host!", "bind_user": "x"}}},
    {"ldap": {"settings": {"host": "dc001", "bind_user": "x", "surprise": 1}}},
    {"nope": {"settings": {}}},
    {"crowdstrike": {"settings": {"client_id": "not-hex"}}},
])
async def test_profile_settings_are_validated(client_admin, modules):
    r = await client_admin.post("/api/v1/collectors", json={"name": "bad", "modules": modules})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_profile_creates_collector_mode_integrations(client_admin, db):
    from api.models.integration import IntegrationConfig
    p = await _profile(client_admin)
    iid = p["modules"]["ldap"]["integration_id"]
    cfg = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == iid))).scalar_one()
    assert cfg.config["mode"] == "collector" and p["modules"]["ldap"]["approval"] == "not enrolled"


# ── enrollment ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enroll_binds_key_and_ip_and_code_is_single_use(client, client_admin, db):
    from api.models.collector import CollectorToken
    p, r, code = await _enroll(client, client_admin)
    assert r.status_code == 200
    body = r.json()
    assert body["token"].startswith("occ_") and body["key_fp"] == crypto.fingerprint(_KEY[1])
    tok = (await db.execute(select(CollectorToken).where(CollectorToken.id == body["collector_id"]))).scalar_one()
    assert tok.allowed_ips == ["127.0.0.1"] and body["token"] not in tok.token_hash
    again = await client.post("/api/v1/collector/enroll", json={
        "code": code, "hostname": "server001", "agent_version": "1.0.1", "public_key": _KEY[1]})
    assert again.status_code == 401


@pytest.mark.asyncio
async def test_junk_key_is_refused_without_burning_the_code(client, client_admin):
    p = await _profile(client_admin)
    code = _code_from((await client_admin.post(f"/api/v1/collectors/{p['id']}/installer", json={})).text)
    weak = "-----BEGIN PUBLIC KEY-----\n" + "A" * 300 + "\n-----END PUBLIC KEY-----"
    r = await client.post("/api/v1/collector/enroll", json={"code": code, "hostname": "s1", "agent_version": "1.0.1", "public_key": weak})
    assert r.status_code == 400
    r = await client.post("/api/v1/collector/enroll", json={"code": code, "hostname": "s1", "agent_version": "1.0.1", "public_key": _KEY[1]})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_enroll_outside_allowed_cidr_is_refused(client, client_admin):
    _, r, _ = await _enroll(client, client_admin, cidrs=["198.51.100.0/24"])
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_password_enroll_rejects_bad_password_non_admins_and_missing_mfa(client, db, it_user, admin_user, monkeypatch):
    from api.auth.local import hash_password
    from api.core.config import get_settings
    for u in (it_user, admin_user):
        u.password_hash = hash_password("Correct-Horse-9")
    await db.commit()
    base = {"name": "server002", "hostname": "server002", "agent_version": "1.0.1", "public_key": _KEY[1], "modules": LDAP}
    r = await client.post("/api/v1/collector/enroll-login", json={**base, "username": it_user.username, "password": "nope"})
    assert r.status_code == 401
    r = await client.post("/api/v1/collector/enroll-login", json={**base, "username": it_user.username, "password": "Correct-Horse-9"})
    assert r.status_code == 403
    monkeypatch.setattr(get_settings(), "mfa_required", True)
    r = await client.post("/api/v1/collector/enroll-login", json={**base, "username": admin_user.username, "password": "Correct-Horse-9"})
    assert r.status_code == 403  # MFA required, never set up
    monkeypatch.setattr(get_settings(), "mfa_required", False)
    r = await client.post("/api/v1/collector/enroll-login", json={**base, "username": admin_user.username, "password": "Correct-Horse-9"})
    assert r.status_code == 200 and r.json()["config"]["name"] == "server002"


# ── check-in, approvals, sealed secrets ───────────────────────────────────────

@pytest.mark.asyncio
async def test_checkin_digest_matches_the_agent_and_drives_approval(client, client_admin):
    p, r, _ = await _enroll(client, client_admin)
    tok = r.json()["token"]
    cfg = (await client.post("/api/v1/collector/checkin", headers=_auth(tok), json=_checkin())).json()
    m = cfg["modules"][0]
    assert m["dest_digest"] == cc.dest_digest("ldap", m["settings"])  # server and agent agree byte for byte
    view = (await client_admin.get(f"/api/v1/collectors/{p['id']}")).json()
    assert view["modules"]["ldap"]["approval"] == "pending"
    await client.post("/api/v1/collector/checkin", headers=_auth(tok), json=_checkin(approved={"ldap": m["dest_digest"]}))
    assert (await client_admin.get(f"/api/v1/collectors/{p['id']}")).json()["modules"]["ldap"]["approval"] == "approved"
    # Moving the host in the GUI puts it back to pending until the box says yes
    await client_admin.put(f"/api/v1/collectors/{p['id']}", json={"modules": {"ldap": {"settings": {
        "host": "dc002.acme.example", "bind_user": "ACME\\svc-ctem"}}}})
    assert (await client_admin.get(f"/api/v1/collectors/{p['id']}")).json()["modules"]["ldap"]["approval"] == "pending"


@pytest.mark.asyncio
async def test_sealed_secret_round_trip_and_ctem_never_sees_plaintext(client, client_admin, db):
    from api.models.collector import CollectorSecret
    p, r, _ = await _enroll(client, client_admin)
    tok = r.json()["token"]
    env = crypto.seal(_KEY[1], p["id"], "ldap", "password", "Hunter2-not-real")
    put = await client_admin.put(f"/api/v1/collectors/{p['id']}/secrets",
                                 json={"secrets": [{"kind": "ldap", "field": "password", "envelope": env}]})
    assert put.status_code == 200
    row = (await db.execute(select(CollectorSecret).where(CollectorSecret.profile_id == p["id"]))).scalar_one()
    assert "Hunter2" not in row.envelope
    cfg = (await client.post("/api/v1/collector/checkin", headers=_auth(tok), json=_checkin())).json()
    s = cfg["secrets"][0]
    fp = crypto.fingerprint(_KEY[1])
    assert crypto.unseal(_KEY[0], fp, cfg["profile_id"], s["kind"], s["field"], s["envelope"]) == "Hunter2-not-real"
    with pytest.raises(Exception):  # AAD binds the field, so CTEM can't relabel it as another source's secret
        crypto.unseal(_KEY[0], fp, cfg["profile_id"], "splunk", "password", s["envelope"])


@pytest.mark.asyncio
async def test_secret_rules(client, client_admin):
    p = await _profile(client_admin)
    env = crypto.seal(_KEY[1], p["id"], "ldap", "password", "x")
    url = f"/api/v1/collectors/{p['id']}/secrets"
    assert (await client_admin.put(url, json={"secrets": [{"kind": "ldap", "field": "password", "envelope": env}]})).status_code == 409
    p, _, _ = await _enroll(client, client_admin)
    url = f"/api/v1/collectors/{p['id']}/secrets"
    env = crypto.seal(_KEY[1], p["id"], "ldap", "password", "x")
    other = crypto.new_identity()
    wrong_key = crypto.seal(other[1], p["id"], "ldap", "password", "x")
    for bad in ({"kind": "ldap", "field": "password", "envelope": wrong_key},
                {"kind": "ldap", "field": "token", "envelope": env},
                {"kind": "splunk", "field": "password", "envelope": env},
                {"kind": "ldap", "field": "password", "envelope": "plaintext-pass-123456"}):
        assert (await client_admin.put(url, json={"secrets": [bad]})).status_code == 400


@pytest.mark.asyncio
async def test_box_can_upload_its_own_sealed_secret(client, client_admin):
    p, r, _ = await _enroll(client, client_admin)
    env = crypto.seal(_KEY[1], p["id"], "ldap", "password", "x")
    r2 = await client.put("/api/v1/collector/secrets", headers=_auth(r.json()["token"]),
                          json={"secrets": [{"kind": "ldap", "field": "password", "envelope": env}]})
    assert r2.status_code == 200
    view = (await client_admin.get(f"/api/v1/collectors/{p['id']}")).json()
    assert view["modules"]["ldap"]["secrets"]["password"]["set"] is True


@pytest.mark.asyncio
async def test_dropping_a_source_deletes_its_secrets(client, client_admin, db):
    from api.models.collector import CollectorSecret
    both = {**LDAP, "splunk": {"settings": {"host": "splunk001", "username": "svc"}}}
    p, _, _ = await _enroll(client, client_admin, modules=both)
    env = crypto.seal(_KEY[1], p["id"], "splunk", "password", "x")
    await client_admin.put(f"/api/v1/collectors/{p['id']}/secrets", json={"secrets": [{"kind": "splunk", "field": "password", "envelope": env}]})
    await client_admin.put(f"/api/v1/collectors/{p['id']}", json={"modules": LDAP})
    assert not (await db.execute(select(CollectorSecret).where(CollectorSecret.profile_id == p["id"]))).scalars().all()


@pytest.mark.asyncio
async def test_checkin_errors_and_clean_runs(client, client_admin, db):
    from api.models.integration import IntegrationConfig, SyncStatus
    p, r, _ = await _enroll(client, client_admin)
    tok = r.json()["token"]
    await client.post("/api/v1/collector/checkin", headers=_auth(tok), json=_checkin(errors={"ldap": "bind failed"}))
    cfg = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == p["modules"]["ldap"]["integration_id"]))).scalar_one()
    assert cfg.last_sync_status == SyncStatus.failed
    await client.post("/api/v1/collector/checkin", headers=_auth(tok), json=_checkin())
    assert (await client_admin.get(f"/api/v1/collectors/{p['id']}")).json()["shipper"]["last_error"]  # ticks don't clear it
    await client.post("/api/v1/collector/checkin", headers=_auth(tok), json=_checkin(ran=True))
    assert (await client_admin.get(f"/api/v1/collectors/{p['id']}")).json()["shipper"]["last_error"] is None


# ── ingest ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ldap_push_upserts_and_closes_run(client, client_admin, db):
    from api.models.device import Device
    from api.models.integration import SyncJob, SyncStatus
    from api.models.user import User
    p, r, _ = await _enroll(client, client_admin)
    tok, iid, run = r.json()["token"], p["modules"]["ldap"]["integration_id"], str(uuid.uuid4())
    r = await client.post(f"/api/v1/collector/ingest/{iid}", headers=_auth(tok), json={
        "kind": "ldap", "run_id": run, "users": [{"username": "jdoe-col", "email": "jdoe@acme.example", "groups": ["CN=IT,DC=acme"]}],
        "computers": [{"hostname": "DESKTOP001COL$", "os": "Windows 11", "last_logon": "2026-11-01T10:00:00Z"}]})
    assert r.status_code == 200 and r.json()["accepted"] == 2
    r = await client.post(f"/api/v1/collector/ingest/{iid}", headers=_auth(tok), json={"kind": "ldap", "run_id": run, "final": True})
    assert r.json()["records"] == 2
    assert (await db.execute(select(User).where(User.username == "jdoe-col"))).scalar_one().ad_groups == ["CN=IT,DC=acme"]
    assert (await db.execute(select(Device).where(Device.hostname == "DESKTOP001COL"))).scalar_one().ad_joined
    assert (await db.execute(select(SyncJob).where(SyncJob.id == run))).scalar_one().status == SyncStatus.success


@pytest.mark.asyncio
async def test_push_never_rewrites_local_accounts(client, client_admin, db, admin_user):
    p, r, _ = await _enroll(client, client_admin)
    await client.post(f"/api/v1/collector/ingest/{p['modules']['ldap']['integration_id']}", headers=_auth(r.json()["token"]), json={
        "kind": "ldap", "run_id": str(uuid.uuid4()), "users": [{"username": admin_user.username, "email": "evil@acme.example"}]})
    await db.refresh(admin_user)
    assert admin_user.email != "evil@acme.example"


@pytest.mark.asyncio
async def test_token_scoping_kind_and_auth_failures(client, client_admin, db):
    from api.models.collector import CollectorToken
    a_p, a, _ = await _enroll(client, client_admin)
    b_p, _, _ = await _enroll(client, client_admin)
    tok = a.json()["token"]
    other = b_p["modules"]["ldap"]["integration_id"]
    assert (await client.post(f"/api/v1/collector/ingest/{other}", headers=_auth(tok),
                              json={"kind": "ldap", "run_id": str(uuid.uuid4())})).status_code == 404
    url = f"/api/v1/collector/ingest/{a_p['modules']['ldap']['integration_id']}"
    assert (await client.post(url, headers=_auth(tok), json={"kind": "crowdstrike", "run_id": str(uuid.uuid4())})).status_code == 404
    assert (await client.post(url, json={"kind": "ldap", "run_id": str(uuid.uuid4())})).status_code == 401
    assert (await client.post(url, headers=_auth("occ_" + "0" * 64), json={})).status_code == 401
    bad = await client.post(url, headers=_auth(tok), json={"kind": "ldap", "run_id": "x", "users": "nope"})
    assert bad.status_code == 400 and "users" not in bad.text
    row = (await db.execute(select(CollectorToken).where(CollectorToken.id == a.json()["collector_id"]))).scalar_one()
    row.allowed_ips = ["203.0.113.9"]
    await db.commit()
    assert (await client.post(url, headers=_auth(tok), json={"kind": "ldap", "run_id": str(uuid.uuid4())})).status_code == 401


@pytest.mark.asyncio
async def test_revoked_box_is_locked_out(client, client_admin):
    p, r, _ = await _enroll(client, client_admin)
    assert (await client_admin.post(f"/api/v1/collectors/{p['id']}/revoke")).status_code == 200
    assert (await client.post("/api/v1/collector/checkin", headers=_auth(r.json()["token"]), json=_checkin())).status_code == 401


@pytest.mark.asyncio
async def test_crowdstrike_rapid7_and_splunk_batches_apply(client, client_admin, db):
    from api.models.device import Device
    mods = {"crowdstrike": {"settings": {"client_id": "a" * 32}},
            "rapid7_console": {"settings": {"host": "console001", "username": "svc"}},
            "splunk": {"settings": {"host": "splunk001", "username": "svc"}}}
    p, r, _ = await _enroll(client, client_admin, modules=mods)
    ids, h = {k: m["integration_id"] for k, m in p["modules"].items()}, _auth(r.json()["token"])
    r = await client.post(f"/api/v1/collector/ingest/{ids['crowdstrike']}", headers=h, json={
        "kind": "crowdstrike", "run_id": str(uuid.uuid4()),
        "devices": [{"device_id": "a" * 32, "hostname": "server010", "status": "normal", "os_version": "RHEL 9"}],
        "detections": [{"detection_id": "cid:ind:abc:1", "max_severity_displayname": "High", "device": {"hostname": "server010"}}]})
    assert r.status_code == 200
    assert (await db.execute(select(Device).where(Device.hostname == "server010"))).scalar_one().edr_vendor == "crowdstrike"
    r = await client.post(f"/api/v1/collector/ingest/{ids['rapid7_console']}", headers=h, json={
        "kind": "rapid7_console", "run_id": str(uuid.uuid4()), "assets": [{"hostName": "server011", "os": "Ubuntu"}],
        "vulnerabilities": [{"id": "x-1", "title": "t", "cves": ["CVE-2026-0001"], "cvss": {"v3": {"score": 9.8}}}]})
    assert r.status_code == 200 and r.json()["accepted"] == 2
    r = await client.post(f"/api/v1/collector/ingest/{ids['splunk']}", headers=h, json={
        "kind": "splunk", "run_id": str(uuid.uuid4()), "events": [{"search_name": "Brute force", "host": "server012"}],
        "indexes": [{"name": "wineventlog", "totalEventCount": 10}]})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_collector_fed_integration_is_managed_on_the_shipper_only(client, client_admin):
    p, _, _ = await _enroll(client, client_admin)
    iid = p["modules"]["ldap"]["integration_id"]
    assert (await client_admin.post(f"/api/v1/integrations/{iid}/sync")).status_code == 409
    r = await client_admin.put(f"/api/v1/integrations/{iid}", json={"config": {"host": "dc001.acme.example"}})
    assert r.status_code == 409   # edited on the Shippers tab, where its connection and schedule live
    assert (await client_admin.delete(f"/api/v1/integrations/{iid}")).status_code == 409


@pytest.mark.asyncio
async def test_agent_endpoints_work_without_an_origin_header(db):
    from httpx import ASGITransport, AsyncClient

    from api.core.db import get_session
    from api.main import create_app

    async def _s():
        yield db
    app = create_app()
    app.dependency_overrides[get_session] = _s
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as bare:
        r = await bare.post("/api/v1/collector/login-check", json={"username": "nobody", "password": "x"})
        assert r.status_code == 401  # reached the handler, not the CSRF guard
        assert (await bare.post("/api/v1/collectors/installer", json={})).status_code in (401, 403)


@pytest.mark.asyncio
async def test_rejected_payloads_never_log_passwords(client, caplog):
    import logging
    caplog.set_level(logging.INFO, logger="open-ctem.collector")
    r = await client.post("/api/v1/collector/enroll-login", json={"username": "a", "password": "Sup3r-Secret-Value"})
    assert r.status_code == 400
    assert "Sup3r-Secret-Value" not in caplog.text and "collector payload rejected" in caplog.text


def test_source_schedule_is_validated_and_needs_no_approval():
    from api.collector.profile import dest_digest, validate_settings

    base = {"host": "splunk001.acme.example", "username": "svc-ctem"}
    every5 = validate_settings("splunk", {**base, "schedule_minutes": 5})
    assert every5["schedule_minutes"] == 5
    assert dest_digest("splunk", every5) == dest_digest("splunk", validate_settings("splunk", base))
    for bad in (7, 0, -5, "30", 100000):
        with pytest.raises(Exception):
            validate_settings("splunk", {**base, "schedule_minutes": bad})


@pytest.mark.asyncio
async def test_shipper_warnings_reach_the_card_and_truncate_pauses_uploads(client, client_admin, db, monkeypatch):
    from api.core import integration_truncate as tr
    from api.models.integration import IntegrationConfig
    p, r, _ = await _enroll(client, client_admin)
    tok, iid, run = r.json()["token"], p["modules"]["ldap"]["integration_id"], str(uuid.uuid4())
    url = f"/api/v1/collector/ingest/{iid}"
    w = await client.post(url, headers=_auth(tok), json={"kind": "ldap", "run_id": run, "warnings": ["software was skipped"]})
    assert w.status_code == 200
    await client.post(url, headers=_auth(tok), json={"kind": "ldap", "run_id": run, "final": True})
    cfg = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.id == iid))).scalar_one()
    await db.refresh(cfg)
    assert cfg.last_sync_status.value == "success" and cfg.last_sync_error == "warning: software was skipped"
    card = [i for i in (await client_admin.get("/api/v1/integrations")).json()["integrations"] if i["id"] == iid][0]
    assert card["last_sync_note"] == "warning: software was skipped"
    bad = await client.post(url, headers=_auth(tok), json={"kind": "ldap", "run_id": str(uuid.uuid4()), "warnings": ["<script>"]})
    assert bad.status_code == 400

    async def busy(_):
        return True
    monkeypatch.setattr(tr, "running", busy)
    assert (await client.post(url, headers=_auth(tok), json={"kind": "ldap", "run_id": str(uuid.uuid4())})).status_code == 409



@pytest.mark.asyncio
async def test_send_software_sooner_puts_itself_back_after_a_software_run(client, client_admin, db):
    from api.collector.software_resend import KEY, resend_soon
    from api.models.collector import CollectorProfile
    from api.models.settings import AppSetting
    mods = {"rapid7_console": {"settings": {"host": "console001", "username": "svc", "software_hours": 24}}}
    p, r, _ = await _enroll(client, client_admin, modules=mods)
    prof = (await db.execute(select(CollectorProfile).where(CollectorProfile.id == p["id"]))).scalar_one()
    assert await resend_soon(db, prof, 4) == 24
    await db.commit()
    await db.refresh(prof)
    assert prof.modules["rapid7_console"]["settings"]["software_hours"] == 4
    iid, h, run = p["modules"]["rapid7_console"]["integration_id"], _auth(r.json()["token"]), str(uuid.uuid4())
    url = f"/api/v1/collector/ingest/{iid}"
    assert (await client.post(url, headers=h, json={"kind": "rapid7_console", "run_id": run,
                                                    "assets": [{"hostName": "server-rs1", "os": "Ubuntu"}]})).status_code == 200
    assert (await client.post(url, headers=h, json={"kind": "rapid7_console", "run_id": run, "software": [
        {"vendor": "Acme", "product": "Resend Tool", "version": "1.0", "hosts": ["server-rs1"]}]})).status_code == 200
    assert (await client.post(url, headers=h, json={"kind": "rapid7_console", "run_id": run, "final": True})).status_code == 200
    await db.refresh(prof)
    assert prof.modules["rapid7_console"]["settings"]["software_hours"] == 24
    assert (await db.execute(select(AppSetting).where(AppSetting.key == KEY.format(prof.id)))).scalar_one_or_none() is None
