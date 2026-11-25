"""Okta: GETs on an allow-list of the org's own paths and nothing else; people matched by UPN, computers by name;
the MFA phone, identity posture and System Log threats; and the asset's Identity tab for admins and cyber only."""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ORG = "acme.okta.com"


def test_only_allow_listed_gets_on_the_org_itself():
    from api.integrations.okta import allowed
    ok = ("/api/v1/users?limit=200", "/api/v1/devices?limit=200&expand=user", "/api/v1/logs?since=x",
          "/api/v1/users/00uABCDEFGHIJ12345/factors")
    for p in ok:
        assert allowed("GET", f"https://{ORG}{p}", ORG), p
    for method in ("POST", "PUT", "PATCH", "DELETE", "HEAD"):
        assert not allowed(method, f"https://{ORG}/api/v1/users", ORG)
    bad = ("/api/v1/users/00uABCDEFGHIJ12345/lifecycle/reset_password", "/api/v1/devices/guoABCDEFGHIJ1/lifecycle/suspend",
           "/api/v1/users/00uABCDEFGHIJ12345", "/api/v1/apps", "/api/v1/api-tokens", "/api/v1/idps/credentials/keys",
           "/api/v1/users/../api-tokens", "/api/v1/users/00uABCDEFGHIJ12345/factors/x/verify", "/oauth2/v1/token")
    for p in bad:
        assert not allowed("GET", f"https://{ORG}{p}", ORG), p
    # the token never goes anywhere but the org: other hosts, look-alikes, plain http, userinfo, other ports
    for url in (f"http://{ORG}/api/v1/users", "https://evil.example/api/v1/users", f"https://{ORG}.evil.example/api/v1/users",
                f"https://user:pw@{ORG}/api/v1/users", f"https://{ORG}:8443/api/v1/users", f"https://x.{ORG}/api/v1/users"):
        assert not allowed("GET", url, ORG), url


def test_org_host_and_next_links():
    from api.integrations.okta import next_link, org_host
    assert org_host({"base_url": "https://ACME.okta.com/api/v1/"}) == ORG
    assert org_host({"base_url": "acme.okta.com"}) == ORG
    for bad in ("", "https://", "https://127.0.0.1", "javascript:alert(1)", "https://acme"):
        with pytest.raises(ValueError):
            org_host({"base_url": bad})
    link = f'<https://{ORG}/api/v1/users?limit=2>; rel="self", <https://{ORG}/api/v1/users?after=abc&limit=2>; rel="next"'
    assert next_link(link) == f"https://{ORG}/api/v1/users?after=abc&limit=2"
    assert next_link(f'<https://{ORG}/api/v1/users>; rel="self"') is None


@pytest.mark.asyncio
async def test_a_next_link_to_another_host_is_refused_before_the_token_is_sent(monkeypatch):
    import httpx

    from api.integrations.okta import OktaConnector, OktaError
    sent = []

    def handler(req: httpx.Request):
        sent.append((req.method, str(req.url), req.headers.get("authorization")))
        return httpx.Response(200, json=[], headers={"link": '<https://evil.example/api/v1/users?after=x>; rel="next"'})

    conn = OktaConnector({"base_url": f"https://{ORG}", "api_token": "example-not-a-real-token"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        with pytest.raises(OktaError, match="next-page link"):
            async for _ in conn.pages("/api/v1/users?limit=200", c):
                pass
        with pytest.raises(OktaError, match="never calls"):
            await conn.fetch("/api/v1/apps", c)
    assert [s[1] for s in sent] == [f"https://{ORG}/api/v1/users?limit=200"]


def test_okta_code_sends_nothing_but_get():
    root = Path(__file__).resolve().parents[1]
    for f in ("api/integrations/okta.py", "api/integrations/okta_ingest.py", "api/integrations/okta_signals.py"):
        src = (root / f).read_text()
        assert not re.search(r"\.(post|put|patch|delete|request|stream)\(", src), f


def test_factor_summary_keeps_the_phone_but_not_device_names():
    from api.integrations.okta_ingest import factor_summary
    fs = [{"factorType": "call", "status": "ACTIVE", "profile": {"phoneNumber": "+15550100111"}},
          {"factorType": "sms", "status": "ACTIVE", "profile": {"phoneNumber": "+15550100199"}},
          {"factorType": "sms", "status": "PENDING_ACTIVATION", "profile": {"phoneNumber": "+15550100000"}},
          {"factorType": "signed_nonce", "status": "ACTIVE", "profile": {"name": "desktop001", "credentialId": "jdoe@acme.example"}}]
    s = factor_summary(fs)
    assert s == {"factors": ["call", "signed_nonce", "sms"], "mfa_phone": "+15550100199", "mfa_phone_kind": "sms"}
    assert factor_summary(fs[:1])["mfa_phone_kind"] == "call"
    assert factor_summary([{"factorType": "sms", "status": "ACTIVE", "profile": {"phoneNumber": "<script>"}}])["mfa_phone"] is None
    assert "desktop001" not in str(s) and "jdoe" not in str(s)


def _dev(name, platform="WINDOWS", status="ACTIVE", users=(), enc="ALL_INTERNAL_VOLUMES", updated="2026-11-20T00:00:00.000Z"):
    return {"id": f"guo{uuid.uuid4().hex[:12]}", "status": status, "created": "2026-01-01T00:00:00.000Z", "lastUpdated": updated,
            "profile": {"displayName": name, "platform": platform, "osVersion": "10.0.26100", "manufacturer": "Acme",
                        "model": "Book 14", "serialNumber": "SN123", "diskEncryptionType": enc, "secureHardwarePresent": True},
            "_embedded": {"users": [{"created": c, "managementStatus": "NOT_MANAGED", "screenLockType": "BIOMETRIC",
                                     "user": {"id": oid, "status": st, "profile": {"login": login}}}
                                    for oid, login, st, c in users]}}


def test_device_record_takes_computers_only_and_the_newest_active_user():
    from api.integrations.okta_ingest import device_record
    assert device_record(_dev("iPhone", platform="IOS")) is None
    assert device_record(_dev("desktop001", status="DEACTIVATED")) is None
    assert device_record(_dev("<img src=x>")) is None
    r = device_record(_dev("desktop001", users=[("00uOLD", "old@acme.example", "ACTIVE", "2025-01-01"),
                                                ("00uNEW", "new@acme.example", "ACTIVE", "2026-06-01"),
                                                ("00uGONE", "gone@acme.example", "SUSPENDED", "2026-09-01")]))
    assert r["owner_okta"] == "00uNEW" and r["platform"] == "Windows" and r["serial"] == "SN123" and len(r["logins"]) == 3


def test_threat_rows_map_and_mask():
    from api.integrations.okta_signals import threat_row
    e = {"uuid": "u-1", "eventType": "user.mfa.okta_verify.deny_push", "published": "2026-11-24T10:00:00.000Z",
         "displayMessage": "User rejected Okta push verify", "actor": {"type": "User", "alternateId": "jdoe@acme.example"},
         "client": {"ipAddress": "203.0.113.9", "geographicalContext": {"country": "United States"}},
         "securityContext": {"risk": {"level": "HIGH"}}, "outcome": {"result": "FAILURE"}}
    r = threat_row(e)
    assert r["threat_type"] == "mfa_fatigue" and r["login"] == "jdoe@acme.example" and r["ip"] == "203.0.113.9"
    assert threat_row({**e, "eventType": "user.session.start"}) is None
    grant = threat_row({**e, "eventType": "user.account.privilege.grant",
                        "target": [{"type": "User", "alternateId": "newadmin@acme.example"}]})
    assert grant["login"] == "newadmin@acme.example" and grant["threat_type"] == "privilege_escalation"


@pytest.mark.asyncio
async def test_sync_matches_people_and_computers_and_reads_signals(db, monkeypatch):
    from sqlalchemy import select

    from api.core.encryption import search_hash
    from api.integrations.okta import OktaConnector
    from api.models.device import Device, DeviceType
    from api.models.identity import IdentityThreat, PostureFinding
    from api.models.user import User
    t = uuid.uuid4().hex[:6]
    upn = f"jdoe{t}@acme.example"
    person = User(username=f"jdoe{t}", is_local=False, upn=upn, upn_hash=search_hash(upn), mobile="+15550100123")
    local = User(username=f"breakglass{t}", is_local=True, upn=f"bg{t}@acme.example", upn_hash=search_hash(f"bg{t}@acme.example"))
    no_epp = Device(hostname=f"L-{t}A", device_type=DeviceType.workstation, sources=",rapid7_insightvm,")
    with_edr = Device(hostname=f"L-{t}B", device_type=DeviceType.workstation, last_login_user="ACME\\someone", edr_vendor="crowdstrike",
                      edr_active=True)
    db.add_all([person, local, no_epp, with_edr])
    await db.commit()
    recent = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    data = {
        "/api/v1/users": [
            {"id": "00uPersonAAAAAAAAAA1", "status": "ACTIVE", "lastLogin": recent, "profile": {"login": upn, "title": "Driver", "primaryPhone": "555-010-0100"}},
            {"id": "00uLocalAAAAAAAAAAA1", "status": "ACTIVE", "lastLogin": recent, "profile": {"login": f"bg{t}@acme.example", "title": "Hacked"}},
            {"id": "00uNewbieAAAAAAAAAA1", "status": "ACTIVE", "lastLogin": recent, "profile": {"login": f"newbie{t}@acme.example", "sam": f"newbie{t}"}}],
        "/api/v1/devices": [
            _dev(f"L-{t}A", platform="MACOS", users=[("00uPersonAAAAAAAAAA1", upn, "ACTIVE", "2026-11-04")], enc="NONE"),
            _dev(f"l-{t}a", platform="MACOS", users=[], updated="2020-01-01T00:00:00.000Z"),   # an old duplicate loses
            _dev(f"L-{t}B", users=[("00uPersonAAAAAAAAAA1", upn, "ACTIVE", "2026-11-04")]),
            _dev(f"L-{t}C", users=[("00uNewbieAAAAAAAAAA1", f"newbie{t}@acme.example", "ACTIVE", "2026-11-04")]),
            _dev("iPhone", platform="IOS", users=[("00uPersonAAAAAAAAAA1", upn, "ACTIVE", "2026-11-04")])],
        "/api/v1/users/00uPersonAAAAAAAAAA1/factors": [{"factorType": "sms", "status": "ACTIVE", "profile": {"phoneNumber": "+15550100199"}}],
        "/api/v1/users/00uNewbieAAAAAAAAAA1/factors": [{"factorType": "push", "status": "ACTIVE", "profile": {}}],
        "/api/v1/logs": [{"uuid": f"ev-{t}", "eventType": "user.mfa.okta_verify.deny_push", "published": recent,
                          "displayMessage": "User rejected Okta push verify", "actor": {"type": "User", "alternateId": upn},
                          "client": {"ipAddress": "203.0.113.9"}}],
    }
    calls = []

    async def fake_fetch(self, url, client):
        from api.integrations.okta import allowed
        full = url if url.startswith("https://") else f"https://{ORG}{url}"
        assert allowed("GET", full, ORG), full
        path = full.split(ORG, 1)[1].split("?", 1)[0]
        calls.append(path)
        return data.get(path, []), None

    monkeypatch.setattr(OktaConnector, "fetch", fake_fetch)
    conn = OktaConnector({"base_url": f"https://{ORG}", "api_token": "example-not-a-real-token"})
    conn.integration_id = str(uuid.uuid4())
    assert await conn.sync(db) > 0
    await db.refresh(no_epp)
    await db.refresh(with_edr)
    await db.refresh(person)
    await db.refresh(local)
    assert no_epp.owner_user_id == person.id and no_epp.idp_device["owner_from_idp"] and no_epp.idp_device["disk_encryption"] == "NONE"
    assert ",okta," in no_epp.sources and ",rapid7_insightvm," in no_epp.sources.replace("okta,", "")
    assert with_edr.owner_user_id is None   # the EDR's sign-ins decide there
    assert person.mfa_phone == "+15550100199" and person.idp["factors"] == ["sms"] and person.title == "Driver"
    assert person.mobile == "+15550100123"   # the directory's value stays
    assert local.title is None and local.idp is None and local.mfa_phone is None   # a local account is never touched
    newbie = (await db.execute(select(User).where(User.username == f"newbie{t}"))).scalar_one()
    assert not newbie.is_local and newbie.upn == f"newbie{t}@acme.example"
    assert (await db.execute(select(Device).where(Device.hostname == f"L-{t}C"))).scalar_one_or_none() is None   # create_devices off
    assert (await db.execute(select(Device).where(Device.hostname == "iPhone"))).scalar_one_or_none() is None
    found = {p.external_id: p for p in (await db.execute(select(PostureFinding).where(PostureFinding.source == "okta"))).scalars()}
    assert f"L-{t}A" in found["okta:devices:unencrypted"].description
    assert "okta:mfa:phone_only" in found and upn not in found["okta:mfa:phone_only"].description
    threat = (await db.execute(select(IdentityThreat).where(IdentityThreat.external_id == f"ev-{t}"))).scalar_one()
    assert threat.threat_type.value == "mfa_fatigue" and threat.user_email_hash == search_hash(upn) and upn not in threat.user_display
    assert set(calls) <= {"/api/v1/users", "/api/v1/devices", "/api/v1/logs", "/api/v1/users/00uPersonAAAAAAAAAA1/factors", "/api/v1/users/00uNewbieAAAAAAAAAA1/factors"}
    # a second run saves the event once and doesn't re-read factors read this week
    calls.clear()
    await conn.sync(db)
    assert len((await db.execute(select(IdentityThreat).where(IdentityThreat.external_id == f"ev-{t}"))).scalars().all()) == 1
    assert not [c for c in calls if c.endswith("/factors")]
    assert "/api/v1/devices" not in calls and "/api/v1/users" in calls   # the device pull waits for its weekly turn
    conn.config["device_interval_days"] = "0"
    calls.clear()
    await conn.sync(db)
    assert "/api/v1/devices" in calls


@pytest.mark.asyncio
async def test_identity_tab_is_admins_and_cyber_only(db, client_admin, client_it_user, client_read_only):
    from api.main import create_app
    from tests.conftest import _authed_client, _make_user
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType
    from api.models.user import User
    t = uuid.uuid4().hex[:6]
    upn = f"pat{t}@acme.example"
    u = User(username=f"pat{t}", is_local=False, upn=upn, upn_hash=search_hash(upn), mfa_phone="+15550100199",
             idp={"factors": ["sms"], "mfa_phone_kind": "sms", "status": "ACTIVE"})
    db.add(u)
    await db.flush()
    d = Device(hostname=f"desktop{t}", device_type=DeviceType.workstation, owner_user_id=u.id,
               idp_device={"platform": "macOS", "disk_encryption": "NONE", "logins": [upn], "owner_from_idp": True})
    db.add(d)
    await db.commit()
    url = f"/api/v1/devices/{d.id}/identity"
    r = (await client_admin.get(url)).json()
    assert r["device"]["disk_encryption"] == "NONE" and r["owner_from_idp"]
    assert r["people"][0]["mfa_phone"] == "+15550100199" and r["people"][0]["why"] == "detected"
    assert "logins" not in r["device"]
    inv = await _make_user(db, "inventory")   # sees every device, but phones and MFA aren't theirs to see
    async with _authed_client(create_app(), db, inv) as c_inv:
        assert (await c_inv.get(f"/api/v1/devices/{d.id}")).status_code == 200
        assert (await c_inv.get(url)).status_code == 404
    for c in (client_it_user, client_read_only):
        assert (await c.get(url)).status_code == 404
    assert (await client_admin.get(f"/api/v1/devices/{uuid.uuid4()}/identity")).status_code == 404


@pytest.mark.asyncio
async def test_saving_an_okta_integration_checks_the_domain(client_admin):
    base = {"vendor": "okta", "name": "Okta", "config": {"api_token": "example-not-a-real-token"}}
    for bad in ("http://acme.okta.com", "acme", "https://127.0.0.1"):
        r = await client_admin.post("/api/v1/integrations", json={**base, "config": {**base["config"], "base_url": bad}})
        assert r.status_code == 400, bad
    r = await client_admin.post("/api/v1/integrations", json={**base, "config": {**base["config"], "base_url": "https://acme.okta.com",
                                                                               "factor_budget": "999999"}})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_okta_data_cannot_hijack_people_or_computers(db, monkeypatch):
    """Review findings: a look-alike Okta login, two Okta accounts on one person, a renamed laptop posing as
    another computer, a server sharing a laptop's name, and a username differing only by case."""
    from sqlalchemy import func, select

    from api.core.encryption import search_hash
    from api.integrations.okta import OktaConnector
    from api.integrations.okta_signals import _mask
    from api.models.device import Device, DeviceType
    from api.models.identity import PostureFinding
    from api.models.user import User
    t = uuid.uuid4().hex[:6]
    tim = User(username=f"tim{t}", is_local=False, upn=f"tim{t}@acme.example", upn_hash=search_hash(f"tim{t}@acme.example"))
    pat = User(username=f"pat{t}", is_local=False, upn=f"pat{t}@acme.example", upn_hash=search_hash(f"pat{t}@acme.example"))
    js = User(username=f"jsmith{t}", is_local=False)
    fin = Device(hostname=f"FIN-{t}", device_type=DeviceType.workstation)
    srv = Device(hostname=f"SRV-{t}", device_type=DeviceType.server)
    db.add_all([tim, pat, js, fin, srv])
    await db.commit()
    ids = {k: f"00u{k}{t}".ljust(20, "A") for k in ("evil", "pat1", "pat2", "case", "other")}
    data = {
        "/api/v1/users": [
            {"id": ids["evil"], "status": "ACTIVE", "profile": {"login": f"tim{t}@partner.example", "title": "Evil"}},
            {"id": ids["pat1"], "status": "ACTIVE", "profile": {"login": f"pat{t}@acme.example"}},
            {"id": ids["pat2"], "status": "ACTIVE", "profile": {"login": f"PAT{t}@acme.example", "title": "Twin"}},
            {"id": ids["case"], "status": "ACTIVE", "profile": {"login": f"j.smith{t}@other.example", "sam": f"JSmith{t}"}},
            {"id": ids["other"], "status": "ACTIVE", "profile": {"login": f"other{t}@acme.example", "sam": f"other{t}"}}],
        "/api/v1/devices": [
            {**_dev(f"FIN-{t}", users=[(ids["evil"], f"tim{t}@partner.example", "ACTIVE", "2026-11-04")]),
             "profile": {**_dev("x")["profile"], "displayName": f"FIN-{t}", "serialNumber": "REAL1"}},
            {**_dev(f"FIN-{t}", users=[(ids["other"], f"other{t}@acme.example", "ACTIVE", "2026-11-05")],
                    updated="2026-11-24T00:00:00.000Z"),
             "profile": {**_dev("x")["profile"], "displayName": f"FIN-{t}", "serialNumber": "FAKE2"}},
            _dev(f"SRV-{t}", users=[(ids["other"], f"other{t}@acme.example", "ACTIVE", "2026-11-04")]),
            _dev(f"WS-{t}", users=[(ids["case"], f"j.smith{t}@other.example", "ACTIVE", "2026-11-04")])],
        "/api/v1/users/" + ids["evil"] + "/factors": [{"factorType": "sms", "status": "ACTIVE", "profile": {"phoneNumber": "+15550100666"}}],
    }

    async def fake_fetch(self, url, client):
        path = url.split("?", 1)[0].replace(f"https://{ORG}", "")
        return data.get(path, []), None

    monkeypatch.setattr(OktaConnector, "fetch", fake_fetch)
    conn = OktaConnector({"base_url": f"https://{ORG}", "api_token": "example-not-a-real-token"})
    conn.integration_id = str(uuid.uuid4())
    await conn.sync(db)
    for row in (tim, pat, fin, srv):
        await db.refresh(row)
    assert tim.mfa_phone is None and tim.idp is None and tim.title is None    # a look-alike login never lands on tim
    assert pat.idp is None and pat.title is None                              # two Okta accounts on one person: neither
    assert fin.owner_user_id is None and fin.idp_device is None               # one name, two serials: neither applied
    assert srv.owner_user_id is None and srv.idp_device is None               # never a server of that name
    same = (await db.execute(select(func.count()).where(func.lower(User.username) == f"jsmith{t}"))).scalar()
    assert same == 1                                                          # JSmith is jsmith, not a second account
    clash = (await db.execute(select(PostureFinding).where(PostureFinding.external_id == "okta:devices:name_conflict"))).scalar_one()
    assert f"FIN-{t}" in clash.description and not clash.is_resolved
    # a sync without the device pull keeps the conflict open
    await conn.sync(db)
    await db.refresh(clash)
    assert not clash.is_resolved
    assert _mask("jdoe") == "**oe" and _mask("jdoe@acme.example") == "**oe@acme.example"
