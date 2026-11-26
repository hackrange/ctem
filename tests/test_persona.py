"""Persona IDV: only the approved calls, only the approved facts, the right state, the badge, and cyber-only review."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select

H = "https://api.withpersona.com"
INQ = "inq_" + "A1b2C3d4E5f6G7h8"


def test_persona_calls_are_allow_listed():
    from api.integrations.persona import allowed
    assert allowed("GET", f"{H}/api/v1/inquiries")
    assert allowed("GET", f"{H}/api/v1/inquiries/{INQ}")
    assert allowed("GET", f"{H}/api/v1/inquiry-templates")
    for action in ("approve", "decline", "generate-one-time-link"):
        assert allowed("POST", f"{H}/api/v1/inquiries/{INQ}/{action}")
    assert allowed("POST", f"{H}/api/v1/inquiries")
    for m, path in (("DELETE", f"/api/v1/inquiries/{INQ}"), ("PATCH", f"/api/v1/inquiries/{INQ}"), ("GET", "/api/v1/accounts"),
                    ("POST", f"/api/v1/inquiries/{INQ}/redact"), ("POST", "/api/v1/webhooks"), ("GET", "/api/v1/api-keys"),
                    ("POST", f"/api/v1/inquiries/{INQ}/expire"), ("GET", f"/api/v1/inquiries/{INQ}/print")):
        assert not allowed(m, f"{H}{path}"), (m, path)
    assert not allowed("GET", "https://evil.example/api/v1/inquiries")
    assert not allowed("GET", f"http://api.withpersona.com/api/v1/inquiries")
    assert not allowed("GET", f"https://user:pw@api.withpersona.com/api/v1/inquiries")


def test_only_the_approved_facts_are_kept():
    from api.integrations.persona_ingest import id_facts, session_facts
    attrs = {"fields": {"name_first": {"value": "Jane"}, "name_last": {"value": "Doe"}, "birthdate": {"value": "1990-01-02"},
                        "identification_number": {"value": "D1234567"}, "address_street_1": {"value": "1 Main St"},
                        "address_subdivision": {"value": "FL"}, "selected_country_code": {"value": "US"},
                        "selected_id_class": {"value": "dl"}, "current_selfie": {"value": {"url": "https://x"}}}}
    f = id_facts(attrs)
    assert f == {"country": "US", "region": "FL", "id_class": "dl", "id_type": "Driver's license"}
    assert id_facts({"fields": {"address_subdivision": {"value": "<script>"}, "selected_country_code": {"value": "USA1"}}}) == {}
    s = session_facts([{"type": "inquiry-session", "attributes": {"created-at": "2026-11-01T00:00:00Z", "device-type": "mobile",
                        "os-name": "iOS", "browser-name": "Safari", "is-vpn": True, "is-tor": False, "threat-level": "low",
                        "ip-address": "198.51.100.7", "gps-latitude": 27.9, "user-agent": "Mozilla"}}])
    assert s == {"device_type": "mobile", "os": "iOS", "browser": "Safari", "threat_level": "low", "vpn": True, "tor": False}


def test_states():
    from api.integrations.persona_ingest import state_of
    now = datetime.now(timezone.utc)
    assert [state_of(s, now, now) for s in ("created", "pending", "completed", "approved", "declined", "expired", "needs_review", "failed")] \
        == ["pending", "pending", "approved", "approved", "rejected", "expired", "review", "review"]
    assert state_of("failed", now - timedelta(days=45), now) == "rejected"   # nobody reviewed it in time


def _inq(iid, status, ref, created="2026-11-20T10:00:00.000Z", fields=None, creator="API", tmpl="itmpl_" + "Z9y8X7w6V5u4"):
    return {"id": iid, "type": "inquiry", "attributes": {"status": status, "reference-id": ref, "created-at": created, "creator": creator,
            "completed-at": created if status == "completed" else None, "fields": fields or {}},
            "relationships": {"inquiry-template": {"data": {"id": tmpl, "type": "inquiry-template"}}}}


@pytest.mark.asyncio
async def test_sync_reads_only_matches_people_and_sets_the_badge(db):
    from api.integrations import persona_ingest
    from api.integrations.persona import PersonaConnector, PersonaError
    from api.models.idv import IdvRequest
    from api.models.user import User
    t = uuid.uuid4().hex[:10]
    okta = f"00u{t}AbC"
    u = User(username=f"idv-{t}", is_local=False, is_active=True, okta_id=okta)
    db.add(u)
    await db.commit()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    done, failed = f"inq_D{t}x", f"inq_F{t}x"
    seen = []

    def handler(req: httpx.Request):
        seen.append((req.method, req.url.path, dict(req.url.params)))
        if req.url.path == "/api/v1/inquiry-templates":
            return httpx.Response(200, json={"data": [{"id": "itmpl_" + "Z9y8X7w6V5u4", "attributes": {"name": "Okta IDV GovID + Selfie"}}]})
        if req.url.path == "/api/v1/inquiries":
            return httpx.Response(200, json={"data": [
                _inq(done, "completed", okta, now, {"name_first": {"value": "Jane"}, "selected_country_code": {"value": "US"},
                                                    "selected_id_class": {"value": "pp"}}),
                _inq(failed, "failed", okta, now)], "links": {"next": None}})
        return httpx.Response(200, json={"data": {"id": req.url.path.rsplit("/", 1)[-1]}, "included": [
            {"type": "inquiry-session", "attributes": {"device-type": "desktop", "os-name": "Windows", "ip-address": "198.51.100.9"}}]})

    conn = PersonaConnector({"api_key": "persona_production_" + "x" * 36})
    conn.integration_id = str(uuid.uuid4())
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        await persona_ingest.sync(conn, c, db, 5, 10)
        with pytest.raises(PersonaError, match="turned off"):
            await conn.request("POST", f"/api/v1/inquiries/{done}/approve", c, body={})
    assert {m for m, _, _ in seen} == {"GET"}
    lists = [p for m, path, p in seen if path == "/api/v1/inquiries"]
    assert lists and "fields[inquiry]" in lists[0]
    details = [p for m, path, p in seen if path.startswith("/api/v1/inquiries/inq_")]
    assert details and all(p.get("fields[inquiry-session]") and "ip-address" not in p["fields[inquiry-session]"] for p in details)
    rows = {r.inquiry_id: r for r in (await db.execute(select(IdvRequest).where(IdvRequest.okta_id == okta))).scalars()}
    assert rows[done].state == "approved" and rows[failed].state == "review"
    assert rows[done].user_id == u.id and rows[done].template == "Okta IDV GovID + Selfie"
    assert rows[done].facts["country"] == "US" and rows[done].facts["id_type"] == "Passport"
    assert rows[done].facts["device_type"] == "desktop"
    assert "Jane" not in str(rows[done].facts) and "198.51.100.9" not in str(rows[done].facts)
    await db.refresh(u)
    assert u.idv_verified_at is not None


@pytest.mark.asyncio
async def test_review_is_cyber_only_goes_to_persona_and_is_audited(db, client_cyber, client_it_user, monkeypatch):
    from api.integrations.persona import PersonaConnector
    from api.models.idv import IdvRequest
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.settings import AuditLog
    cfg = IntegrationConfig(vendor=Vendor.persona, name="Persona", config={"api_key": "persona_production_" + "y" * 36,
                                                                        "allow_actions": True})
    db.add(cfg)
    await db.flush()
    t = uuid.uuid4().hex[:10]
    r = IdvRequest(inquiry_id=f"inq_R{t}x", integration_id=str(cfg.id), state="review", persona_status="failed")
    done = IdvRequest(inquiry_id=f"inq_S{t}x", integration_id=str(cfg.id), state="approved", persona_status="completed")
    db.add_all([r, done])
    await db.commit()
    calls = []

    async def fake_review(self, inquiry, approve, comment):
        calls.append((inquiry, approve, comment))
        return "approved" if approve else "declined"
    monkeypatch.setattr(PersonaConnector, "review", fake_review)
    assert (await client_it_user.get("/api/v1/idv/requests")).status_code == 403
    assert (await client_it_user.post(f"/api/v1/idv/requests/{r.id}/review", json={"decision": "approve", "note": "ok then"})).status_code == 403
    listed = (await client_cyber.get("/api/v1/idv/requests", params={"tab": "pending", "limit": 200})).json()
    assert any(x["id"] == r.id and x["state"] == "review" for x in listed["requests"])
    assert (await client_cyber.get("/api/v1/idv/summary")).json()["review"] >= 1
    bad = await client_cyber.post(f"/api/v1/idv/requests/{r.id}/review", json={"decision": "approve", "note": "x", "extra": 1})
    assert bad.status_code == 422
    assert (await client_cyber.post(f"/api/v1/idv/requests/{done.id}/review", json={"decision": "decline", "note": "no way"})).status_code == 409
    assert (await client_cyber.post(f"/api/v1/idv/requests/{uuid.uuid4()}/review", json={"decision": "decline", "note": "no way"})).status_code == 404
    ok = await client_cyber.post(f"/api/v1/idv/requests/{r.id}/review", json={"decision": "approve", "note": "Called them back, ID matches"})
    assert ok.status_code == 200 and ok.json()["state"] == "approved"
    assert calls == [(r.inquiry_id, True, calls[0][2])] and "Called them back" in calls[0][2]
    audit = (await db.execute(select(AuditLog).where(AuditLog.action == "idv.approve", AuditLog.resource_id == r.id))).scalars().all()
    assert len(audit) == 1


def test_twilio_calls_are_allow_listed():
    from api.integrations.twilio import allowed
    ac, sm = "AC" + "0" * 32, "SM" + "1" * 32
    base = f"https://api.twilio.com/2010-04-01/Accounts/{ac}"
    assert allowed("POST", f"{base}/Messages.json", ac)
    assert allowed("GET", f"{base}/Messages/{sm}.json", ac)
    assert not allowed("GET", f"{base}/Messages.json", ac)            # no listing anyone's texts
    assert not allowed("DELETE", f"{base}/Messages/{sm}.json", ac)
    assert not allowed("POST", f"{base}/Calls.json", ac)
    assert not allowed("POST", f"https://api.twilio.com/2010-04-01/Accounts/AC{'2' * 32}/Messages.json", ac)
    assert not allowed("POST", f"https://evil.example/2010-04-01/Accounts/{ac}/Messages.json", ac)


def test_settings_checks():
    from api.integrations.idv_config import check
    check("persona", {"api_key": "persona_production_" + "a" * 36, "template_id": "itmpl_" + "B" * 12})
    check("persona", {"api_key": "__REDACTED__"})
    for bad in ({"api_key": "sk-live-123"}, {"api_key": "__REDACTED__", "template_id": "../x"},
                {"api_key": "__REDACTED__", "detail_budget": "99999"}, {"base_url": "https://evil.example"}):
        with pytest.raises(ValueError):
            check("persona", bad)
    good = {"account_sid": "AC" + "a" * 32, "api_key_sid": "SK" + "b" * 32, "from_number": "+12395550100"}
    check("twilio", good)
    for k, v in (("account_sid", "ACxyz"), ("api_key_sid", "AK123"), ("from_number", "239-555-0100")):
        with pytest.raises(ValueError):
            check("twilio", {**good, k: v})


@pytest.mark.asyncio
async def test_two_persona_integrations_never_touch_each_others_requests(db):
    """The Horizon3 lesson: one integration's sync or truncate leaves another's data alone."""
    from api.core import integration_truncate
    from api.integrations import persona_ingest
    from api.integrations.persona import PersonaConnector
    from api.models.idv import IdvRequest
    from api.models.integration import IntegrationConfig, Vendor
    a = IntegrationConfig(vendor=Vendor.persona, name="Persona A", config={"api_key": "persona_production_" + "a" * 36})
    b = IntegrationConfig(vendor=Vendor.persona, name="Persona B", config={"api_key": "persona_production_" + "b" * 36})
    db.add_all([a, b])
    await db.flush()
    t = uuid.uuid4().hex[:10]
    theirs = IdvRequest(inquiry_id=f"inq_B{t}x", integration_id=str(b.id), state="review", persona_status="failed")
    db.add(theirs)
    await db.commit()

    def handler(req: httpx.Request):   # tenant A's Persona claims B's inquiry is approved
        if req.url.path == "/api/v1/inquiry-templates":
            return httpx.Response(200, json={"data": []})
        if req.url.path == "/api/v1/inquiries":
            return httpx.Response(200, json={"data": [_inq(theirs.inquiry_id, "completed", "00u" + t), _inq(f"inq_A{t}x", "completed", "00u" + t)]})
        return httpx.Response(200, json={"data": {}, "included": []})

    conn = PersonaConnector(a.config)
    conn.integration_id = str(a.id)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        await persona_ingest.sync(conn, c, db, 5, 5)
    await db.refresh(theirs)
    assert theirs.state == "review" and theirs.integration_id == str(b.id)
    assert (await db.execute(select(IdvRequest).where(IdvRequest.inquiry_id == f"inq_A{t}x"))).scalar_one().integration_id == str(a.id)
    await integration_truncate.run(db, a, "admin")
    left = (await db.execute(select(IdvRequest.inquiry_id).where(IdvRequest.inquiry_id.in_([theirs.inquiry_id, f"inq_A{t}x"])))).scalars().all()
    assert left == [theirs.inquiry_id]


@pytest.mark.asyncio
async def test_only_trusted_passes_earn_the_badge(db):
    """An inquiry started from a hosted link can carry anyone's Okta id: it never earns the badge. Nor does a
    template the integration doesn't trust, nor an Okta id two people share."""
    from api.integrations import persona_ingest
    from api.integrations.persona import PersonaConnector
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.user import User
    t = uuid.uuid4().hex[:10]
    good_t, other_t = "itmpl_" + "Good1234abcd", "itmpl_" + "Othr1234abcd"
    victim = User(username=f"v-{t}", is_local=False, is_active=True, okta_id=f"00uV{t}")
    trusted = User(username=f"t-{t}", is_local=False, is_active=True, okta_id=f"00uT{t}")
    twin_a = User(username=f"a-{t}", is_local=False, is_active=True, okta_id=f"00uW{t}")
    twin_b = User(username=f"b-{t}", is_local=False, is_active=True, okta_id=f"00uW{t}")
    cfg = IntegrationConfig(vendor=Vendor.persona, name="P", config={"api_key": "persona_production_" + "c" * 36,
                                                                  "badge_templates": good_t})
    db.add_all([victim, trusted, twin_a, twin_b, cfg])
    await db.commit()
    data = [_inq(f"inq_H{t}x", "completed", victim.okta_id, creator="Hosted flow", tmpl=good_t),   # attacker's own ID
            _inq(f"inq_O{t}x", "completed", victim.okta_id, tmpl=other_t),                         # untrusted template
            _inq(f"inq_G{t}x", "completed", trusted.okta_id, tmpl=good_t),
            _inq(f"inq_W{t}x", "completed", twin_a.okta_id, tmpl=good_t)]

    def handler(req: httpx.Request):
        if req.url.path == "/api/v1/inquiry-templates":
            return httpx.Response(200, json={"data": []})
        if req.url.path == "/api/v1/inquiries":
            return httpx.Response(200, json={"data": data})
        return httpx.Response(200, json={"data": {}, "included": []})

    conn = PersonaConnector(cfg.config)
    conn.integration_id = str(cfg.id)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        await persona_ingest.sync(conn, c, db, 5, 5)
    for u in (victim, trusted, twin_a, twin_b):
        await db.refresh(u)
    assert victim.idv_verified_at is None
    assert trusted.idv_verified_at is not None
    assert twin_a.idv_verified_at is None and twin_b.idv_verified_at is None


@pytest.mark.asyncio
async def test_search_rejects_control_characters(client_cyber):
    assert (await client_cyber.get("/api/v1/idv/requests", params={"q": "a\x00b"})).status_code == 422
    assert (await client_cyber.get("/api/v1/idv/requests", params={"q": "jane.doe"})).status_code == 200


@pytest.mark.asyncio
async def test_device_page_shows_the_verification_date_to_cyber_only(db, client_cyber, client_it_user, it_user):
    from api.models.device import Device, DeviceAssignment, DeviceType
    from api.models.user import User
    t = uuid.uuid4().hex[:8]
    person = User(username=f"owner-{t}", is_local=False, is_active=True, idv_verified_at=datetime.now(timezone.utc))
    db.add(person)
    await db.flush()
    d = Device(hostname=f"idv-{t}", device_type=DeviceType.workstation, owner_user_id=person.id)
    db.add(d)
    await db.flush()
    db.add(DeviceAssignment(device_id=d.id, user_id=it_user.id))   # the IT user may open this device
    await db.commit()
    assert (await client_cyber.get(f"/api/v1/devices/{d.id}")).json()["detected_user_idv_at"]
    r = await client_it_user.get(f"/api/v1/devices/{d.id}")
    assert r.status_code == 200 and r.json()["detected_user_idv_at"] is None
    assert "idv_verified_at" not in r.text
