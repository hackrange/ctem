"""Send re-verification link: only to contacts the SSO/MFA provider verified, never shown in full, never storing the
link; Persona and Twilio called once each; rate limited; idv:request only."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select


def test_okta_factors_give_only_verified_contacts():
    from api.core.verified_contacts import verified_contacts
    from api.integrations.okta_ingest import factor_summary
    s = factor_summary([{"factorType": "sms", "status": "ACTIVE", "profile": {"phoneNumber": "+1 555 010 0199"}},
                        {"factorType": "email", "status": "ACTIVE", "profile": {"email": "jane.doe@acme.example"}},
                        {"factorType": "email", "status": "PENDING_ACTIVATION", "profile": {"email": "other@evil.example"}}])
    assert s["mfa_email"] == "jane.doe@acme.example" and s["mfa_phone_kind"] == "sms"

    class U:
        mfa_phone, okta_id = "+15550100199", "00uX"
        idp = {"mfa_phone_kind": "sms", "mfa_email": "jane.doe@acme.example"}
    c = verified_contacts(U)
    assert c["sms"]["shown"].endswith("0199") and "555" not in c["sms"]["shown"]
    assert c["email"]["shown"].startswith("j") and "jane.doe" not in c["email"]["shown"] and c["sms"]["source"] == "Okta SMS MFA"
    U.idp = {"mfa_phone_kind": "call"}
    assert verified_contacts(U) == {"sms": None, "email": None}   # a voice-only factor isn't a texting number


@pytest.mark.asyncio
async def test_send_link_only_to_verified_contacts(db, client_cyber, client_it_user, monkeypatch):
    from api.integrations.persona import PersonaConnector
    from api.integrations.twilio import TwilioConnector
    from api.models.idv import IdvRequest
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.settings import AuditLog
    from api.models.user import User
    t = uuid.uuid4().hex[:10]
    await db.execute(delete(IntegrationConfig).where(IntegrationConfig.vendor.in_([Vendor.persona, Vendor.twilio])))
    persona = IntegrationConfig(vendor=Vendor.persona, name="P", config={"api_key": "persona_production_" + "s" * 36})
    twilio = IntegrationConfig(vendor=Vendor.twilio, name="T", config={"account_sid": "AC" + "1" * 32, "api_key_sid": "SK" + "2" * 32,
                                                                      "api_key_secret": "x" * 32, "from_number": "+15550100100"})
    u = User(username=f"idvd-{t}", is_local=False, is_active=True, okta_id=f"00u{t}DsK", first_name="Jane", last_name="Doe",
             mfa_phone="+15550100199", phone="+15550100777",
             idp={"mfa_phone_kind": "sms", "status": "ACTIVE", "mfa_phone_at": "2026-11-27T00:00:00+00:00"})
    db.add_all([persona, twilio, u])
    await db.commit()
    calls = {"persona": [], "sms": []}

    async def fake_start(self, ref, fields=None):
        calls["persona"].append((ref, fields))
        return f"inq_N{t}x", "https://inquiry.withpersona.com/i/secret-one-time"

    async def fake_send(self, to, text):
        calls["sms"].append((to, text))
        return {"sid": "SM" + "a" * 32, "status": "queued"}
    monkeypatch.setattr(PersonaConnector, "start_inquiry", fake_start)
    monkeypatch.setattr(TwilioConnector, "send", fake_send)
    try:
        assert (await client_it_user.get(f"/api/v1/idv/people/{u.id}/contacts")).status_code == 403
        assert (await client_it_user.post(f"/api/v1/idv/people/{u.id}/send", json={"channel": "sms"})).status_code == 403
        c = (await client_cyber.get(f"/api/v1/idv/people/{u.id}/contacts")).json()
        assert [x["channel"] for x in c["channels"]] == ["sms"] and "0199" in c["channels"][0]["shown"]
        assert "5550100199" not in str(c) and "turn on Persona actions" in c["missing"]
        assert (await client_cyber.post(f"/api/v1/idv/people/{u.id}/send", json={"channel": "sms"})).status_code == 409   # actions off
        persona.config = {**persona.config, "allow_actions": True, "template_id": "itmpl_" + "T" * 12}
        await db.commit()
        assert (await client_cyber.post(f"/api/v1/idv/people/{u.id}/send", json={"channel": "email"})).status_code == 409   # none verified
        assert (await client_cyber.post(f"/api/v1/idv/people/{u.id}/send", json={"channel": "sms", "to": "+15550109999"})).status_code == 422
        recent = await client_cyber.post(f"/api/v1/idv/people/{u.id}/send", json={"channel": "sms"})
        assert recent.status_code == 409 and "7 days" in recent.json()["detail"] and not calls["persona"]   # a just-changed factor
        r = await client_cyber.post(f"/api/v1/idv/people/{u.id}/send", json={"channel": "sms", "confirm_recent": True})
        assert r.status_code == 200 and "0199" in r.json()["to"] and "secret" not in r.text
        assert calls["persona"] == [(u.okta_id, {"name-first": "Jane", "name-last": "Doe"})]
        assert calls["sms"][0][0] == "+15550100199" and "secret-one-time" in calls["sms"][0][1]   # the MFA phone, not the directory one
        row = (await db.execute(select(IdvRequest).where(IdvRequest.inquiry_id == f"inq_N{t}x"))).scalar_one()
        assert row.origin == "service_desk" and row.user_id == u.id and row.state == "pending"
        assert "secret" not in str(row.channels) and "5550100199" not in str(row.channels)
        assert (await db.execute(select(AuditLog).where(AuditLog.action == "idv.send", AuditLog.resource_id == u.id))).scalars().first()
        again = await client_cyber.post(f"/api/v1/idv/people/{u.id}/send", json={"channel": "sms", "confirm_recent": True})
        assert again.status_code == 429 and len(calls["persona"]) == 1
        assert (await client_cyber.post(f"/api/v1/idv/people/{uuid.uuid4()}/send", json={"channel": "sms"})).status_code == 404
    finally:
        await db.execute(delete(IdvRequest).where(IdvRequest.user_id == u.id))
        await db.execute(delete(IntegrationConfig).where(IntegrationConfig.id.in_([persona.id, twilio.id])))
        await db.commit()


@pytest.mark.asyncio
async def test_failures_are_recorded_and_wrong_accounts_refused(db, client_cyber, monkeypatch):
    from api.integrations.persona import PersonaConnector, PersonaError
    from api.integrations.twilio import TwilioConnector, TwilioError
    from api.models.idv import IdvRequest
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.user import User
    t = uuid.uuid4().hex[:10]
    await db.execute(delete(IntegrationConfig).where(IntegrationConfig.vendor.in_([Vendor.persona, Vendor.twilio])))
    persona = IntegrationConfig(vendor=Vendor.persona, name="P", config={"api_key": "persona_production_" + "f" * 36, "allow_actions": True,
                                                                        "template_id": "itmpl_" + "F" * 12})
    twilio = IntegrationConfig(vendor=Vendor.twilio, name="T", config={"account_sid": "AC" + "3" * 32, "api_key_sid": "SK" + "4" * 32,
                                                                      "api_key_secret": "y" * 32, "from_number": "+15550100100"})
    old = {"mfa_phone_kind": "sms", "status": "ACTIVE", "mfa_phone_at": "2025-01-01T00:00:00+00:00"}
    ok = User(username=f"idvf-{t}", is_local=False, is_active=True, okta_id=f"00u{t}FaL", mfa_phone="+15550100188", idp=old)
    svc = User(username=f"idvs-{t}", is_local=False, is_active=True, okta_id=f"00u{t}SvC", mfa_phone="+15550100177", idp=old,
               is_service_account=True)
    gone = User(username=f"idvg-{t}", is_local=False, is_active=True, okta_id=f"00u{t}GoN", mfa_phone="+15550100166",
                idp={**old, "status": "DEPROVISIONED"})
    db.add_all([persona, twilio, ok, svc, gone])
    await db.commit()
    try:
        for who in (svc, gone):
            r = await client_cyber.post(f"/api/v1/idv/people/{who.id}/send", json={"channel": "sms"})
            assert r.status_code == 409 and "No link can go" in r.json()["detail"]

        async def no_link(self, ref, fields=None):
            e = PersonaError("Persona answered HTTP 500")
            e.inquiry = f"inq_X{t}x"
            raise e
        monkeypatch.setattr(PersonaConnector, "start_inquiry", no_link)
        assert (await client_cyber.post(f"/api/v1/idv/people/{ok.id}/send", json={"channel": "sms"})).status_code == 502
        row = (await db.execute(select(IdvRequest).where(IdvRequest.user_id == ok.id))).scalar_one()
        assert row.inquiry_id == f"inq_X{t}x" and row.state == "failed"
        # it still counts toward the limit, so retrying can't spray inquiries
        assert (await client_cyber.post(f"/api/v1/idv/people/{ok.id}/send", json={"channel": "sms"})).status_code == 429
        await db.execute(delete(IdvRequest).where(IdvRequest.user_id == ok.id))
        await db.commit()

        async def started(self, ref, fields=None):
            return f"inq_Y{t}x", "https://inquiry.withpersona.com/i/abc"

        async def down(self, to, text):
            raise TwilioError("Twilio didn't answer (ConnectTimeout)")
        monkeypatch.setattr(PersonaConnector, "start_inquiry", started)
        monkeypatch.setattr(TwilioConnector, "send", down)
        assert (await client_cyber.post(f"/api/v1/idv/people/{ok.id}/send", json={"channel": "sms"})).status_code == 502
        row = (await db.execute(select(IdvRequest).where(IdvRequest.user_id == ok.id))).scalar_one()
        assert row.inquiry_id == f"inq_Y{t}x" and row.state == "failed" and "abc" not in str(row.channels)
    finally:
        await db.execute(delete(IdvRequest).where(IdvRequest.user_id.in_([ok.id, svc.id, gone.id])))
        await db.execute(delete(IntegrationConfig).where(IntegrationConfig.id.in_([persona.id, twilio.id])))
        await db.commit()


def test_persona_link_host_is_exact():
    from api.integrations.persona import link_host_ok
    for host, good in (("inquiry.withpersona.com", True), ("withpersona.com", True), ("perso.na", True), ("evilwithpersona.com", False),
                       ("withpersona.com.evil.example", False), ("perso.na.evil.example", False), ("evilperso.na", False), (None, False)):
        assert link_host_ok(host) is good, host


@pytest.mark.asyncio
async def test_start_inquiry_accepts_personas_short_link(monkeypatch):
    """Persona answers with withpersona.com and perso.na (its shortener) links; the short one goes in the text."""
    import httpx
    from api.integrations.persona import PersonaConnector
    def handler(req):
        if req.url.path == "/api/v1/inquiries":
            return httpx.Response(201, json={"data": {"id": "inq_" + "Q" * 20}})
        return httpx.Response(200, json={"data": {}, "meta": {"one-time-link": "https://withpersona.com/verify?code=us1-x",
                                                              "one-time-link-short": "https://perso.na/verify?code=ABC"}})
    c = PersonaConnector({"api_key": "persona_production_" + "k" * 36, "allow_actions": True, "template_id": "itmpl_" + "T" * 12})
    monkeypatch.setattr(PersonaConnector, "client", lambda self: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    iid, link = await c.start_inquiry("00uABCDEFGHIJ")
    assert iid == "inq_" + "Q" * 20 and link == "https://perso.na/verify?code=ABC"
