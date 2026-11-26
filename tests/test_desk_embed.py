"""Caller verification embedded in the service desk: admins make and revoke embeds; only the embed's IP-bound token
starts a session; the framed page may be framed only by the embed's site and holds no data; the launch token works
once, briefly, from the analysts' network; the session key works only from the address that traded it; the panel
sends through the same verified-contact rules; revoking ends it all."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select

SITE = "https://acme.service-now.com"


async def _embed(client_admin, **kw):
    body = {"name": "ServiceNow test", "frame_origin": SITE, "server_ips": ["127.0.0.1"], "client_ips": ["127.0.0.0/8"], **kw}
    return await client_admin.post("/api/v1/idv/desk/embeds", json=body)


@pytest.mark.asyncio
async def test_admins_make_embeds_with_strict_settings(client_admin, client_cyber):
    assert (await _embed(client_cyber)).status_code == 403
    for bad in ({"frame_origin": "https://*.service-now.com"}, {"frame_origin": "http://acme.service-now.com"},
                {"frame_origin": "https://acme.service-now.com/path"}, {"server_ips": ["0.0.0.0/0"]}, {"client_ips": ["10.0.0.0/4"]},
                {"server_ips": []}, {"name": "<b>x</b>"}):
        assert (await _embed(client_admin, **bad)).status_code == 422, bad
    r = await _embed(client_admin)
    assert r.status_code == 201 and len(r.json()["token"]) == 64
    listed = (await client_admin.get("/api/v1/idv/desk/embeds")).json()["embeds"]
    assert any(e["id"] == r.json()["id"] for e in listed) and "token" not in str(listed)
    await client_admin.post(f"/api/v1/idv/desk/embeds/{r.json()['id']}/revoke")


@pytest.mark.asyncio
async def test_panel_flow_from_token_to_status_and_revoke(db, client_admin, client_no_auth, client_cyber, monkeypatch):
    from api.core import desk_status
    from api.integrations.persona import PersonaConnector
    from api.integrations.twilio import TwilioConnector
    from api.models.idv import DeskSession, IdvRequest
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.user import User
    t = uuid.uuid4().hex[:10]
    await db.execute(delete(IntegrationConfig).where(IntegrationConfig.vendor.in_([Vendor.persona, Vendor.twilio])))
    db.add_all([IntegrationConfig(vendor=Vendor.persona, name="P", config={"api_key": "persona_production_" + "e" * 36, "allow_actions": True,
                                                                         "template_id": "itmpl_" + "E" * 12}),
                IntegrationConfig(vendor=Vendor.twilio, name="T", config={"account_sid": "AC" + "7" * 32, "api_key_sid": "SK" + "8" * 32,
                                                                         "api_key_secret": "q" * 32, "from_number": "+15550100100"})])
    caller = User(username=f"caller{t}", is_local=False, is_active=True, okta_id=f"00u{t}CaL", first_name="Casey", last_name=f"Caller{t}",
                  mfa_phone="+15550100155", idp={"mfa_phone_kind": "sms", "status": "ACTIVE", "mfa_phone_at": "2025-01-01T00:00:00+00:00"})
    db.add(caller)
    await db.commit()
    emb = (await _embed(client_admin)).json()
    token = emb["token"]
    bearer = {"Authorization": f"Bearer {token}"}

    # the embed's token opens nothing else: not other IDV routes, not the profile, not tags
    for m, url in (("GET", "/api/v1/idv/summary"), ("GET", f"/api/v1/idv/people/{caller.id}/contacts"), ("GET", "/api/v1/tags"),
                   ("PATCH", "/api/v1/profile/prefs"), ("POST", f"/api/v1/idv/people/{caller.id}/send")):
        assert (await client_no_auth.request(m, url, headers=bearer, json={})).status_code == 403, url
    # a browser session can't start one; only the embed's token, which is bound to the server range
    assert (await client_cyber.post("/api/v1/idv/desk/sessions", json={"ticket": "INC0012345", "analyst": "jdoe"})).status_code == 403
    assert (await client_no_auth.post("/api/v1/idv/desk/sessions", json={"ticket": "INC0012345", "analyst": "jdoe", "origin": "x"},
                                      headers=bearer)).status_code == 422   # no origin field: the embed decides
    r = await client_no_auth.post("/api/v1/idv/desk/sessions", json={"ticket": "INC0012345", "analyst": "jdoe", "caller": caller.username},
                                  headers=bearer)
    assert r.status_code == 200
    launch = r.json()["launch_path"].split("#", 1)[1]
    sid = r.json()["session"]

    # the page: framed only by the embed's site, no X-Frame-Options, no data
    p = await client_no_auth.get("/desk/embed")
    csp = p.headers["content-security-policy"]
    assert p.status_code == 200 and f"frame-ancestors {SITE}" in csp and "script-src 'self';" in csp and "unsafe-inline" not in csp
    assert "x-frame-options" not in p.headers and p.headers["cache-control"] == "no-store" and caller.username not in p.text
    assert (await client_no_auth.get("/vulns")).headers.get("x-frame-options") == "DENY"   # everything else stays unframeable

    # the trade: same-origin only, once
    assert (await client_no_auth.post("/api/v1/idv/desk/exchange", json={"launch": launch}, headers={"Sec-Fetch-Site": "cross-site"})).status_code == 403
    ex = await client_no_auth.post("/api/v1/idv/desk/exchange", json={"launch": launch}, headers={"Sec-Fetch-Site": "same-origin"})
    assert ex.status_code == 200 and ex.json()["parent_origin"] == SITE and ex.json()["caller"] == caller.username
    assert (await client_no_auth.post("/api/v1/idv/desk/exchange", json={"launch": launch}, headers={"Sec-Fetch-Site": "same-origin"})).status_code == 401
    key = {"X-Desk-Key": ex.json()["key"]}

    assert (await client_no_auth.get("/api/v1/idv/desk/s/lookup", params={"q": caller.username})).status_code == 422
    assert (await client_no_auth.get("/api/v1/idv/desk/s/lookup", params={"q": caller.username}, headers={"X-Desk-Key": "x" * 43})).status_code == 401
    found = (await client_no_auth.get("/api/v1/idv/desk/s/lookup", params={"q": caller.username}, headers=key)).json()["people"]
    assert [x["username"] for x in found] == [caller.username] and "mfa" not in str(found) and "0155" not in str(found)
    card = (await client_no_auth.get(f"/api/v1/idv/desk/s/person/{caller.id}", headers=key)).json()
    assert card["channels"][0]["shown"].endswith("0155") and "5550100155" not in str(card)

    async def start_inq(self, ref, fields=None, kind="id_selfie"):
        return f"inq_D{t}x", "https://perso.na/verify?code=SECRET1"

    async def sms(self, to, text):
        assert to == "+15550100155"
        return {"sid": "SM" + "c" * 32, "status": "queued"}
    monkeypatch.setattr(PersonaConnector, "start_inquiry", start_inq)
    monkeypatch.setattr(TwilioConnector, "send", sms)

    async def no_refresh(db_, row, force=False):
        return None
    monkeypatch.setattr(desk_status, "refresh", no_refresh)
    sent = await client_no_auth.post("/api/v1/idv/desk/s/send", json={"person": caller.id, "channel": "sms"}, headers=key)
    assert sent.status_code == 200 and "SECRET1" not in sent.text
    st = (await client_no_auth.get("/api/v1/idv/desk/s/status", headers=key)).json()
    assert st["stage"] == "waiting" and st["steps"][0]["done"] and "SECRET1" not in str(st)
    row = (await db.execute(select(IdvRequest).where(IdvRequest.inquiry_id == f"inq_D{t}x"))).scalar_one()
    row.state, row.persona_status = "approved", "completed"
    row.facts = {"verifications": [{"kind": "government-id", "status": "passed", "id_type": "Driver's license", "country": "US", "checks": []},
                                   {"kind": "selfie", "status": "passed", "checks": [["selfie_id_comparison", "passed", []]]}]}
    await db.commit()
    done = (await client_no_auth.get("/api/v1/idv/desk/s/status", headers=key)).json()
    assert done["result"]["kind"] == "verified" and "Driver's license (US)" in done["result"]["detail"]
    out = (await client_no_auth.get(f"/api/v1/idv/desk/sessions/{sid}", headers=bearer)).json()
    assert out["verified"] is True and out["ticket"] == "INC0012345"

    # revoke: the token, the key and new launches all stop
    assert (await client_admin.post(f"/api/v1/idv/desk/embeds/{emb['id']}/revoke")).status_code == 200
    assert (await client_no_auth.get("/api/v1/idv/desk/s/status", headers=key)).status_code == 401
    assert (await client_no_auth.post("/api/v1/idv/desk/sessions", json={"ticket": "INC1", "analyst": "jdoe"}, headers=bearer)).status_code == 401
    page = await client_no_auth.get("/desk/embed")
    assert SITE not in page.headers["content-security-policy"] or "frame-ancestors 'none'" in page.headers["content-security-policy"]
    await db.execute(delete(DeskSession).where(DeskSession.embed_id == emb["id"]))
    await db.execute(delete(IdvRequest).where(IdvRequest.user_id == caller.id))
    await db.commit()


@pytest.mark.asyncio
async def test_launch_only_from_the_analysts_network(db, client_admin, client_no_auth):
    emb = (await _embed(client_admin, client_ips=["198.51.100.0/24"])).json()
    r = await client_no_auth.post("/api/v1/idv/desk/sessions", json={"ticket": "INC0000001", "analyst": "jdoe"},
                                  headers={"Authorization": f"Bearer {emb['token']}"})
    launch = r.json()["launch_path"].split("#", 1)[1]
    ex = await client_no_auth.post("/api/v1/idv/desk/exchange", json={"launch": launch}, headers={"Sec-Fetch-Site": "same-origin"})
    assert ex.status_code == 403   # the test client isn't on 198.51.100.0/24
    await client_admin.post(f"/api/v1/idv/desk/embeds/{emb['id']}/revoke")


@pytest.mark.asyncio
async def test_pending_holds_only_what_needs_a_decision(db, client_cyber):
    from datetime import datetime, timezone
    from api.models.idv import IdvRequest
    t = uuid.uuid4().hex[:10]
    now = datetime.now(timezone.utc)
    waiting = IdvRequest(inquiry_id=f"inq_W{t}x", state="pending", persona_status="created", origin="service_desk", created_at=now)
    review = IdvRequest(inquiry_id=f"inq_V{t}x", state="review", persona_status="failed", created_at=now)
    db.add_all([waiting, review])
    await db.commit()
    ids = {x["id"] for x in (await client_cyber.get("/api/v1/idv/requests", params={"tab": "pending", "limit": 200})).json()["requests"]}
    assert review.id in ids and waiting.id not in ids
    await db.execute(delete(IdvRequest).where(IdvRequest.id.in_([waiting.id, review.id])))
    await db.commit()
