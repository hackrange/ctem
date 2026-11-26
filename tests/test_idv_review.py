"""IDV review: only IDV Approvers decide, with a reason; revoke and expire; badges need a verified government ID;
the name on the ID and the network are read live and never kept; the list's window and the person's history."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select


@pytest.mark.asyncio
async def test_only_idv_approvers_decide_with_a_reason_and_it_is_audited(db, client_cyber, client_admin, client_it_user,
                                                                          client_idv_approver, monkeypatch):
    from api.integrations.persona import PersonaConnector
    from api.models.idv import IdvRequest
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.settings import AuditLog
    cfg = IntegrationConfig(vendor=Vendor.persona, name="Persona", config={"api_key": "persona_production_" + "y" * 36,
                                                                        "allow_actions": True})
    db.add(cfg)
    await db.flush()
    t = uuid.uuid4().hex[:10]
    r = IdvRequest(inquiry_id=f"inq_R{t}x", integration_id=str(cfg.id), state="review", persona_status="failed",
                   facts={"verifications": [{"kind": "government-id", "status": "failed", "id_type": "Passport", "country": "IN",
                                             "checks": [["id_electronic_replica_detection", "failed", ["replica_detected"]]]}]})
    done = IdvRequest(inquiry_id=f"inq_S{t}x", integration_id=str(cfg.id), state="approved", persona_status="completed")
    db.add_all([r, done])
    await db.commit()
    calls = []

    async def fake_review(self, inquiry, approve, comment):
        calls.append((inquiry, approve, comment))
        return "approved" if approve else "declined"
    monkeypatch.setattr(PersonaConnector, "review", fake_review)
    body = {"decision": "approve", "reason": "video_call", "note": "Saw the passport on a video call"}
    assert (await client_it_user.get("/api/v1/idv/requests")).status_code == 403
    for c in (client_it_user, client_cyber, client_admin):   # seeing isn't deciding
        assert (await c.post(f"/api/v1/idv/requests/{r.id}/review", json=body)).status_code == 403
    d = (await client_cyber.get(f"/api/v1/idv/requests/{r.id}")).json()
    assert d["can"] == {"review": False, "revoke": False, "names": False} and d["reasons"] is None
    assert d["explain"]["failed"][0]["check"] == "id_electronic_replica_detection" and d["explain"]["failed"][0]["validate"]
    assert d["country"] is None or d["country"] == "IN"
    a = (await client_idv_approver.get(f"/api/v1/idv/requests/{r.id}")).json()
    assert a["can"]["review"] and a["reasons"]["approve"]["video_call"]
    assert (await client_idv_approver.get("/api/v1/idv/summary")).json()["review"] >= 1
    for bad in ({**body, "extra": 1}, {**body, "reason": "Video Call"}, {**body, "note": "x"}, {k: v for k, v in body.items() if k != "reason"}):
        assert (await client_idv_approver.post(f"/api/v1/idv/requests/{r.id}/review", json=bad)).status_code == 422
    assert (await client_idv_approver.post(f"/api/v1/idv/requests/{r.id}/review", json={**body, "reason": "name_mismatch"})).status_code == 400
    assert (await client_idv_approver.post(f"/api/v1/idv/requests/{done.id}/review", json=body)).status_code == 409
    assert (await client_idv_approver.post(f"/api/v1/idv/requests/{uuid.uuid4()}/review", json=body)).status_code == 404
    ok = await client_idv_approver.post(f"/api/v1/idv/requests/{r.id}/review", json=body)
    assert ok.status_code == 200 and ok.json()["state"] == "approved" and ok.json()["review_reason"] == "video_call"
    assert calls == [(r.inquiry_id, True, calls[0][2])] and "video call" in calls[0][2]
    audit = (await db.execute(select(AuditLog).where(AuditLog.action == "idv.approve", AuditLog.resource_id == r.id))).scalars().all()
    assert len(audit) == 1 and audit[0].detail.startswith("video_call")


@pytest.mark.asyncio
async def test_revoke_takes_the_badge_until_a_new_pass(db, client_cyber, client_idv_approver, monkeypatch):
    from api.integrations.persona import PersonaConnector
    from api.integrations.persona_ingest import link_people
    from api.models.idv import IdvRequest
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.user import User
    cfg = IntegrationConfig(vendor=Vendor.persona, name="Persona", config={"api_key": "persona_production_" + "z" * 36,
                                                                        "allow_actions": True})
    db.add(cfg)
    t = uuid.uuid4().hex[:10]
    okta = f"00u{t}ReV"
    u = User(username=f"idvr-{t}", is_local=False, is_active=True, okta_id=okta)
    db.add(u)
    await db.flush()
    gov = {"verifications": [{"kind": "government-id", "status": "passed", "checks": []}]}
    now = datetime.now(timezone.utc)
    ok = IdvRequest(inquiry_id=f"inq_V{t}x", integration_id=str(cfg.id), okta_id=okta, state="approved", persona_status="completed",
                    created_via="API", facts=gov, created_at=now - timedelta(days=3), completed_at=now - timedelta(days=3))
    db.add(ok)
    await db.commit()
    await link_people(db)
    await db.commit()
    await db.refresh(u)
    assert u.idv_verified_at is not None
    declined = []

    async def fake_review(self, inquiry, approve, comment):
        declined.append((inquiry, approve))
        return "declined"
    monkeypatch.setattr(PersonaConnector, "review", fake_review)
    body = {"reason": "fraud_suspected", "note": "Account takeover reported"}
    assert (await client_cyber.post(f"/api/v1/idv/people/{u.id}/revoke", json=body)).status_code == 403
    assert (await client_idv_approver.post(f"/api/v1/idv/people/{uuid.uuid4()}/revoke", json=body)).status_code == 404
    assert (await client_idv_approver.post(f"/api/v1/idv/people/{u.id}/revoke", json={**body, "reason": "video_call"})).status_code == 400
    r = await client_idv_approver.post(f"/api/v1/idv/people/{u.id}/revoke", json=body)
    assert r.status_code == 200 and r.json()["declined_in_persona"] == 1 and r.json()["idv_verified_at"] is None
    assert declined == [(ok.inquiry_id, False)]
    # Persona still saying approved (actions failed, or a sync) doesn't bring it back; a new pass does
    await db.refresh(ok)
    ok.state = "approved"
    full = {"verifications": gov["verifications"] + [{"kind": "selfie", "status": "passed", "checks": [["selfie_id_comparison", "passed", []]]}]}
    db.add(IdvRequest(inquiry_id=f"inq_N{t}x", integration_id=str(cfg.id), okta_id=okta, state="approved", persona_status="completed",
                      created_via="API", facts=full, created_at=datetime.now(timezone.utc) + timedelta(seconds=5),
                      completed_at=datetime.now(timezone.utc) + timedelta(seconds=5)))
    await db.commit()
    await link_people(db)
    await db.commit()
    await db.refresh(u)
    assert u.idv_revoked_kind == "revoke" and u.idv_verified_at is None   # after a revoke even a full pass waits for an approver
    pend = (await client_idv_approver.get("/api/v1/idv/requests", params={"tab": "pending", "limit": 200})).json()["requests"]
    assert any(r["id"] and r["state"] == "unproven" and r["person"]["id"] == u.id for r in pend)


@pytest.mark.asyncio
async def test_a_selfie_only_pass_proves_nothing_alone(db):
    """Okta's re-check compares a new selfie with an earlier one: it counts only for someone who passed an ID before,
    and it never clears an earlier failed ID from the review queue."""
    from api.integrations.persona_ingest import link_people
    from api.models.idv import IdvRequest
    from api.models.user import User
    t = uuid.uuid4().hex[:10]
    okta = f"00u{t}SlF"
    u = User(username=f"idvf-{t}", is_local=False, is_active=True, okta_id=okta)
    db.add(u)
    now = datetime.now(timezone.utc)
    failed = {"verifications": [{"kind": "government-id", "status": "failed",
                                 "checks": [["id_electronic_replica_detection", "failed", ["replica_detected"]]]}]}
    selfie = {"verifications": [{"kind": "selfie", "status": "passed", "checks": [["selfie_id_comparison", "not_applicable", ["no_government_id"]]]}]}
    bad = IdvRequest(inquiry_id=f"inq_B{t}x", okta_id=okta, state="review", persona_status="failed", facts=failed, created_at=now - timedelta(days=2))
    face = IdvRequest(inquiry_id=f"inq_F{t}x", okta_id=okta, state="approved", persona_status="completed", created_via="API",
                      facts=selfie, created_at=now - timedelta(days=1), completed_at=now - timedelta(days=1))
    db.add_all([bad, face])
    await db.commit()
    await link_people(db)
    await db.commit()
    await db.refresh(u)
    assert u.idv_verified_at is None and bad.state == "review"
    from api.integrations.persona_checks import explain
    assert any("Only a selfie passed" in n for n in explain(selfie)["notes"])


@pytest.mark.asyncio
async def test_live_details_for_approvers_only_never_stored(db, client_cyber, client_idv_approver, monkeypatch):
    from api.integrations.persona import PersonaConnector
    from api.models.idv import IdvRequest
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.settings import AuditLog
    cfg = IntegrationConfig(vendor=Vendor.persona, name="Persona", config={"api_key": "persona_production_" + "w" * 36})
    db.add(cfg)
    await db.flush()
    r = IdvRequest(inquiry_id=f"inq_L{uuid.uuid4().hex[:10]}x", integration_id=str(cfg.id), state="review", persona_status="failed")
    db.add(r)
    await db.commit()
    seen = []

    def handler(req: httpx.Request):
        seen.append(dict(req.url.params))
        return httpx.Response(200, json={"data": {"id": r.inquiry_id}, "included": [
            {"type": "verification/government-id", "attributes": {"status": "failed", "id-class": "pp", "country-code": "IN",
                                                                  "name-first": "Asha", "name-last": "Rao", "identification-number": "Z123"}},
            {"type": "inquiry-session", "attributes": {"created-at": "2026-10-28T12:00:00Z", "device-type": "mobile", "ip-isp": "Example Telecom",
                                                       "country-name": "India", "ip-address": "198.51.100.4", "latitude": 12.9}}]})
    real = PersonaConnector.client
    monkeypatch.setattr(PersonaConnector, "client", lambda self: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert (await client_cyber.get(f"/api/v1/idv/requests/{r.id}/live")).status_code == 403
    got = await client_idv_approver.get(f"/api/v1/idv/requests/{r.id}/live")
    monkeypatch.setattr(PersonaConnector, "client", real)
    assert got.status_code == 200 and got.headers["cache-control"] == "no-store"
    d = got.json()
    assert d["on_id"][0]["first"] == "Asha" and d["on_id"][0]["id_type"] == "Passport" and d["sessions"][0]["isp"] == "Example Telecom"
    assert "Z123" not in got.text and "198.51.100.4" not in got.text and "12.9" not in got.text
    assert "ip-address" not in seen[0]["fields[inquiry-session]"] and "identification-number" not in seen[0]["fields[verification/government-id]"]
    await db.refresh(r)
    assert "Asha" not in str(r.facts) and "Example Telecom" not in str(r.facts)
    assert (await db.execute(select(AuditLog).where(AuditLog.action == "idv.view_live", AuditLog.resource_id == r.id))).scalars().first()


def test_verification_outline_keeps_no_personal_data():
    from api.integrations.persona_checks import verification_facts
    vs = verification_facts([{"type": "verification/government-id", "attributes": {
        "status": "failed", "id-class": "dl", "country-code": "IN", "capture-method": "auto", "name-first": "Asha",
        "identification-number": "Z123", "birthdate": "1990-01-01", "front-photo-url": "https://x/y",
        "checks": [{"name": "id_electronic_replica_detection", "status": "failed", "reasons": ["replica_detected"], "requirement": "required"},
                   {"name": "id_barcode_detection", "status": "not_applicable", "reasons": ["unsupported_country"], "requirement": "required"},
                   {"name": "<script>", "status": "failed"}]}}, {"type": "inquiry-session", "attributes": {}}])
    assert vs == [{"kind": "government-id", "status": "failed", "id_class": "dl", "id_type": "Driver's license", "country": "IN",
                   "capture": "auto", "checks": [["id_electronic_replica_detection", "failed", ["replica_detected"]]]}]


@pytest.mark.asyncio
async def test_an_untrusted_id_pass_never_unlocks_a_selfie_badge(db):
    """Someone with the person's Okta session passes a hosted-link check with their own ID: that row never counts,
    and the next selfie-only re-check (now matching the impostor's face) mustn't count either. Nor a check whose
    verifications haven't been read, once CTEM reads them."""
    from api.integrations.persona_ingest import link_people
    from api.models.idv import IdvRequest
    from api.models.user import User
    t = uuid.uuid4().hex[:10]
    okta, okta2 = f"00u{t}HoS", f"00u{t}UnR"
    victim = User(username=f"idvh-{t}", is_local=False, is_active=True, okta_id=okta)
    fresh = User(username=f"idvu-{t}", is_local=False, is_active=True, okta_id=okta2)
    db.add_all([victim, fresh])
    later = datetime(2026, 12, 2, tzinfo=timezone.utc)
    gov = {"verifications": [{"kind": "government-id", "status": "passed", "checks": []}]}
    selfie = {"verifications": [{"kind": "selfie", "status": "passed", "checks": []}]}
    db.add_all([
        IdvRequest(inquiry_id=f"inq_H{t}x", okta_id=okta, state="approved", persona_status="completed", created_via="other",
                   facts=gov, created_at=later, completed_at=later),
        IdvRequest(inquiry_id=f"inq_S{t}x", okta_id=okta, state="approved", persona_status="completed", created_via="API",
                   facts=selfie, created_at=later + timedelta(days=1), completed_at=later + timedelta(days=1)),
        IdvRequest(inquiry_id=f"inq_U{t}x", okta_id=okta2, state="approved", persona_status="completed", created_via="API",
                   facts={}, created_at=later, completed_at=later)])
    await db.commit()
    await link_people(db)
    await db.commit()
    await db.refresh(victim)
    await db.refresh(fresh)
    assert victim.idv_verified_at is None and fresh.idv_verified_at is None


@pytest.mark.asyncio
async def test_list_window_hides_expired_and_counts_history(db, client_cyber):
    from api.models.idv import IdvRequest
    t = uuid.uuid4().hex[:10]
    okta = f"00u{t}WiN"
    now = datetime.now(timezone.utc)
    new = IdvRequest(inquiry_id=f"inq_N{t}x", okta_id=okta, state="review", persona_status="failed", created_at=now - timedelta(days=1))
    old = IdvRequest(inquiry_id=f"inq_O{t}x", okta_id=okta, state="review", persona_status="failed", created_at=now - timedelta(days=9))
    gone = IdvRequest(inquiry_id=f"inq_G{t}x", okta_id=okta, state="expired", persona_status="expired", created_at=now - timedelta(days=1))
    ok = IdvRequest(inquiry_id=f"inq_A{t}x", okta_id=okta, state="approved", persona_status="completed", created_at=now - timedelta(days=20),
                    completed_at=now - timedelta(days=20), facts={"verifications": [{"kind": "government-id", "status": "passed", "checks": []}]})
    db.add_all([new, old, gone, ok])
    await db.commit()
    r = (await client_cyber.get("/api/v1/idv/requests", params={"tab": "pending", "days": 5, "limit": 200})).json()
    ids = {x["id"] for x in r["requests"]}
    assert new.id in ids and old.id not in ids and r["older"] >= 1
    rej = (await client_cyber.get("/api/v1/idv/requests", params={"tab": "rejected", "limit": 200})).json()
    assert gone.id not in {x["id"] for x in rej["requests"]}
    d = (await client_cyber.get(f"/api/v1/idv/requests/{new.id}")).json()
    assert d["history"]["verified"] == 1 and d["history"]["failed"] == 1 and d["history"]["id_passed_before"] is True
    assert (await client_cyber.get("/api/v1/idv/requests", params={"days": 0})).status_code == 422


@pytest.mark.asyncio
async def test_passed_but_never_id_verified_waits_for_an_approver(db, client_cyber, client_idv_approver, monkeypatch):
    from api.integrations.persona import PersonaConnector
    from api.integrations.persona_ingest import link_people
    from api.models.idv import IdvRequest
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.user import User
    cfg = IntegrationConfig(vendor=Vendor.persona, name="P", config={"api_key": "persona_production_" + "u" * 36, "allow_actions": True})
    db.add(cfg)
    t = uuid.uuid4().hex[:10]
    u = User(username=f"idvp-{t}", is_local=False, is_active=True, okta_id=f"00u{t}PrV")
    db.add(u)
    await db.flush()
    now = datetime.now(timezone.utc)
    r = IdvRequest(inquiry_id=f"inq_P{t}x", integration_id=str(cfg.id), okta_id=u.okta_id, state="approved", persona_status="completed",
                   created_via="API", created_at=now, completed_at=now,
                   facts={"verifications": [{"kind": "selfie", "status": "passed", "checks": []}]})
    db.add(r)
    await db.commit()
    await link_people(db)
    await db.commit()
    pend = (await client_cyber.get("/api/v1/idv/requests", params={"tab": "pending", "q": u.username, "limit": 200})).json()
    assert [(x["id"], x["state"]) for x in pend["requests"]] == [(r.id, "unproven")]
    appr = (await client_cyber.get("/api/v1/idv/requests", params={"tab": "approved", "q": u.username})).json()
    assert appr["requests"] == []
    assert (await client_cyber.get("/api/v1/idv/summary")).json()["unproven"] >= 1
    assert (await client_idv_approver.get(f"/api/v1/idv/requests/{r.id}")).json()["can"]["review"] is True

    async def fake_review(self, inquiry, approve, comment):
        return "approved"
    monkeypatch.setattr(PersonaConnector, "review", fake_review)
    ok = await client_idv_approver.post(f"/api/v1/idv/requests/{r.id}/review",
                                        json={"decision": "approve", "reason": "video_call", "note": "Saw ID on video"})
    assert ok.status_code == 200 and ok.json()["state"] == "approved"
    await db.refresh(u)
    assert u.idv_verified_at is not None


@pytest.mark.asyncio
async def test_expire_needs_a_new_verification_without_declining(db, client_idv_approver, monkeypatch):
    from api.integrations.persona import PersonaConnector
    from api.integrations.persona_ingest import link_people
    from api.models.idv import IdvRequest
    from api.models.settings import AuditLog
    from api.models.user import User
    t = uuid.uuid4().hex[:10]
    u = User(username=f"idve-{t}", is_local=False, is_active=True, okta_id=f"00u{t}ExP")
    db.add(u)
    now = datetime.now(timezone.utc) - timedelta(days=2)
    db.add(IdvRequest(inquiry_id=f"inq_E{t}x", okta_id=u.okta_id, state="approved", persona_status="completed", created_via="API",
                      created_at=now, completed_at=now, facts={"verifications": [{"kind": "government-id", "status": "passed", "checks": []}]}))
    await db.commit()
    await link_people(db)
    await db.commit()
    calls = []

    async def fake_review(self, *a):
        calls.append(a)
        return "declined"
    monkeypatch.setattr(PersonaConnector, "review", fake_review)
    assert (await client_idv_approver.post(f"/api/v1/idv/people/{u.id}/revoke",
                                           json={"mode": "expire", "reason": "fraud_suspected", "note": "wrong list"})).status_code == 400
    r = await client_idv_approver.post(f"/api/v1/idv/people/{u.id}/revoke", json={"mode": "expire", "reason": "role_change", "note": "New admin role"})
    assert r.status_code == 200 and r.json()["idv_verified_at"] is None and calls == []
    assert (await db.execute(select(AuditLog).where(AuditLog.action == "idv.expire", AuditLog.resource_id == u.id))).scalars().first()


@pytest.mark.asyncio
async def test_bubble_counts_only_the_last_five_days(db, client_cyber):
    from api.models.idv import IdvRequest
    t = uuid.uuid4().hex[:10]
    now = datetime.now(timezone.utc)
    before = (await client_cyber.get("/api/v1/idv/summary")).json()
    db.add_all([IdvRequest(inquiry_id=f"inq_R{t}x", state="review", persona_status="failed", created_at=now - timedelta(days=1)),
                IdvRequest(inquiry_id=f"inq_Q{t}x", state="review", persona_status="failed", created_at=now - timedelta(days=8))])
    await db.commit()
    after = (await client_cyber.get("/api/v1/idv/summary")).json()
    assert after["review_recent"] - before["review_recent"] == 1 and after["review"] - before["review"] == 2


@pytest.mark.asyncio
async def test_after_a_revoke_only_id_and_face_bring_the_badge_back(db):
    from api.integrations.persona_ingest import link_people
    from api.models.idv import IdvRequest
    from api.models.user import User
    t = uuid.uuid4().hex[:10]
    now = datetime.now(timezone.utc)
    u = User(username=f"idvk-{t}", is_local=False, is_active=True, okta_id=f"00u{t}RvK", idv_revoked_at=now - timedelta(days=1),
             idv_revoked_kind="expire")
    db.add(u)
    id_only = {"verifications": [{"kind": "government-id", "status": "passed", "checks": []}]}
    both = {"verifications": [{"kind": "government-id", "status": "passed", "checks": []},
                              {"kind": "selfie", "status": "passed", "checks": [["selfie_id_comparison", "passed", []]]}]}
    db.add(IdvRequest(inquiry_id=f"inq_I{t}x", okta_id=u.okta_id, state="approved", persona_status="completed", created_via="API",
                      facts=id_only, created_at=now - timedelta(hours=2), completed_at=now - timedelta(hours=2)))
    await db.commit()
    await link_people(db)
    await db.commit()
    await db.refresh(u)
    assert u.idv_verified_at is None   # an ID without a matching face isn't enough after a revoke
    db.add(IdvRequest(inquiry_id=f"inq_B{t}x", okta_id=u.okta_id, state="approved", persona_status="completed", created_via="API",
                      facts=both, created_at=now - timedelta(hours=1), completed_at=now - timedelta(hours=1)))
    await db.commit()
    await link_people(db)
    await db.commit()
    await db.refresh(u)
    assert u.idv_verified_at is not None



@pytest.mark.asyncio
async def test_expire_or_revoke_can_send_the_link_in_the_same_step(db, client_idv_approver, monkeypatch):
    from api.integrations.persona import PersonaConnector
    from api.integrations.persona_ingest import link_people
    from api.integrations.twilio import TwilioConnector
    from api.models.idv import IdvRequest
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.user import User
    t = uuid.uuid4().hex[:10]
    from sqlalchemy import delete
    await db.execute(delete(IntegrationConfig).where(IntegrationConfig.vendor.in_([Vendor.persona, Vendor.twilio])))
    db.add_all([IntegrationConfig(vendor=Vendor.persona, name="P", config={"api_key": "persona_production_" + "j" * 36, "allow_actions": True,
                                                                         "template_id": "itmpl_" + "J" * 12}),
                IntegrationConfig(vendor=Vendor.twilio, name="T", config={"account_sid": "AC" + "9" * 32, "api_key_sid": "SK" + "0" * 32,
                                                                         "api_key_secret": "k" * 32, "from_number": "+15550100100"})])
    u = User(username=f"idvx-{t}", is_local=False, is_active=True, okta_id=f"00u{t}SnD", mfa_phone="+15550100144",
             idp={"mfa_phone_kind": "sms", "status": "ACTIVE", "mfa_phone_at": "2025-01-01T00:00:00+00:00"})
    db.add(u)
    now = datetime.now(timezone.utc) - timedelta(days=3)
    both = {"verifications": [{"kind": "government-id", "status": "passed", "checks": []},
                              {"kind": "selfie", "status": "passed", "checks": [["selfie_id_comparison", "passed", []]]}]}
    db.add(IdvRequest(inquiry_id=f"inq_X{t}x", okta_id=u.okta_id, state="approved", persona_status="completed", created_via="API",
                      facts=both, created_at=now, completed_at=now))
    await db.commit()
    await link_people(db)
    await db.commit()
    sent = []

    async def start(self, ref, fields=None):
        return f"inq_L{t}x", "https://perso.na/verify?code=Z"

    async def sms(self, to, text):
        sent.append(to)
        return {"sid": "SM" + "d" * 32, "status": "queued"}
    monkeypatch.setattr(PersonaConnector, "start_inquiry", start)
    monkeypatch.setattr(TwilioConnector, "send", sms)
    r = await client_idv_approver.post(f"/api/v1/idv/people/{u.id}/revoke",
                                       json={"mode": "expire", "reason": "reverify_required", "note": "Annual check", "send": "sms"})
    assert r.status_code == 200 and r.json()["kind"] == "expire" and r.json()["link"]["sent"] and sent == ["+15550100144"]
    await db.refresh(u)
    assert u.idv_verified_at is None and u.idv_revoked_kind == "expire"
    assert (await client_idv_approver.post(f"/api/v1/idv/people/{u.id}/revoke",
                                           json={"mode": "expire", "reason": "reverify_required", "note": "x y z", "send": "fax"})).status_code == 422
    await db.execute(delete(IdvRequest).where(IdvRequest.okta_id == u.okta_id))
    await db.commit()
