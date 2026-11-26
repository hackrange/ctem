"""Selfie or ID + selfie: someone with a valid verified ID on file (Daffy) gets a selfie check; someone without one
(Elmer), or anyone after an expire or revoke, gets a government ID and a selfie; a sender can raise a selfie to ID +
selfie but never lower it; each kind uses its own Persona template."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

NOW = datetime.now(timezone.utc)
GOV = {"verifications": [{"kind": "government-id", "status": "passed", "id_type": "Driver's license", "country": "US", "checks": []},
                         {"kind": "selfie", "status": "passed", "checks": [["selfie_id_comparison", "passed", []]]}]}
CFG = {"api_key": "persona_production_" + "v" * 36, "allow_actions": True, "template_id": "itmpl_" + "G" * 12,
       "selfie_template_id": "itmpl_" + "S" * 12}


async def _people(db, t):
    from api.models.idv import IdvRequest
    from api.models.user import User
    idp = {"mfa_phone_kind": "sms", "status": "ACTIVE", "mfa_phone_at": "2025-01-01T00:00:00+00:00"}
    elmer = User(username=f"elmer{t}", is_local=False, is_active=True, okta_id=f"00u{t}ElM", mfa_phone="+15550100111", idp=idp)
    daffy = User(username=f"daffy{t}", is_local=False, is_active=True, okta_id=f"00u{t}DaF", mfa_phone="+15550100122", idp=idp)
    db.add_all([elmer, daffy])
    await db.flush()
    db.add(IdvRequest(inquiry_id=f"inq_D{t}x", user_id=daffy.id, okta_id=daffy.okta_id, state="approved", persona_status="completed",
                      created_via="API", facts=GOV, created_at=NOW - timedelta(days=30), completed_at=NOW - timedelta(days=30)))
    await db.commit()
    return elmer, daffy


@pytest.mark.asyncio
async def test_plan_selfie_only_with_a_valid_id_on_file(db):
    from fastapi import HTTPException
    from api.core.verified_id import plan
    elmer, daffy = await _people(db, uuid.uuid4().hex[:10])
    assert (await plan(db, elmer, CFG))["kind"] == "id_selfie"
    d = await plan(db, daffy, CFG)
    assert d["kind"] == "selfie" and d["active_id"]["id_type"] == "Driver's license"
    assert (await plan(db, daffy, CFG, "id_selfie"))["kind"] == "id_selfie"            # a sender can always raise it
    assert (await plan(db, daffy, {**CFG, "selfie_template_id": ""}))["kind"] == "id_selfie"   # no selfie template: ID + selfie
    with pytest.raises(HTTPException):
        await plan(db, elmer, CFG, "selfie")                                              # never a way around the ID
    daffy.idv_revoked_at, daffy.idv_revoked_kind = NOW - timedelta(days=1), "expire"
    await db.commit()
    assert (await plan(db, daffy, CFG))["kind"] == "id_selfie"                            # after an expire the old ID doesn't count


@pytest.mark.asyncio
async def test_send_uses_the_right_template(db, client_idv_approver, monkeypatch):
    from api.integrations.persona import PersonaConnector
    from api.integrations.twilio import TwilioConnector
    from api.models.idv import IdvRequest
    from api.models.integration import IntegrationConfig, Vendor
    t = uuid.uuid4().hex[:10]
    await db.execute(delete(IntegrationConfig).where(IntegrationConfig.vendor.in_([Vendor.persona, Vendor.twilio])))
    db.add_all([IntegrationConfig(vendor=Vendor.persona, name="P", config=CFG),
                IntegrationConfig(vendor=Vendor.twilio, name="T", config={"account_sid": "AC" + "4" * 32, "api_key_sid": "SK" + "5" * 32,
                                                                         "api_key_secret": "p" * 32, "from_number": "+15550100100"})])
    elmer, daffy = await _people(db, t)
    kinds = []

    async def start(self, ref, fields=None, kind="id_selfie"):
        kinds.append((ref, kind))
        return f"inq_{kind[:2].upper()}{uuid.uuid4().hex[:12]}", "https://perso.na/verify?code=Q"

    async def sms(self, to, text):
        return {"sid": "SM" + "e" * 32, "status": "queued"}
    monkeypatch.setattr(PersonaConnector, "start_inquiry", start)
    monkeypatch.setattr(TwilioConnector, "send", sms)
    c = (await client_idv_approver.get(f"/api/v1/idv/people/{daffy.id}/contacts")).json()
    assert c["plan"]["kind"] == "selfie"
    r = await client_idv_approver.post(f"/api/v1/idv/people/{daffy.id}/send", json={"channel": "sms"})
    assert r.status_code == 200 and r.json()["kind"] == "selfie"
    r = await client_idv_approver.post(f"/api/v1/idv/people/{elmer.id}/send", json={"channel": "sms", "kind": "selfie"})
    assert r.status_code == 409   # Elmer has no ID on file
    r = await client_idv_approver.post(f"/api/v1/idv/people/{elmer.id}/send", json={"channel": "sms"})
    assert r.status_code == 200 and r.json()["kind"] == "id_selfie"
    assert kinds == [(daffy.okta_id, "selfie"), (elmer.okta_id, "id_selfie")]
    row = (await db.execute(select(IdvRequest).where(IdvRequest.user_id == daffy.id, IdvRequest.origin == "service_desk"))).scalar_one()
    assert row.check_kind == "selfie"
    await db.execute(delete(IdvRequest).where(IdvRequest.user_id.in_([elmer.id, daffy.id])))
    await db.commit()


def test_selfie_check_counts_only_with_a_face_match():
    from api.integrations.persona_checks import selfie_matched
    assert selfie_matched({"verifications": [{"kind": "selfie", "status": "passed", "checks": [["selfie_account_comparison", "passed", []]]}]})
    assert not selfie_matched({"verifications": [{"kind": "selfie", "status": "passed", "checks": [["selfie_account_comparison", "not_applicable", []]]}]})
