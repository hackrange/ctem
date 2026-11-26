"""Twilio Send test text: admins only, E.164 numbers only (tidied, never guessed), fixed text, rate limited, audited
with the number masked; and the sending number is tidied and checked on save."""
from __future__ import annotations

import pytest
from sqlalchemy import delete, select


def test_numbers_must_be_international():
    from api.integrations.idv_config import check
    from api.routes.sms_test import e164
    assert e164("+1 (239) 347-9872") == "+12393479872" and e164("+44 20 7946 0958") == "+442079460958"
    for bad in ("239-347-9872", "12393479872", "+0123456789", "+1239347987212345678", "+1 239 ext 5"):
        assert e164(bad) is None, bad
    cfg = {"account_sid": "AC" + "a" * 32, "api_key_sid": "SK" + "b" * 32, "from_number": "+1 (239) 347-9872"}
    check("twilio", cfg)
    assert cfg["from_number"] == "+12393479872"
    with pytest.raises(ValueError, match="international"):
        check("twilio", {**cfg, "from_number": "239-347-9872"})


@pytest.mark.asyncio
async def test_send_test_text(db, client_admin, client_cyber, monkeypatch):
    from api.integrations.twilio import TwilioConnector, TwilioError
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.settings import AuditLog
    cfg = IntegrationConfig(vendor=Vendor.twilio, name="T", config={"account_sid": "AC" + "5" * 32, "api_key_sid": "SK" + "6" * 32,
                                                                   "api_key_secret": "z" * 32, "from_number": "+15550100100"})
    db.add(cfg)
    await db.commit()
    sent = []

    async def fake(self, to, text):
        sent.append((to, text))
        return {"sid": "SM" + "b" * 32, "status": "queued"}
    monkeypatch.setattr(TwilioConnector, "send", fake)
    try:
        url = f"/api/v1/integrations/{cfg.id}/sms-test"
        assert (await client_cyber.post(url, json={"to": "+15550100199"})).status_code == 403
        assert (await client_admin.post(url, json={"to": "555-010-0199"})).status_code == 400
        assert (await client_admin.post(url, json={"to": "+1555<script>"})).status_code == 422
        r = await client_admin.post(url, json={"to": "+1 (555) 010-0199"})
        assert r.status_code == 200 and r.json()["to"].endswith("0199") and "555" not in r.json()["to"]
        assert sent[0][0] == "+15550100199" and "http" not in sent[0][1]
        a = (await db.execute(select(AuditLog).where(AuditLog.action == "integration.sms_test", AuditLog.resource_id == cfg.id))).scalars().all()
        assert a and "5550100199" not in a[0].detail
        for _ in range(4):
            assert (await client_admin.post(url, json={"to": "+15550100199"})).status_code == 200
        assert (await client_admin.post(url, json={"to": "+15550100199"})).status_code == 429

        async def refused(self, to, text):
            raise TwilioError("Twilio refused the message (HTTP 401, code 20003)")
        monkeypatch.setattr(TwilioConnector, "send", refused)
        await db.execute(delete(AuditLog).where(AuditLog.action == "integration.sms_test", AuditLog.resource_id == cfg.id))
        await db.commit()
        bad = await client_admin.post(url, json={"to": "+15550100199"})
        assert bad.status_code == 502 and "20003" in bad.json()["detail"]
    finally:
        await db.execute(delete(AuditLog).where(AuditLog.resource_id == cfg.id))
        await db.execute(delete(IntegrationConfig).where(IntegrationConfig.id == cfg.id))
        await db.commit()
