"""Risk register edits from CTEM go to FairTPRM: three fields, grc:write, who did it, and honest refusals."""
from __future__ import annotations

import json
import uuid

import httpx
import pytest
from sqlalchemy import select

from api.integrations import fairtprm


async def _setup(db):
    from api.models.grc import GrcRisk
    from api.models.integration import IntegrationConfig, Vendor
    if not (await db.execute(select(IntegrationConfig).where(IntegrationConfig.vendor == Vendor.fairtprm,
                                                             IntegrationConfig.is_enabled.is_(True)))).scalars().first():
        db.add(IntegrationConfig(id=str(uuid.uuid4()), vendor=Vendor.fairtprm, name="FairTPRM", is_enabled=True,
                                 config={"base_url": "https://tprm.acme.example", "api_key": "k"}))
    ext = str(uuid.uuid4().int % 10**8)
    risk = GrcRisk(source="fairtprm", external_id=ext, risk_ref=f"RSK-{ext}", title="Ransomware", status="identified")
    db.add(risk)
    await db.commit()
    return risk


def _fairtprm(seen: list, status: int = 200):
    def handle(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, json.loads(req.content or b"{}")))
        if status != 200:
            return httpx.Response(status, json={"success": False, "error": "nope"})
        body = json.loads(req.content)
        return httpx.Response(200, json={"success": True, "data": {"id": 1, "status": body.get("status"),
                                                                   "review_date": body.get("review_date"),
                                                                   "treatment_plan": body.get("treatment_plan"),
                                                                   "likelihood": "likely"}})
    return lambda **_kw: httpx.AsyncClient(transport=httpx.MockTransport(handle))


@pytest.mark.asyncio
async def test_review_goes_to_fairtprm_with_who_did_it(db, monkeypatch, client_admin):
    from api.models.settings import AuditLog
    risk = await _setup(db)
    seen = []
    monkeypatch.setattr(fairtprm, "safe_client", _fairtprm(seen))
    r = await client_admin.put(f"/api/v1/grc/risks/{risk.id}/review",
                               json={"status": "monitoring", "review_date": "2027-01-15", "treatment_plan": " Patch monthly "})
    d = r.json()
    assert r.status_code == 200 and d["saved"] and d["risk"]["status"] == "monitoring"
    method, path, body = seen[-1]
    assert (method, path) == ("PUT", f"/api/v2/grc/risks/{risk.external_id}/review")
    assert body["treatment_plan"] == "Patch monthly" and body["review_date"] == "2027-01-15" and body["acting_user"]
    await db.refresh(risk)
    assert risk.status == "monitoring" and risk.treatment_plan == "Patch monthly"
    audit = (await db.execute(select(AuditLog).where(AuditLog.action == "grc.risk_review",
                                                     AuditLog.resource_id == str(risk.id)))).scalar_one()
    assert "sent to FairTPRM" in audit.detail

    r = await client_admin.put(f"/api/v1/grc/risks/{risk.id}/review", json={"clear_review_date": True})
    assert r.json()["saved"] and seen[-1][2]["review_date"] is None


@pytest.mark.asyncio
async def test_review_refusals_and_input_checks(db, monkeypatch, client_admin, client_cyber, client_read_only):
    risk = await _setup(db)
    seen = []
    monkeypatch.setattr(fairtprm, "safe_client", _fairtprm(seen, status=403))
    d = (await client_admin.put(f"/api/v1/grc/risks/{risk.id}/review", json={"status": "closed"})).json()
    assert d == {"saved": False, "reason": "read_only", "message": d["message"]} and "read_write" in d["message"]
    monkeypatch.setattr(fairtprm, "safe_client", _fairtprm(seen, status=404))
    assert (await client_admin.put(f"/api/v1/grc/risks/{risk.id}/review", json={"status": "closed"})).json()["reason"] == "not_found"
    await db.refresh(risk)
    assert risk.status == "identified"  # nothing changed locally when FairTPRM said no

    n = len(seen)
    url = f"/api/v1/grc/risks/{risk.id}/review"
    assert (await client_admin.put(url, json={"likelihood": "rare"})).status_code == 422  # human-owned field
    assert (await client_admin.put(url, json={"status": "done"})).status_code == 422
    assert (await client_admin.put(url, json={})).status_code == 422
    assert (await client_admin.put(url, json={"treatment_plan": "x" * 10001})).status_code == 422
    assert (await client_read_only.put(url, json={"status": "closed"})).status_code == 403
    assert (await client_cyber.put(url, json={"status": "closed"})).status_code == 403  # cyber reads GRC, doesn't edit it
    assert (await client_admin.put(f"/api/v1/grc/risks/{uuid.uuid4()}/review", json={"status": "closed"})).status_code == 404
    assert len(seen) == n  # none of those reached FairTPRM

    assert (await client_admin.get("/api/v1/grc/risks")).json()["can_edit"] is True
    assert (await client_cyber.get("/api/v1/grc/risks")).json()["can_edit"] is False


def test_acting_user_fits_fairtprm():
    from types import SimpleNamespace as NS

    from api.routes.grc_risk_edit import acting_user
    assert acting_user(NS(username="jdoe", display_name="Doe, Jane")) == "jdoe (Doe, Jane)"
    assert acting_user(NS(username="x<script>", display_name=None)) == "xscript"
    assert len(acting_user(NS(username="a" * 300, display_name=None))) == 128
