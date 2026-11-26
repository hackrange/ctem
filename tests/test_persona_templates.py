"""Persona > Templates in use: Persona's list joined with CTEM's use of each template; admins only; reads only."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import delete


@pytest.mark.asyncio
async def test_templates_in_use(db, client_admin, client_cyber, monkeypatch):
    from api.integrations.persona import PersonaConnector
    from api.models.idv import IdvRequest
    from api.models.integration import IntegrationConfig, Vendor
    t = uuid.uuid4().hex[:8]
    used, idle = "itmpl_" + f"U{t}".ljust(12, "x"), "itmpl_" + f"I{t}".ljust(12, "x")
    cfg = IntegrationConfig(vendor=Vendor.persona, name="P", config={"api_key": "persona_production_" + "t" * 36, "template_id": used})
    db.add(cfg)
    await db.flush()
    now = datetime.now(timezone.utc)
    db.add_all([IdvRequest(inquiry_id=f"inq_{t}{n}xxxxxx", integration_id=cfg.id, template_id=used, state=s, created_at=now - timedelta(days=d),
                           facts={"verifications": [{"kind": "selfie", "status": "passed", "checks": []}]} if n == 0 else {})
                for n, (s, d) in enumerate((("approved", 2), ("review", 40), ("approved", 3)))])
    await db.commit()
    seen = []

    def handler(req):
        seen.append((req.method, req.url.path))
        return httpx.Response(200, json={"data": [{"id": used, "attributes": {"name": "Employees", "status": "active"}},
                                                  {"id": idle, "attributes": {"name": "Old copy", "status": "inactive"}}], "links": {}})
    monkeypatch.setattr(PersonaConnector, "client", lambda self: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    try:
        assert (await client_cyber.get(f"/api/v1/integrations/{cfg.id}/persona-templates")).status_code == 403
        d = (await client_admin.get(f"/api/v1/integrations/{cfg.id}/persona-templates")).json()
        rows = {r["id"]: r for r in d["templates"]}
        assert rows[used]["uses"] == 3 and rows[used]["last_30_days"] == 2 and rows[used]["passed"] == 2 and rows[used]["selfie_only"] == 1
        assert rows[used]["ctem_uses"] == ["Government ID + selfie links"] and rows[idle]["uses"] == 0 and rows[idle]["status"] == "inactive"
        assert d["templates"][0]["id"] == used and {m for m, _ in seen} == {"GET"}
    finally:
        await db.execute(delete(IdvRequest).where(IdvRequest.integration_id == cfg.id))
        await db.execute(delete(IntegrationConfig).where(IntegrationConfig.id == cfg.id))
        await db.commit()
