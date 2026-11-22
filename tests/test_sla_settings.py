"""Change SLAs: one setting for ages, past-SLA flags, the dashboard and the remediation SLA check's defaults."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from api.core import sla


@pytest.fixture(autouse=True)
async def _restore(db):
    yield
    from sqlalchemy import delete

    from api.models.settings import AppSetting
    await db.execute(delete(AppSetting).where(AppSetting.key == sla.KEY))   # other tests expect the defaults
    await db.commit()
    sla._apply(dict(sla.DEFAULTS))
    sla._state["at"] = 0.0


@pytest.mark.asyncio
async def test_admins_change_slas_and_everything_follows(db, client_admin, client_it_user, client_read_only):
    from api.grc.checks import REGISTRY
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, Vulnerability
    n = uuid.uuid4().hex[:6]
    v = Vulnerability(source="test", source_vuln_id=f"sla-{n}", title=f"sla {n}", cvss_base=9.8)
    d = Device(hostname=f"sla-{n}", device_type=DeviceType.server)
    db.add_all([v, d])
    await db.flush()
    db.add(Finding(device_id=d.id, vuln_id=v.id, source="test", first_detected=datetime.now(timezone.utc) - timedelta(days=10)))
    await db.commit()
    f = lambda: client_admin.get(f"/api/v1/devices/{d.id}/findings")  # noqa: E731
    first = (await f()).json()["findings"][0]
    assert (first["sla_days"], first["past_sla"]) == (15, False)
    got = (await client_read_only.get("/api/v1/sla")).json()
    assert got["sla_days"] == sla.DEFAULTS and got["can_edit"] is False
    assert (await client_it_user.put("/api/v1/sla", json={"critical": 7, "high": 14, "medium": 30, "low": 90})).status_code in (403, 404)
    r = (await client_admin.put("/api/v1/sla", json={"critical": 7, "high": 14, "medium": 30, "low": 90})).json()
    assert r["ok"] and r["sla_days"]["critical"] == 7
    after = (await f()).json()["findings"][0]
    assert (after["sla_days"], after["past_sla"]) == (7, True)                         # 10 days old, now past a 7-day SLA
    assert REGISTRY["ctem_vuln_sla"].thresholds["critical_days"].default == 7          # the control check's default
    from api.core.vuln_dashboard import SLA_DAYS
    assert SLA_DAYS["high"] == 14
    # it is stored: a fresh load (another process) reads the same
    sla._apply(dict(sla.DEFAULTS))
    assert (await sla.load(db, force=True))["critical"] == 7


@pytest.mark.asyncio
async def test_sla_values_are_checked(client_admin):
    bad = [{"critical": 0, "high": 14, "medium": 30, "low": 90}, {"critical": 7, "high": 14, "medium": 30, "low": 400},
           {"critical": "7", "high": 14, "medium": 30, "low": 90, "extra": 1}]
    for b in bad:
        assert (await client_admin.put("/api/v1/sla", json=b)).status_code == 422
    r = (await client_admin.put("/api/v1/sla", json={"critical": 30, "high": 14, "medium": 30, "low": 90})).json()
    assert r["ok"] is False and "critical" in r["error"]
