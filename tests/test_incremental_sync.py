"""InsightVM incremental sync and changed-only rescoring."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from api.integrations.base import get_connector, load_sync_state, save_sync_state

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


def _c(**cfg):
    return get_connector("rapid7_insightvm", {"api_key": "example-not-a-key", **cfg})


def test_full_or_incremental_decision():
    c = _c()
    assert c._incremental_since({}, NOW) is None  # never synced: full
    recent = {"last_success": (NOW - timedelta(hours=6)).isoformat(), "last_full": (NOW - timedelta(days=2)).isoformat()}
    assert c._incremental_since(recent, NOW) == NOW - timedelta(hours=7)  # 1h overlap
    stale = {**recent, "last_full": (NOW - timedelta(days=8)).isoformat()}
    assert c._incremental_since(stale, NOW) is None  # weekly refresh due
    assert _c(full_sync_days="30")._incremental_since(stale, NOW) is not None
    assert _c(max_assets="10")._incremental_since(recent, NOW) is None
    assert _c(full_sync="true")._incremental_since(recent, NOW) is None


@pytest.mark.asyncio
async def test_incremental_run_asks_for_changes_only(db, monkeypatch):
    from sqlalchemy import select

    from api.integrations import rapid7_insightvm
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability

    run = uuid.uuid4().hex[:6]
    old_v = Vulnerability(source="rapid7_insightvm", source_vuln_id=f"{run}-old", title="old", cvss_base=9.0)
    gone_v = Vulnerability(source="rapid7_insightvm", source_vuln_id=f"{run}-gone", title="gone", cvss_base=9.0)
    dev = Device(hostname=f"inc-{run}.acme.example", device_type=DeviceType.server, source="rapid7_insightvm",
                 source_id=f"{run}-a1")
    db.add_all([old_v, gone_v, dev])
    await db.flush()
    db.add(Finding(device_id=dev.id, vuln_id=gone_v.id, source="rapid7_insightvm", status=FindingStatus.open))
    await db.commit()

    integration_id = str(uuid.uuid4())
    last_full = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    await save_sync_state(db, integration_id, {"last_success": last_full, "last_full": last_full})

    seen = {"asset_params": None, "asset_body": None, "vuln_queries": []}

    def fake_client(**_):
        def handler(request):
            if request.url.path.endswith("/assets"):
                seen["asset_params"] = dict(request.url.params)
                seen["asset_body"] = json.loads(request.content)
                return httpx.Response(200, json={"metadata": {}, "data": [{
                    "id": f"{run}-a1", "host_name": f"inc-{run}.acme.example",
                    "new": [{"vulnerability_id": f"{run}-old"}],
                    "remediated": [{"vulnerability_id": f"{run}-gone"}]}]})
            seen["vuln_queries"].append(json.loads(request.content)["vulnerability"])
            return httpx.Response(200, json={"data": []})
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(rapid7_insightvm, "safe_client", fake_client)
    c = _c()
    c.integration_id = integration_id
    assert await c.sync(db) == 1 and c.last_mode == "incremental"
    assert seen["asset_params"]["includeSame"] == "false" and "comparisonTime" in seen["asset_params"]
    assert seen["asset_body"]["asset"].startswith("asset.last_scan_end > ")
    assert seen["vuln_queries"] == []  # both vulns already stored: no catalog calls

    rows = {f.vuln_id: f.status for f in (await db.execute(
        select(Finding).where(Finding.device_id == dev.id).execution_options(populate_existing=True))).scalars()}
    assert rows[str(old_v.id)] == FindingStatus.open and rows[str(gone_v.id)] == FindingStatus.remediated
    state = await load_sync_state(db, integration_id)
    assert state["last_full"] == last_full and state["last_success"] > last_full


@pytest.mark.asyncio
async def test_first_sync_is_full_and_sets_bookmark(db, monkeypatch):
    from api.integrations import rapid7_insightvm

    params = {}

    def fake_client(**_):
        def handler(request):
            params.update(request.url.params)
            return httpx.Response(200, json={"metadata": {}, "data": []})
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(rapid7_insightvm, "safe_client", fake_client)
    c = _c()
    c.integration_id = str(uuid.uuid4())
    await c.sync(db)
    assert c.last_mode == "full" and params["includeSame"] == "true" and "comparisonTime" not in params
    state = await load_sync_state(db, c.integration_id)
    assert state["last_full"] == state["last_success"]


@pytest.mark.asyncio
async def test_rescore_only_changed_devices(db):
    from sqlalchemy import select, update

    from api.models.device import Device, DeviceType
    from api.scoring.engine import recalculate_changed

    old = Device(hostname="untouched.acme.example", device_type=DeviceType.server, source="t_rescore")
    new = Device(hostname="touched.acme.example", device_type=DeviceType.server, source="t_rescore")
    db.add_all([old, new])
    await db.commit()
    past = datetime(2020, 1, 1)
    await db.execute(update(Device).where(Device.id == old.id).values(created_at=past, updated_at=past, score_inputs_at=past))
    await db.commit()

    since = datetime.now(timezone.utc) - timedelta(minutes=5)
    await recalculate_changed(db, since)
    got = {d.hostname: d.risk_grade for d in (await db.execute(
        select(Device).where(Device.source == "t_rescore")
        .execution_options(populate_existing=True))).scalars()}
    assert got["touched.acme.example"] is not None and got["untouched.acme.example"] is None
