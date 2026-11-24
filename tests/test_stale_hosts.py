"""Gone hosts lose their findings only once the network probe has confirmed they don't answer; nothing live does."""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

NOW = datetime.now(timezone.utc)
OLD = NOW - timedelta(days=40)


async def _hosts(db):
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    tag = uuid.uuid4().hex[:6]
    net = f"10.{random.randint(150, 199)}.{random.randint(0, 255)}"

    def host(name, last, **kw):
        ip = f"{net}.{last}"
        d = Device(hostname=f"{name}-{tag}", device_type=kw.pop("kind", DeviceType.server), ip=ip, ip_hash=search_hash(ip),
                   subnet_hash=search_hash(f"{net}.0/24"), **kw)
        db.add(d)
        return d
    hosts = {
        "confirmed": host("confirmed", 10, sources=",rapid7_insightvm,", last_seen=OLD, probed_at=NOW - timedelta(days=1)),
        "untried": host("untried", 11, sources=",rapid7_insightvm,", last_seen=OLD),
        "answered": host("answered", 12, sources=",rapid7_insightvm,netprobe,", last_seen=OLD, probed_at=NOW - timedelta(days=1),
                         alive_at=NOW - timedelta(days=1)),
        "scanned": host("scanned", 13, sources=",rapid7_insightvm,", last_seen=NOW - timedelta(days=2)),
        "silent_probe": host("silent", 14, sources=",netprobe,", kind=DeviceType.unknown, alive_at=OLD, probed_at=NOW - timedelta(days=1)),
    }
    v = Vulnerability(source="t_stale", source_vuln_id=f"s{tag}", title="Stale test vuln")
    db.add(v)
    await db.flush()
    db.add_all([Finding(device_id=hosts[k].id, vuln_id=v.id, source="t_stale", status=FindingStatus.open, last_seen=OLD)
                for k in ("confirmed", "untried", "answered", "scanned")])
    await db.commit()
    return {k: d.id for k, d in hosts.items()}, {k: d.ip for k, d in hosts.items()}


async def _findings(db, did):
    from api.models.vuln import Finding
    return (await db.execute(select(Finding).where(Finding.device_id == did))).scalars().all()


@pytest.mark.asyncio
async def test_only_hosts_the_probe_confirmed_offline_lose_their_findings(db):
    from api.core import stale_hosts
    from api.models.device import Device
    ids, _ = await _hosts(db)
    got = await stale_hosts.prune(db, 30)
    assert got["hosts"] >= 1 and got["probe_only"] >= 1 and got["waiting_for_probe"] >= 1
    assert await _findings(db, ids["confirmed"]) == []
    assert len(await _findings(db, ids["untried"])) == 1     # unseen, but nobody checked it's gone: kept
    assert len(await _findings(db, ids["answered"])) == 1    # it answered the probe: alive
    assert len(await _findings(db, ids["scanned"])) == 1
    assert (await db.execute(select(Device).where(Device.id == ids["confirmed"]))).scalar_one_or_none() is not None
    assert (await db.execute(select(Device).where(Device.id == ids["silent_probe"]))).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_unseen_hosts_go_on_the_probes_list_and_retention_can_be_turned_off(db):
    from api.core import netprobe, retention, stale_hosts
    ids, ips = await _hosts(db)
    t = await netprobe.targets(db)
    assert ips["untried"] in t["hosts"] and ips["untried"] not in t["skip"]   # tried so it can be confirmed
    assert ips["scanned"] not in t["hosts"]
    await retention.save(db, {"enabled": False})
    await db.commit()
    try:
        assert (await stale_hosts.prune(db))["disabled"] is True
        assert len(await _findings(db, ids["confirmed"])) == 1
        assert await stale_hosts.candidates(db) == []
    finally:
        await retention.save(db, {"enabled": True})
        await db.commit()


@pytest.mark.asyncio
async def test_retention_settings_are_for_admins_and_checked(client_admin, client_cyber):
    r = await client_admin.get("/api/v1/retention")
    assert r.status_code == 200 and r.json()["enabled"] is True and r.json()["stale_host_days"] == 30
    assert "confirmed_offline" in r.json()["now"]
    ok = await client_admin.put("/api/v1/retention", json={"enabled": True, "stale_host_days": 45, "probe_within_days": 5})
    assert ok.status_code == 200 and ok.json()["stale_host_days"] == 45
    for bad in ({"enabled": True, "stale_host_days": 3, "probe_within_days": 5},
                {"enabled": True, "stale_host_days": 45, "probe_within_days": 90},
                {"enabled": "yes", "stale_host_days": 45, "probe_within_days": 5}):
        assert (await client_admin.put("/api/v1/retention", json=bad)).status_code == 422
    assert (await client_cyber.put("/api/v1/retention", json={"enabled": False, "stale_host_days": 30, "probe_within_days": 7})).status_code == 403
    assert (await client_cyber.get("/api/v1/retention")).status_code == 403
    await client_admin.put("/api/v1/retention", json={"enabled": True, "stale_host_days": 30, "probe_within_days": 7})


def test_the_default_window_is_a_bounded_setting():
    from pydantic import ValidationError

    from api.core.config import Settings
    assert Settings.model_fields["stale_host_days"].default == 30
    with pytest.raises(ValidationError):
        Settings(stale_host_days=1, secret_key="x" * 40, database_url="sqlite+aiosqlite://")
