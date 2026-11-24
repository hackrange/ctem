"""Reachable, not scanned: hosts a pentest, cloud inventory or the probe reached that no vulnerability scanner covers."""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.grc.checks import REGISTRY, evaluate
from api.models.base import Base

NOW = datetime.now(timezone.utc)


@pytest_asyncio.fixture
async def gdb():
    """A private database so the counts are exact."""
    path = tempfile.mktemp(prefix="ctem_cov_", suffix=".db")
    eng = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(eng, expire_on_commit=False)() as s:
        yield s
    await eng.dispose()
    os.unlink(path)


async def _scanner(db):
    """A vulnerability scanner that synced an hour ago: checks refuse to grade without their data source."""
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    cfg = IntegrationConfig(vendor=Vendor("rapid7_insightvm"), name="scanner", is_enabled=True, config={})
    db.add(cfg)
    await db.flush()
    at = NOW - timedelta(hours=1)
    db.add(SyncJob(integration_id=str(cfg.id), vendor="rapid7_insightvm", status=SyncStatus.success, started_at=at, finished_at=at))
    await db.commit()


@pytest.mark.asyncio
async def test_reachable_hosts_no_scanner_covers(gdb):
    await _scanner(gdb)
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability

    def host(name, sources, **kw):
        d = Device(hostname=name, device_type=kw.pop("kind", DeviceType.unknown), sources=sources, ip=kw.pop("ip", "10.0.0.1"),
                   subnet_hash=search_hash("10.0.0.0/24"), **kw)
        gdb.add(d)
        return d
    php = host("10.128.142.13", ",horizon3,", ip="10.128.142.13", open_findings=1)
    scanned = host("server001", ",horizon3,rapid7_insightvm,", kind=DeviceType.server, last_seen=NOW - timedelta(days=2))
    old = host("10.0.0.9", ",horizon3,")
    probed = host("10.0.0.20", ",netprobe,", alive_at=NOW - timedelta(days=1), alive_ports="23/tcp")
    bucket = host("acme-bucket", ",rapid7_cloudsec,horizon3,", kind=DeviceType.cloud_resource)
    v = Vulnerability(source="horizon3", source_vuln_id="php2shell", title="PHP Possibly Affected by PHP2Shell", cvss_base=9.8)
    gdb.add(v)
    await gdb.flush()
    gdb.add_all([Finding(device_id=php.id, vuln_id=v.id, source="horizon3", status=FindingStatus.open, last_seen=NOW - timedelta(days=3)),
                 Finding(device_id=scanned.id, vuln_id=v.id, source="horizon3", status=FindingStatus.open, last_seen=NOW - timedelta(days=3)),
                 Finding(device_id=old.id, vuln_id=v.id, source="horizon3", status=FindingStatus.open, last_seen=NOW - timedelta(days=120)),
                 Finding(device_id=bucket.id, vuln_id=v.id, source="horizon3", status=FindingStatus.open, last_seen=NOW - timedelta(days=3))])
    await gdb.commit()

    body, out = await evaluate(gdb, REGISTRY["ctem_reachable_unscanned"], {}, detail=True)
    d = out.details
    assert (d["reachable"], d["unscanned"], d["unscanned_with_findings"]) == (3, 2, 1)   # php, scanned, probed; not old or the bucket
    assert out.result == "fail"   # one of them already has open findings
    rows = {r["hostname"]: r for r in out.rows}
    assert set(rows) == {"10.128.142.13", "10.0.0.20"}
    assert rows["10.128.142.13"]["known_by"] == "pentest" and rows["10.128.142.13"]["top_finding"].startswith("PHP")
    assert rows["10.0.0.20"]["known_by"] == "network probe" and rows["10.128.142.13"]["scanner_last_seen"] == "never"
    assert out.rows[0]["hostname"] == "10.128.142.13"   # worst first


@pytest.mark.asyncio
async def test_nothing_reached_is_an_error_not_a_pass(gdb):
    await _scanner(gdb)
    _, out = await evaluate(gdb, REGISTRY["ctem_reachable_unscanned"], {})
    assert out.result == "error"
