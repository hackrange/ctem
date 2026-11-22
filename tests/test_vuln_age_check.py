"""CTEM control check: vulnerability age (Infrastructure, Code and Web apps, against the install's SLAs)."""
from __future__ import annotations

import contextlib
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.core import sla
from api.grc.checks import REGISTRY, evaluate
from api.models.base import Base

NOW = datetime.now(timezone.utc)
CHECK = REGISTRY["ctem_vuln_age"]


@pytest_asyncio.fixture
async def gdb():
    path = tempfile.mktemp(prefix="ctem_age_", suffix=".db")
    eng = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(eng, expire_on_commit=False)() as s:
        yield s
    await eng.dispose()
    sla._apply(dict(sla.DEFAULTS))
    sla._state["at"] = 0.0
    with contextlib.suppress(OSError):
        os.unlink(path)


async def _seed(db):
    from api.models.device import Device, DeviceType
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    for vendor in ("rapid7_insightvm", "github_code_review"):
        cfg = IntegrationConfig(vendor=Vendor(vendor), name=vendor, is_enabled=True, config={})
        db.add(cfg)
        await db.flush()
        db.add(SyncJob(integration_id=str(cfg.id), vendor=vendor, status=SyncStatus.success, started_at=NOW, finished_at=NOW))
    host = Device(hostname="srv-acme-01", device_type=DeviceType.server, last_seen=NOW)
    repo = Device(hostname="acme/claims-portal", device_type=DeviceType.code_repository, last_seen=NOW)
    site = Device(hostname="portal.acme.example", device_type=DeviceType.website, last_seen=NOW)
    db.add_all([host, repo, site])
    rows = [  # (device, domain, cvss, days old)
        (host, "infra", 9.8, 20), (host, "infra", 9.8, 5), (host, "infra", 7.5, 400), (host, "infra", 5.0, 30),
        (repo, "code", 7.5, 45), (repo, "code", 2.0, 500), (site, "web", 5.0, 120)]
    await db.flush()
    for i, (dev, dom, cvss, age) in enumerate(rows):
        v = Vulnerability(source="test", source_vuln_id=f"age-{i}-{uuid.uuid4().hex[:4]}", title=f"Flaw {i}", cvss_base=cvss, domain=dom)
        db.add(v)
        await db.flush()
        db.add(Finding(device_id=dev.id, vuln_id=v.id, source="test", domain=dom, status=FindingStatus.open,
                       first_detected=NOW - timedelta(days=age)))
    await db.commit()


@pytest.mark.asyncio
async def test_age_against_the_install_slas_for_every_type(gdb):
    await _seed(gdb)
    body, out = await evaluate(gdb, CHECK, {}, detail=True)
    d = body["details"]
    # medium and up (6 findings): critical 20 > 15, high 400 > 30, high 45 > 30, medium 120 > 90 are too old
    assert d["open_findings"] == 6 and d["too_old"] == 4 and body["result"] == "fail"
    assert d["too_old_by_severity"] == {"critical": 1, "high": 2, "medium": 1}
    assert d["too_old_by_type"] == {"infra": 2, "code": 1, "web": 1}
    assert d["oldest_days"] == 400 and d["uses_install_sla"] and d["limits_days"]["critical"] == 15
    assert sum(d["age_buckets_days"].values()) == 6
    assert [r["age_days"] for r in out.rows] == [400, 120, 45, 20]                     # oldest first
    assert {r["type"] for r in out.rows} == {"infra", "code", "web"}


@pytest.mark.asyncio
async def test_thresholds_shape_it(gdb):
    await _seed(gdb)
    code = (await evaluate(gdb, CHECK, {"type": "2"}))[0]["details"]
    assert (code["open_findings"], code["too_old"]) == (1, 1)
    everything = (await evaluate(gdb, CHECK, {"min_severity": "1"}))[0]["details"]
    assert (everything["open_findings"], everything["too_old"]) == (7, 5)           # low 500 > 180
    flat = (await evaluate(gdb, CHECK, {"max_age_days": "100"}))[0]["details"]
    assert flat["too_old"] == 2 and not flat["uses_install_sla"]                      # 400 and 120
    lenient = (await evaluate(gdb, CHECK, {"warn_max_pct": "70"}))[0]
    assert lenient["result"] == "warning"


@pytest.mark.asyncio
async def test_shorter_install_slas_tighten_it(gdb):
    await _seed(gdb)
    from api.core.sla import save
    await save(gdb, {"critical": 3, "high": 14, "medium": 30, "low": 90})
    await gdb.commit()
    d = (await evaluate(gdb, CHECK, {}))[0]["details"]
    assert d["too_old"] == 6 and d["limits_days"]["critical"] == 3   # the 5-day critical and the 30-day medium now count
