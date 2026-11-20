"""Rapid7 AppSec web apps count as internet-facing exposure when their scanned URLs are public."""
from __future__ import annotations

import contextlib
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.integrations.rapid7_appsec import internal_domains, public_url
from api.models.base import Base


@pytest.mark.parametrize("url,expected", [
    ("https://shop.acme.example/login", True),
    ("https://203.0.113.10/app", False),              # documentation range: not a real public address
    ("http://10.1.2.3:8080/", False),
    ("http://[fd00::1]/", False),
    ("http://localhost/", False),
    ("http://intranet/", False),                      # single-label name
    ("https://hr.corp/", False),
    ("https://portal.ad.acme.example/", False),        # listed as internal below
    ("https://ad.acme.example/", False),
    ("https://notad.acme.example/", True),             # suffix match is on whole labels
    ("not a url", None),
    (None, None),
])
def test_public_url(url, expected):
    assert public_url(url, internal_domains("AD.acme.example, ; bad domain!")) is expected


def test_internal_domains_are_cleaned():
    assert internal_domains(" .ad.acme.example , corp.acme.example; x y") == (".ad.acme.example", ".corp.acme.example")


@pytest_asyncio.fixture
async def gdb():
    path = tempfile.mktemp(prefix="ctem_appsec_", suffix=".db")
    eng = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(eng, expire_on_commit=False)() as s:
        yield s
    await eng.dispose()
    with contextlib.suppress(OSError):
        os.unlink(path)


def _vuln(vid, app, url, sev="CRITICAL"):
    return {"id": vid, "app": {"id": app}, "severity": sev, "status": "UNREVIEWED", "attack_type": "SQL Injection",
            "root_cause": {"url": url, "method": "POST", "parameter": "q"}}


@pytest.mark.asyncio
async def test_public_apps_feed_the_exposure_check(gdb):
    from api.grc.checks import REGISTRY, evaluate
    from api.integrations.base import get_connector
    from api.models.device import Device
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor

    conn = get_connector("rapid7_appsec", {"api_key": "x", "region": "us", "internal_domains": "corp.acme.example"})
    await conn._upsert({"a1": "shop", "a2": "hr"}, [
        _vuln("v1", "a1", "https://shop.acme.example/search"),
        _vuln("v2", "a2", "https://hr.corp.acme.example/login"),
        _vuln("v3", "a2", "http://10.0.0.5/admin", sev="HIGH"),
    ], gdb)
    apps = {d.hostname: d for d in (await gdb.execute(select(Device).where(Device.source == "rapid7_appsec"))).scalars()}
    assert apps["shop"].is_internet_exposed is True and apps["hr"].is_internet_exposed is False

    # AppSec alone is enough fresh data for the check now
    cfg = IntegrationConfig(vendor=Vendor.rapid7_appsec, name="appsec", is_enabled=True, config={})
    gdb.add(cfg)
    await gdb.flush()
    at = datetime.now(timezone.utc) - timedelta(hours=1)
    gdb.add(SyncJob(integration_id=str(cfg.id), vendor="rapid7_appsec", status=SyncStatus.success, started_at=at, finished_at=at))
    await gdb.commit()
    check = REGISTRY["ctem_exposed_criticals"]
    assert "rapid7_appsec" in check.sources and check.version == 2
    body, _ = await evaluate(gdb, check, {})
    assert body["result"] == "fail" and body["details"]["with_exposed_criticals"] == 1
