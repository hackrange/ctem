"""InsightCloudSec sync: GET only, every page, honest failures, and closing what the tenant stopped listing."""
from __future__ import annotations

import random

import httpx
import pytest
from sqlalchemy import select

from api.integrations import rapid7_cloudsec
from api.integrations.base import get_connector
from api.integrations.rapid7_cloudsec_store import account_of
from api.models.vuln import Finding, FindingStatus

_INSIGHTS = [
    {"insight_id": 59, "source": "backoffice", "severity": 5, "name": "Instance Exposing SSH", "resource_types": ["instance"]},
    {"insight_id": 7, "source": "custom", "severity": 2, "custom_severity": 4, "name": "Acme bucket rule"},
    {"insight_id": 2, "source": "backoffice", "severity": 1, "name": "Not Multi-AZ"},   # below the "high" floor
    {"insight_id": 60, "source": "backoffice", "severity": 5, "name": "Retired", "disabled": True},
]


def _row(insight, acct, rid):
    return {"insight_id": insight, "resource_id": f"instance:{acct}:us-east-1:{rid}:", "resource_name": rid,
            "identified_at": "2026-08-24 20:53:16", "namespace_id": None}


def _tenant(accounts, methods):
    """accounts: {id: [pages of rows]} or {id: status_code}."""
    def handler(request):
        methods.append(request.method)
        path = request.url.path
        if path == "/v2/public/insights/list":
            return httpx.Response(200, json=_INSIGHTS)
        if path == "/v2/public/clouds/list":
            return httpx.Response(200, json={"clouds": [{"id": int(a)} for a in accounts], "total_count": len(accounts)})
        acct = path.rstrip("/").rsplit("/", 1)[-1]
        if not path.endswith("/"):
            return httpx.Response(308, headers={"location": f"http://internal.example.com{path}/"})
        pages = accounts[acct]
        if isinstance(pages, int):
            return httpx.Response(pages, json={})
        i = int(request.url.params.get("cursor") or 0)
        nxt = str(i + 1) if i + 1 < len(pages) else None
        return httpx.Response(200, json={"count": sum(map(len, pages)), "next_cursor": nxt, "results": pages[i]})
    return lambda **_: httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _conn():
    return get_connector("rapid7_cloudsec", {"api_key": "example-not-a-key", "base_url": "https://acme.insightcloudsec.example"})


async def _status(db, acct):
    rows = (await db.execute(select(Finding.source_id, Finding.status).where(
        Finding.source == "rapid7_cloudsec", Finding.source_id.like(f"%:instance:{acct}:%")))).all()
    return {sid.split(":")[-2]: st for sid, st in rows}


def test_account_of():
    assert account_of("backoffice:59:instance:2:us-east-1:i-1:") == "2"
    assert account_of("custom:7:storagecontainer:31:") == "31"
    assert account_of("junk") is None


@pytest.mark.asyncio
async def test_sync_is_get_only_reads_every_page_and_closes_what_vanished(db, monkeypatch):
    a, b = (str(random.randint(10_000, 99_999)) for _ in range(2))
    methods = []
    first = {a: [[_row("backoffice:59", a, "i-1"), _row("backoffice:2", a, "i-low")],
                 [_row("custom:7", a, "i-2"), _row("custom:7", a, "i-2")]],
             b: [[_row("backoffice:59", b, "i-9")]]}
    monkeypatch.setattr(rapid7_cloudsec, "safe_client", _tenant(first, methods))
    c = _conn()
    assert await c.sync(db) == 3   # low-severity row dropped, the duplicate counted once
    assert set(methods) == {"GET"}
    assert c.warnings == []
    assert await _status(db, a) == {"i-1": FindingStatus.open, "i-2": FindingStatus.open}

    # Next run: i-2 is fixed in account a, and account b answers 500
    second = {a: [[_row("backoffice:59", a, "i-1")]], b: 500}
    methods.clear()
    monkeypatch.setattr(rapid7_cloudsec, "safe_client", _tenant(second, methods))
    c = _conn()
    assert await c.sync(db) == 1
    assert set(methods) == {"GET"}
    assert await _status(db, a) == {"i-1": FindingStatus.open, "i-2": FindingStatus.remediated}
    assert await _status(db, b) == {"i-9": FindingStatus.open}   # unread account: nothing closed
    assert c.warnings == ["1 of 2 cloud accounts could not be read and were skipped"]

    # It comes back: reopened, not duplicated
    monkeypatch.setattr(rapid7_cloudsec, "safe_client", _tenant(first, methods))
    await _conn().sync(db)
    assert await _status(db, a) == {"i-1": FindingStatus.open, "i-2": FindingStatus.open}


@pytest.mark.asyncio
async def test_account_removed_from_tenant_is_closed(db, monkeypatch):
    a, gone = (str(random.randint(100_000, 999_999)) for _ in range(2))
    monkeypatch.setattr(rapid7_cloudsec, "safe_client", _tenant({a: [[]], gone: [[_row("backoffice:59", gone, "i-5")]]}, []))
    await _conn().sync(db)
    monkeypatch.setattr(rapid7_cloudsec, "safe_client", _tenant({a: [[]]}, []))
    await _conn().sync(db)
    assert await _status(db, gone) == {"i-5": FindingStatus.remediated}


@pytest.mark.asyncio
async def test_every_account_failing_fails_the_run(db, monkeypatch):
    a = str(random.randint(1_000_000, 9_999_999))
    monkeypatch.setattr(rapid7_cloudsec, "safe_client", _tenant({a: 500}, []))
    with pytest.raises(rapid7_cloudsec.CloudSecError, match="refused every cloud account"):
        await _conn().sync(db)


@pytest.mark.asyncio
async def test_refused_key_fails_the_run(db, monkeypatch):
    def handler(request):
        return httpx.Response(302, headers={"location": "https://login.example.com/saml/logout"})
    monkeypatch.setattr(rapid7_cloudsec, "safe_client", lambda **_: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(rapid7_cloudsec.CloudSecError, match="key was refused"):
        await _conn().sync(db)


@pytest.mark.asyncio
async def test_disabled_integration_stops_mid_run(db, monkeypatch):
    a = str(random.randint(10_000_000, 99_999_999))
    methods = []
    monkeypatch.setattr(rapid7_cloudsec, "safe_client", _tenant({a: [[_row("backoffice:59", a, "i-1")]]}, methods))
    c = _conn()
    c.integration_id = "00000000-0000-0000-0000-000000000000"   # not on file, so not enabled
    assert await c.sync(db) == 0
    assert "disabled mid-run" in c.warnings[0]
    assert methods == ["GET", "GET"]   # the two lists, then it stopped before reading any account
