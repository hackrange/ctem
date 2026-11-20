"""Audit log paging and cache-busted static asset URLs."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pytest


@pytest.mark.asyncio
async def test_audit_pages_without_gaps_or_repeats(client_admin, db):
    from api.models.settings import AuditLog

    tag = uuid.uuid4().hex[:8]
    base = datetime(2099, 1, 1)  # newer than anything else, so these come first
    for i in range(7):
        db.add(AuditLog(actor_username="admin", action=f"t_{tag}", resource_type="x", resource_id=str(i),
                        detail=str(i), created_at=base + timedelta(seconds=i // 2)))  # pairs share a timestamp
    await db.commit()

    seen, cursor = [], None
    for _ in range(5):
        params = {"limit": 3, **({"cursor": cursor} if cursor else {})}
        data = (await client_admin.get("/api/v1/admin/audit", params=params)).json()
        seen += [e["detail"] for e in data["entries"] if e["action"] == f"t_{tag}"]
        cursor = data["next_cursor"]
        if len(seen) >= 7 or not cursor:
            break
    assert sorted(seen) == [str(i) for i in range(7)]
    assert (await client_admin.get("/api/v1/admin/audit", params={"cursor": "junk"})).status_code == 400


def test_static_urls_are_versioned_and_confined():
    from api.web.assets import static_url
    url = static_url("js/data_table.js")
    assert url.startswith("/static/js/data_table.js?v=") and len(url.split("v=")[1]) == 10
    assert static_url("../../api/core/config.py") == "/static/../../api/core/config.py"  # no hash, no file read
    assert static_url("js/missing.js") == "/static/js/missing.js"


@pytest.mark.asyncio
async def test_pages_use_versioned_assets(client_admin):
    html = (await client_admin.get("/devices")).text
    assert "/static/js/data_table.js?v=" in html and "/static/css/components.css?v=" in html


@pytest.mark.asyncio
async def test_audit_export_downloads_every_row(client_admin, client_cyber, db):
    import csv
    import io

    from sqlalchemy import func, select

    from api.models.settings import AuditLog

    db.add(AuditLog(actor_username="admin", action="t_export", detail="=cmd|' /C calc'!A0"))
    await db.commit()
    total = (await db.execute(select(func.count()).select_from(AuditLog))).scalar_one()
    resp = await client_admin.get("/api/v1/admin/audit/export")
    assert resp.status_code == 200 and resp.headers["content-disposition"].startswith("attachment;")
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert rows[0][0] == "Time (UTC)" and len(rows) - 1 == total
    assert [r for r in rows if r[2] == "t_export"][0][5].startswith("'=")  # formula neutralized
    logged = (await db.execute(select(AuditLog).where(AuditLog.action == "audit.export"))).scalars().first()
    assert logged is not None and "rows" in logged.detail
    assert (await client_admin.get("/api/v1/admin/audit/export", params={"since": "nope"})).status_code == 400
    assert (await client_cyber.get("/api/v1/admin/audit/export")).status_code == 403
