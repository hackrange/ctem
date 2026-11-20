"""Vulnerability list search/sort/paging/export and the affected-devices view."""
from __future__ import annotations

import csv
import io
import uuid

import pytest


async def _seed(db, n_vulns: int = 30, n_devices: int = 6):
    from api.models.device import Device, DeviceType, RiskGrade
    from api.models.vuln import Finding, FindingStatus, Vulnerability

    src = f"t_{uuid.uuid4().hex[:8]}"
    devices = []
    for i in range(n_devices):
        d = Device(hostname=f"vh-{i:02d}.acme.example", device_type=DeviceType.server, source=src,
                   risk_score=float(i * 10), risk_grade=RiskGrade.F if i % 2 else RiskGrade.C)
        db.add(d)
        devices.append(d)
    await db.flush()
    vulns = []
    for i in range(n_vulns):
        v = Vulnerability(cve_id=f"CVE-2026-{7000 + i}", title=f"Acme OpenWidget Remote Code Execution {i}",
                          cvss_base=round(i / 3, 1), source=src, source_vuln_id=f"acme-widget-rce-{i}",
                          is_kev=i % 5 == 0)
        db.add(v)
        vulns.append(v)
    await db.flush()
    # vuln i affects the first (i % n_devices) devices; vuln 0 affects none
    for i, v in enumerate(vulns):
        for d in devices[: i % n_devices]:
            db.add(Finding(device_id=d.id, vuln_id=v.id, source=src, status=FindingStatus.open))
    await db.commit()
    from api.scoring.engine import refresh_affected_counts
    await refresh_affected_counts(db)  # what every scoring run does
    return src, vulns, devices


@pytest.mark.asyncio
async def test_partial_title_and_cve_search(client_admin, db):
    src, _, _ = await _seed(db)
    title = (await client_admin.get("/api/v1/vulns", params={"source": src, "q": "openwidget remote"})).json()
    assert title["total"] == 30  # case-insensitive partial match on title
    cve = (await client_admin.get("/api/v1/vulns", params={"source": src, "q": "2026-701"})).json()
    assert cve["total"] == 10  # CVE-2026-7010..7019
    scanner = (await client_admin.get("/api/v1/vulns", params={"source": src, "q": "widget-rce-2"})).json()
    assert scanner["total"] == 11  # 2 and 20-29
    legacy = (await client_admin.get("/api/v1/vulns", params={"source": src, "cve_id": "7001"})).json()
    assert legacy["total"] == 1


@pytest.mark.asyncio
async def test_paging_total_and_sort_by_affected(client_admin, db):
    src, _, _ = await _seed(db)
    p2 = (await client_admin.get("/api/v1/vulns", params={"source": src, "limit": 25, "offset": 25})).json()
    assert p2["total"] == 30 and len(p2["vulns"]) == 5
    top = (await client_admin.get("/api/v1/vulns", params={"source": src, "sort": "affected", "order": "desc"})).json()
    counts = [v["affected_devices"] for v in top["vulns"]]
    assert counts == sorted(counts, reverse=True) and counts[0] == 5
    only = (await client_admin.get("/api/v1/vulns", params={"source": src, "affected_only": "true"})).json()
    assert only["total"] == 25  # i % 6 == 0 affects nobody
    kev = (await client_admin.get("/api/v1/vulns", params={"source": src, "is_kev": "true"})).json()
    assert kev["total"] == 6


@pytest.mark.asyncio
async def test_vuln_export_all_rows(client_admin, db, monkeypatch):
    from api.core import csv_export
    monkeypatch.setattr(csv_export, "_CHUNK", 4)
    src, _, _ = await _seed(db)
    resp = await client_admin.get("/api/v1/vulns/export", params={"source": src, "sort": "cve_id", "order": "asc"})
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert rows[0][0] == "CVE" and len(rows) == 31
    assert rows[1][0] == "CVE-2026-7000"


@pytest.mark.asyncio
async def test_affected_devices_page_sort_and_export(client_admin, db):
    src, vulns, _ = await _seed(db)
    v = vulns[5]  # affects 5 devices
    base = f"/api/v1/vulns/{v.id}/findings"
    data = (await client_admin.get(base, params={"sort": "hostname", "order": "asc", "limit": 2})).json()
    assert data["total"] == 5 and [f["hostname"] for f in data["findings"]] == ["VH-00", "VH-01"]
    assert data["findings"][0]["device_id"]
    detail = (await client_admin.get(f"/api/v1/vulns/{v.id}")).json()
    assert detail["affected_devices"] == 5 and detail["source_vuln_id"] == "acme-widget-rce-5"
    exp = await client_admin.get(f"{base}/export")
    rows = list(csv.reader(io.StringIO(exp.text)))
    assert len(rows) == 6 and rows[1][0] == "CVE-2026-7005"


@pytest.mark.asyncio
async def test_affected_view_is_scoped_for_restricted_users(client_it_user, it_user, db):
    from api.models.device import DeviceTag
    from api.models.tag import GroupTagAccess, Tag

    src, vulns, devices = await _seed(db)
    tag = Tag(name=f"app:acme-{uuid.uuid4().hex[:6]}", source="manual")
    db.add(tag)
    await db.flush()
    db.add(GroupTagAccess(role_name="it_user", tag_id=tag.id))
    db.add(DeviceTag(device_id=devices[1].id, tag_id=tag.id))
    await db.commit()

    v = vulns[5]
    data = (await client_it_user.get(f"/api/v1/vulns/{v.id}/findings")).json()
    assert data["total"] == 1 and data["findings"][0]["hostname"] == "VH-01"
    listing = (await client_it_user.get("/api/v1/vulns", params={"source": src, "q": "CVE-2026-7005"})).json()
    assert listing["vulns"][0]["affected_devices"] == 1  # counts don't leak hidden devices
    exp = await client_it_user.get(f"/api/v1/vulns/{v.id}/findings/export")
    assert len(list(csv.reader(io.StringIO(exp.text)))) == 2


@pytest.mark.asyncio
async def test_unknown_vuln_is_404(client_admin):
    assert (await client_admin.get(f"/api/v1/vulns/{uuid.uuid4()}/findings")).status_code == 404
    assert (await client_admin.get(f"/api/v1/vulns/{uuid.uuid4()}")).status_code == 404


@pytest.mark.asyncio
async def test_stored_affected_count_follows_refresh(client_admin, db):
    from api.models.vuln import Finding, FindingStatus
    from api.scoring.engine import refresh_affected_counts

    src, vulns, devices = await _seed(db)
    v = vulns[6]  # affects nobody
    db.add(Finding(device_id=devices[0].id, vuln_id=v.id, source=src, status=FindingStatus.open))
    await db.commit()
    await refresh_affected_counts(db)
    data = (await client_admin.get("/api/v1/vulns", params={"source": src, "q": "CVE-2026-7006"})).json()
    assert data["vulns"][0]["affected_devices"] == 1
