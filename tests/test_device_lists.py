"""Device list: real totals, paging past 200, sorting, search, scope, summary, and CSV export."""
from __future__ import annotations

import csv
import io
import uuid

import pytest


async def _seed(db, n: int, owner=None):
    """n devices under a unique source so counts don't collide with other tests."""
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType, RiskGrade

    src = f"t_{uuid.uuid4().hex[:8]}"
    grades = [RiskGrade.F, RiskGrade.D, RiskGrade.C, None]
    for i in range(n):
        ip = f"192.0.2.{i % 250}"
        d = Device(hostname=f"host-{i:04d}.acme.example", device_type=DeviceType.server, source=src,
                   risk_score=float(i % 100), risk_grade=grades[i % 4], open_findings=i, kev_findings=i % 3,
                   ip=ip, ip_hash=search_hash(ip), mac_address=f"00:00:5E:00:53:{i % 256:02X}")
        if owner is not None and i == 0:
            d.owner_user_id = owner.id
        db.add(d)
    await db.commit()
    return src


@pytest.mark.asyncio
async def test_list_reports_total_and_pages_past_200(client_admin, db):
    src = await _seed(db, 230)
    first = (await client_admin.get("/api/v1/devices", params={"source": src, "limit": 200})).json()
    assert first["total"] == 230 and len(first["devices"]) == 200
    last = (await client_admin.get("/api/v1/devices", params={"source": src, "limit": 200, "offset": 200})).json()
    assert len(last["devices"]) == 30
    ids = {d["id"] for d in first["devices"]} | {d["id"] for d in last["devices"]}
    assert len(ids) == 230  # no overlap, nothing skipped


@pytest.mark.asyncio
async def test_sorting_both_directions_and_unknown_sort_is_safe(client_admin, db):
    src = await _seed(db, 12)
    asc = (await client_admin.get("/api/v1/devices", params={"source": src, "sort": "hostname", "order": "asc"})).json()
    names = [d["hostname"] for d in asc["devices"]]
    assert names == sorted(names)
    desc = (await client_admin.get("/api/v1/devices", params={"source": src, "sort": "open_findings", "order": "desc"})).json()
    counts = [d["open_findings"] for d in desc["devices"]]
    assert counts == sorted(counts, reverse=True)
    # Off-list sort keys fall back to the default instead of reaching SQL
    ok = await client_admin.get("/api/v1/devices", params={"source": src, "sort": "hostname;drop table devices"})
    assert ok.status_code == 200
    bad = await client_admin.get("/api/v1/devices", params={"source": src, "order": "sideways"})
    assert bad.status_code == 422


@pytest.mark.asyncio
async def test_search_hostname_ip_mac_and_like_wildcards(client_admin, db):
    src = await _seed(db, 20)
    by_name = (await client_admin.get("/api/v1/devices", params={"source": src, "q": "host-001"})).json()
    assert by_name["total"] == 10  # host-0010..0019
    by_ip = (await client_admin.get("/api/v1/devices", params={"source": src, "q": "192.0.2.7"})).json()
    assert [(d["hostname"], d["fqdn"]) for d in by_ip["devices"]] == [("host-0007", "host-0007.acme.example")]
    assert by_ip["devices"][0]["ip"] == "192.0.2.7"
    by_mac = (await client_admin.get("/api/v1/devices", params={"source": src, "q": "00:00:5e:00:53:0a"})).json()
    assert by_mac["total"] == 1
    # % and _ are literals, not wildcards
    wild = (await client_admin.get("/api/v1/devices", params={"source": src, "q": "%"})).json()
    assert wild["total"] == 0


@pytest.mark.asyncio
async def test_user_column_comes_from_owner(client_admin, db, cyber_user):
    src = await _seed(db, 3, owner=cyber_user)
    data = (await client_admin.get("/api/v1/devices", params={"source": src, "sort": "user", "order": "asc"})).json()
    assert data["devices"][0]["user"] == cyber_user.username
    found = (await client_admin.get("/api/v1/devices", params={"source": src, "q": cyber_user.username})).json()
    assert found["total"] == 1


@pytest.mark.asyncio
async def test_grade_filter_and_unscored(client_admin, db):
    src = await _seed(db, 8)
    f = (await client_admin.get("/api/v1/devices", params={"source": src, "grade": "f"})).json()
    assert f["total"] == 2 and all(d["risk_grade"] == "F" for d in f["devices"])
    none = (await client_admin.get("/api/v1/devices", params={"source": src, "grade": "none"})).json()
    assert none["total"] == 2 and all(d["risk_grade"] is None for d in none["devices"])


@pytest.mark.asyncio
async def test_summary_counts_every_device(client_admin, db):
    src = await _seed(db, 240)
    s = (await client_admin.get("/api/v1/devices/summary", params={"source": src})).json()
    assert s["total"] == 240
    assert s["grades"]["F"] == 60 and s["grades"]["D"] == 60 and s["grades"]["C"] == 60
    assert s["ungraded"] == 60
    assert s["kev_devices"] == 160  # kev_findings = i % 3, so two of every three
    assert sum(e["devices"] for e in s["environments"]) == 240


@pytest.mark.asyncio
async def test_tag_scoped_user_sees_only_their_devices(client_it_user, it_user, db):
    from api.models.device import Device, DeviceTag, DeviceType
    from api.models.tag import GroupTagAccess, Tag

    src = await _seed(db, 5)
    tag = Tag(name=f"app:acme-{uuid.uuid4().hex[:6]}", source="manual")
    db.add(tag)
    await db.flush()
    db.add(GroupTagAccess(role_name="it_user", tag_id=tag.id))
    mine = Device(hostname="visible.acme.example", device_type=DeviceType.server, source=src)
    owned = Device(hostname="owned.acme.example", device_type=DeviceType.server, source=src, owner_user_id=it_user.id)
    db.add_all([mine, owned])
    await db.flush()
    db.add(DeviceTag(device_id=mine.id, tag_id=tag.id))
    await db.commit()

    data = (await client_it_user.get("/api/v1/devices", params={"source": src})).json()
    assert sorted(d["fqdn"] for d in data["devices"]) == ["owned.acme.example", "visible.acme.example"]
    assert data["total"] == 2
    s = (await client_it_user.get("/api/v1/devices/summary", params={"source": src})).json()
    assert s["total"] == 2
    exp = await client_it_user.get("/api/v1/devices/export", params={"source": src})
    rows = list(csv.reader(io.StringIO(exp.text)))
    assert len(rows) == 3  # header + 2


@pytest.mark.asyncio
async def test_export_has_every_row_and_neutralizes_formulas(client_admin, db, monkeypatch):
    from api.core import csv_export
    from api.models.device import Device, DeviceType

    monkeypatch.setattr(csv_export, "_CHUNK", 7)  # force several pages
    src = await _seed(db, 30)
    db.add(Device(hostname="=HYPERLINK(\"http://203.0.113.9\")", device_type=DeviceType.server, source=src))
    await db.commit()
    resp = await client_admin.get("/api/v1/devices/export", params={"source": src, "sort": "hostname", "order": "asc"})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert "attachment" in resp.headers["content-disposition"]
    assert resp.headers["x-export-rows"] == "31"
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert rows[0][:3] == ["Hostname", "FQDN", "User"] and len(rows) == 32
    evil = [r for r in rows if "HYPERLINK" in r[0]][0]
    assert evil[0].startswith("'=")


def test_safe_cell():
    from api.core.csv_export import safe_cell
    assert safe_cell("+1+1") == "'+1+1"
    assert safe_cell("@SUM(A1)") == "'@SUM(A1)"
    assert safe_cell("-2") == "'-2"
    assert safe_cell("acme") == "acme"
    assert safe_cell(None) == "" and safe_cell(True) == "yes"


@pytest.mark.asyncio
async def test_device_findings_page_sort_filter_export(client_admin, db):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability

    dev = Device(hostname="findings.acme.example", device_type=DeviceType.server, source="t_findings")
    db.add(dev)
    await db.flush()
    for i in range(60):
        v = Vulnerability(cve_id=f"CVE-2026-{1000 + i}", title=f"Acme flaw {i}", cvss_base=round(i / 6, 1), source="t_findings")
        db.add(v)
        await db.flush()
        status = FindingStatus.remediated if i % 10 == 0 else FindingStatus.open
        db.add(Finding(device_id=dev.id, vuln_id=v.id, source="t_findings", status=status))
    await db.commit()

    base = f"/api/v1/devices/{dev.id}/findings"
    page = (await client_admin.get(base, params={"limit": 25, "offset": 50})).json()
    assert page["total"] == 54 and len(page["findings"]) == 4  # 6 remediated are hidden by default
    every = (await client_admin.get(base, params={"status": "all"})).json()
    assert every["total"] == 60
    top = (await client_admin.get(base, params={"sort": "cvss_base", "order": "desc", "limit": 1})).json()
    assert top["findings"][0]["cvss_base"] == 9.8 and top["findings"][0]["vuln_id"]
    hit = (await client_admin.get(base, params={"q": "flaw 4"})).json()
    assert hit["total"] == 10  # "flaw 4" and "flaw 40".."49" match; 40 is remediated
    exp = await client_admin.get(f"{base}/export", params={"status": "all"})
    assert len(list(csv.reader(io.StringIO(exp.text)))) == 61
    bad = await client_admin.get(base, params={"status": "deleted"})
    assert bad.status_code == 422


@pytest.mark.asyncio
async def test_detail_pages_render(client_admin, db):
    from api.models.device import Device, DeviceType
    dev = Device(hostname="page.acme.example", device_type=DeviceType.server, source="t_pages")
    db.add(dev)
    await db.commit()
    for path in (f"/devices/{dev.id}", f"/vulns/{uuid.uuid4()}"):
        resp = await client_admin.get(path)
        assert resp.status_code == 200 and "data_table.js" in resp.text
