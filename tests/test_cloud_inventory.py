"""Cloud Inventory: cloud instances with reachability, coverage and exposure, filtered and admin/cyber only."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest


async def _estate(db):
    from api.cloud.exposure import Instance, Opening, store
    from api.core.device_tags import sync_tags
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType, RiskGrade
    n = uuid.uuid4().hex[:6]
    ip1, ip2 = f"10.91.{int(n[:2], 16)}.{int(n[2:4], 16)}", f"10.92.{int(n[:2], 16)}.{int(n[2:4], 16)}"
    web = Device(hostname=f"web-{n}.acme.example", device_type=DeviceType.server, ip=ip1, ip_hash=search_hash(ip1),
                 sources=",rapid7_insightvm,crowdstrike,", edr_active=True, kev_findings=2, open_findings=9,
                 risk_grade=RiskGrade.F, risk_score=88.0, last_seen=datetime.now(timezone.utc))
    db_dev = Device(hostname=f"db-{n}.acme.example", device_type=DeviceType.server, ip=ip2, ip_hash=search_hash(ip2),
                    sources=",ldap,", edr_active=False)
    db.add_all([web, db_dev])
    await db.flush()
    await sync_tags(db, web.id, {f"tech_owner:Pat {n}"}, ("tech_owner:",), "manual", {})
    await db.commit()
    i1 = Instance("aws", f"i-web-{n}", name=f"web-{n}", account="111111111111", region="us-east-1", private_ips=[ip1],
                  public_ips=["198.51.100.30"], openings=[Opening("tcp", 443, 443, ["0.0.0.0/0"], "sg-web")])
    i1.add_firewall("AWS security group", "sg-web", "web")
    i2 = Instance("aws", f"i-db-{n}", name=f"db-{n}", account="111111111111", region="us-east-1", private_ips=[ip2],
                  openings=[Opening("tcp", 5432, 5432, ["10.0.0.0/8"], "sg-db")])
    i3 = Instance("aws", f"i-lost-{n}", name=None, account="111111111111", region="us-west-2", private_ips=["192.0.2.201"])
    await store(db, f"int-inv-{n}", [i1, i2, i3], create_devices=False)
    return n


@pytest.mark.asyncio
async def test_inventory_filters_and_rows(db, client_admin):
    n = await _estate(db)
    get = lambda **p: client_admin.get("/api/v1/cloud", params={"q": n, **p})  # noqa: E731
    rows = (await get()).json()["items"]
    by = {r["resource_id"]: r for r in rows}
    web = by[f"i-web-{n}"]
    assert web["internet_exposed"] and web["internet_ports"] == ["443/tcp"] and web["firewalls"][0]["id"] == "sg-web"
    assert web["scanned"] and web["edr"] and web["kev_findings"] == 2 and web["owner"] == f"Pat {n}"
    dbr = by[f"i-db-{n}"]
    assert not dbr["internet_exposed"] and dbr["restricted_ports"] == 1 and not dbr["scanned"] and not dbr["edr"]
    assert [r["resource_id"] for r in (await get(show="breachable")).json()["items"]] == [f"i-web-{n}"]
    # an instance in no other tool is, by definition, neither scanned nor covered by EDR
    assert {r["resource_id"] for r in (await get(show="unscanned")).json()["items"]} == {f"i-db-{n}", f"i-lost-{n}"}
    assert {r["resource_id"] for r in (await get(show="no_edr")).json()["items"]} == {f"i-db-{n}", f"i-lost-{n}"}
    # the instance in no other tool has no name or IP match, so search for it by resource id
    lost = (await client_admin.get("/api/v1/cloud", params={"q": f"i-lost-{n}", "show": "unmatched"})).json()
    assert lost["total"] == 1 and lost["items"][0]["device_id"] is None
    assert (await client_admin.get("/api/v1/cloud", params={"q": "198.51.100.30"})).json()["total"] >= 1
    s = (await client_admin.get("/api/v1/cloud/summary")).json()
    assert s["total"] >= 3 and s["breachable"] >= 1 and any(p["provider"] == "aws" for p in s["providers"])
    csv = (await client_admin.get("/api/v1/cloud/export", params={"q": n})).text
    assert f"web-{n}" in csv and "443/tcp" in csv


@pytest.mark.asyncio
async def test_inventory_is_admin_and_cyber_only(client_cyber, client_it_user, client_read_only):
    assert (await client_cyber.get("/api/v1/cloud")).status_code == 200
    for c in (client_it_user, client_read_only):
        assert (await c.get("/api/v1/cloud")).status_code == 403
        assert (await c.get("/api/v1/cloud/summary")).status_code == 403
    assert (await client_cyber.get("/api/v1/cloud", params={"show": "drop table"})).status_code == 422
