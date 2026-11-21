"""Tag focus: an owner/application tag narrows the vulnerability list, a vulnerability's affected devices,
its affected count and the export to devices with that tag, on top of the viewer's own scope."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest


async def _setup(db):
    from api.core.device_tags import sync_tags
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    n = uuid.uuid4().hex[:8]
    mine, other = (Device(hostname=f"tf-a-{n}", device_type=DeviceType.server, last_seen=datetime.now(timezone.utc)),
                   Device(hostname=f"tf-b-{n}", device_type=DeviceType.server, last_seen=datetime.now(timezone.utc)))
    v = Vulnerability(cve_id=f"CVE-2026-{int(n[:4], 16) % 90000 + 10000}", title=f"tf {n}", cvss_base=8.1, source="t_focus")
    db.add_all([mine, other, v])
    await db.flush()
    db.add_all([Finding(device_id=d.id, vuln_id=v.id, source="t_focus", status=FindingStatus.open) for d in (mine, other)])
    tag = f"owner:E-O: Pat {n}"
    await sync_tags(db, mine.id, {tag}, ("owner:",), "rapid7_insightvm", {})
    await db.commit()
    return mine, other, v, tag


@pytest.mark.asyncio
async def test_vuln_pages_follow_the_tag_focus(db, client_admin):
    mine, other, v, tag = await _setup(db)
    base = f"/api/v1/vulns/{v.id}"
    assert (await client_admin.get(base)).json()["affected_devices"] == 2
    assert (await client_admin.get(base, params={"tag": tag})).json()["affected_devices"] == 1
    rows = (await client_admin.get(f"{base}/findings", params={"tag": tag})).json()
    assert rows["total"] == 1 and rows["findings"][0]["hostname"].lower() == mine.hostname.lower()
    assert (await client_admin.get(f"{base}/findings")).json()["total"] == 2
    listed = (await client_admin.get("/api/v1/vulns", params={"q": v.cve_id, "tag": tag})).json()
    assert listed["total"] == 1 and listed["vulns"][0]["affected_devices"] == 1
    gone = (await client_admin.get("/api/v1/vulns", params={"q": v.cve_id, "tag": "owner:E-O: nobody", "affected_only": "true"})).json()
    assert gone["total"] == 0
    csv = (await client_admin.get(f"{base}/findings/export", params={"tag": tag})).text
    assert mine.hostname.upper() in csv.upper() and other.hostname.upper() not in csv.upper()


def test_with_tags_keeps_the_viewers_scope():
    from sqlalchemy import true

    from api.routes import device_query as dq
    assert dq.with_tags(None, None) is None and dq.with_tags(None, ["", None]) is None
    scope = true()
    assert dq.with_tags(scope, []) is scope
    narrowed = dq.with_tags(scope, ["owner:E-O: Pat"] * 3)
    assert narrowed is not scope and "AND" in str(narrowed)
