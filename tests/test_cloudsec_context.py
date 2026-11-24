"""Cloud findings get their own score, where they are, and Rapid7's fix steps; read with GET only."""
from __future__ import annotations

import random

import httpx
import pytest
from sqlalchemy import select

from api.integrations import rapid7_cloudsec
from api.integrations.base import get_connector
from api.scoring import cloud_score

NOTES = ("Overview\n----------\nThese access lists allow access over the Internet.\n\nRemediation\n-----------\n"
         "Restrict ingress to known ranges. <b>Never</b> 0.0.0.0/0. See https://docs.example.com/sg-rules.")


def test_cloud_score_uses_severity_and_what_the_check_is_about():
    assert cloud_score.signals("Access List Allows Public Access", ["Access Control"]) == ["public"]
    assert cloud_score.signals("Root Account Without MFA", []) == ["identity"]
    assert cloud_score.signals("Bucket Without Access Logging", ["Logging"]) == ["hygiene"]
    assert cloud_score.signals("Public Bucket Without Logging", []) == ["public"]   # still about the public bucket
    assert cloud_score.score({"severity": 5, "signals": ["public"]}, 9.5)[0] == 90.0
    assert cloud_score.score({"severity": 5, "signals": []}, 9.5)[0] == 70.0
    assert cloud_score.score({"severity": 4, "signals": ["hygiene"]}, 7.5)[0] == 40.0
    assert cloud_score.score(None, 9.5)[0] == 70.0   # stored before severity was kept: from its CVSS-ish number
    assert cloud_score.score({"severity": 4, "signals": ["evil"]}, 7.5)[0] == 50.0


def _tenant(acct, insight_tags, methods):
    insights = [{"insight_id": 143, "source": "backoffice", "severity": 5, "name": "Access List Allows Public Access",
                 "tags": insight_tags, "notes": NOTES, "compliance_controls": [{"name": "CIS AWS 5.2"}], "description": "Public ingress"}]
    rows = [{"insight_id": "backoffice:143", "resource_id": f"resourceaccesslist:{acct}:us-east-1:sg-0abc:", "resource_name": f"web-sg-{acct}",
             "identified_at": "2026-08-24 20:53:16", "namespace_id": "arn:aws:ec2:us-east-1:111122223333:security-group/sg-0abc"}]

    def handler(request):
        methods.append(request.method)
        p = request.url.path
        if p == "/v2/public/insights/list":
            return httpx.Response(200, json=insights)
        if p == "/v2/public/clouds/list":
            return httpx.Response(200, json={"clouds": [{"id": int(acct), "name": "Prod AWS", "account_id": "111122223333",
                                                         "cloud_type_id": "AWS"}], "total_count": 1})
        return httpx.Response(200, json={"count": 1, "next_cursor": None, "results": rows})
    return lambda **_: httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _conn():
    return get_connector("rapid7_cloudsec", {"api_key": "example-not-a-key", "base_url": "https://acme.insightcloudsec.example"})


@pytest.mark.asyncio
async def test_sync_keeps_where_and_how_to_fix_and_the_grade_follows(db, monkeypatch, client_admin):
    from api.models.device import Device
    from api.models.vuln import Finding, Fix
    from api.scoring.engine import recalculate_device
    acct, methods = str(random.randint(10_000_000, 99_999_999)), []
    monkeypatch.setattr(rapid7_cloudsec, "safe_client", _tenant(acct, ["Access Control"], methods))
    assert await _conn().sync(db) == 1 and set(methods) == {"GET"}
    f = (await db.execute(select(Finding).where(Finding.source_id == f"backoffice:143:resourceaccesslist:{acct}:us-east-1:sg-0abc:"))).scalar_one()
    d = f.details
    assert (d["provider"], d["account"], d["account_id"], d["region"], d["resource_type"], d["resource"]) == \
        ("AWS", "Prod AWS", "111122223333", "us-east-1", "resourceaccesslist", "sg-0abc")
    assert d["arn"].startswith("arn:aws:ec2:") and d["signals"] == ["public"] and d["compliance"] == ["CIS AWS 5.2"]
    fix = (await db.execute(select(Fix).where(Fix.key == f.fix_key))).scalar_one()
    assert fix.title == "Fix: Access List Allows Public Access" and "Restrict ingress" in fix.steps
    assert "<b>" not in fix.steps and "-----" not in fix.steps and fix.links == ["https://docs.example.com/sg-rules"]

    dev = (await db.execute(select(Device).where(Device.id == f.device_id))).scalar_one()
    await recalculate_device(dev, db)
    await db.refresh(f)
    assert f.composite_score == 90.0 and f.risk_grade == "F" and dev.risk_grade.value == "F"   # not a B any more

    fid, dev_id, vuln_id = f.id, dev.id, f.vuln_id
    # The tool retags the check: only what changed is rewritten, and the next score follows
    monkeypatch.setattr(rapid7_cloudsec, "safe_client", _tenant(acct, ["Logging"], methods))
    await _conn().sync(db)
    f = (await db.execute(select(Finding).where(Finding.id == fid).execution_options(populate_existing=True))).scalar_one()
    assert f.details["signals"] == ["public"] and f.details["tags"] == ["Logging"] and set(methods) == {"GET"}

    r = await client_admin.get(f"/api/v1/devices/{dev_id}/findings")
    row = r.json()["findings"][0]
    assert row["details"]["fix"].startswith("Overview") and row["details"]["fix_links"] == ["https://docs.example.com/sg-rules"]
    assert row["details"]["score_why"][0] == "critical in the cloud security tool"
    where = (await client_admin.get(f"/api/v1/devices/{dev_id}")).json()["cloud_where"]
    assert where["account"] == "Prod AWS" and where["region"] == "us-east-1"
    aff = (await client_admin.get(f"/api/v1/vulns/{vuln_id}/findings", params={"q": f"web-sg-{acct}"})).json()["findings"]
    assert aff and aff[0]["details"]["account_id"] == "111122223333" and aff[0]["details"]["fix_title"].startswith("Fix:")
    fixes = (await client_admin.get("/api/v1/fixes", params={"kind": "cloud", "q": "Access List Allows Public"})).json()
    assert fixes["total"] >= 1
    for page in (f"/devices/{dev_id}", f"/vulns/{vuln_id}"):   # the pages render (inline scripts must not hold Jinja braces)
        r = await client_admin.get(page)
        assert r.status_code == 200 and "asset_cloud.js" in r.text
