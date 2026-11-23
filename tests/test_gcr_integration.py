"""GitHub Code Review (SAST and DAST): repositories and sites become Code and Web application assets with their
findings, owners and application as tags, a tag map adds more, and what GCR stops reporting is remediated."""
from __future__ import annotations

import uuid

import pytest

from api.integrations.github_code_review import GitHubCodeReviewConnector, mapped, tag_map


def test_tag_map_parses_and_rejects_bad_lines():
    rules = tag_map("# comments are fine\nacme/claims-portal* = app:Claims Portal, exec_owner:Jane Doe\n\nclaims.acme.example = env:Prod")
    assert mapped("ACME/Claims-Portal-API", rules) == {"app:Claims Portal", "exec_owner:Jane Doe"}
    assert mapped("claims.acme.example", rules) == {"env:Prod"} and mapped("other/repo", rules) == set()
    for bad in ("no equals sign", "x = notag", "x = app:<b>", " = app:X"):
        with pytest.raises(ValueError):
            tag_map(bad)


def _finding(n, i, **kw):
    base = {"id": i, "vuln_id": f"GCR-{n}{i}", "kind": "code", "severity": "high", "state": "open",
            "repository": f"acme/claims-portal-{n}", "branch": "main", "file": "src/app.py", "line": 10 + i,
            "rule": "sql-injection", "title": "SQL built from request input", "first_found": "2026-10-01T00:00:00Z",
            "last_found": "2026-11-20T00:00:00Z", "excepted": False,
            "asset": {"application": "Claims Portal", "business_owner": "pat@acme.example",
                      "technical_owner": "dev-team@acme.example", "holds": ["PII"], "visibility": "private"},
            "ai_review": {"fix": "Use a bound parameter."}}
    return {**base, **kw}


@pytest.mark.asyncio
async def test_sync_builds_code_and_web_assets_with_findings(db, monkeypatch):
    from sqlalchemy import select

    from api.models.device import Device, DeviceTag, DeviceType
    from api.models.tag import Tag
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    n = uuid.uuid4().hex[:6]
    repo = f"acme/claims-portal-{n}"
    found = [
        _finding(n, 1),
        _finding(n, 2, kind="dependency", severity="critical", file="package-lock.json", rule="",
                 title="lodash prototype pollution", package={"name": "lodash", "version": "4.17.20"},
                 vulnerability={"id": f"CVE-2099-{n[:4]}", "cvss_score": 9.1, "known_exploited": True, "epss_score": 0.4},
                 reachability={"verdict": "reachable"}),
        _finding(n, 3, kind="credential", severity="critical", title="AWS key committed", excepted=True),
    ]
    site = {"id": int(n[:5], 16), "host": f"claims-{n}.acme.example", "application": "Claims Portal", "environment": "Prod",
            "executive_owner": "exec@acme.example", "technical_owner": "web@acme.example", "tags": ["ecommerce"],
            "status": "active", "telemetry": {"category": "live", "status_code": 200, "ip": "203.0.113.77", "grade": "B"},
            "last_dast": {"scanned_at": "2026-11-19T02:00:00Z"},
            "repositories": [{"full_name": repo, "linked": True}]}
    scan = {"id": 9, "scanned_at": "2026-11-19T02:00:00Z",
            "findings": [{"title": "Git repository metadata is served", "severity": "high", "url": "https://x/.git/HEAD",
                          "remediation": "Block /.git"}, {"title": "Missing security header", "severity": "low"}]}
    c = GitHubCodeReviewConnector({"base_url": "https://gcr.acme.example", "api_token": "gcr_x", "include_dast": True,
                                   "tag_map": f"acme/claims-portal-{n} = exec_owner:Jeffrey Davis"})
    count = await c.store(db, [{"full_name": repo, "archived": False}], found, [site], {site["id"]: scan},
                          {"critical", "high", "medium"})
    assert count == 4   # three repo findings and one DAST finding at high or above (the low one is left out)
    r = (await db.execute(select(Device).where(Device.source_id == f"repo:{repo}"))).scalar_one()
    w = (await db.execute(select(Device).where(Device.source_id == f"site:{site['id']}"))).scalar_one()
    assert r.device_type == DeviceType.code_repository and w.device_type == DeviceType.website
    assert w.is_internet_exposed and r.is_internet_exposed   # code behind a live site can be reached
    rt = set((await db.execute(select(Tag.name).join(DeviceTag, DeviceTag.tag_id == Tag.id).where(DeviceTag.device_id == r.id))).scalars())
    wt = set((await db.execute(select(Tag.name).join(DeviceTag, DeviceTag.tag_id == Tag.id).where(DeviceTag.device_id == w.id))).scalars())
    assert {"app:Claims Portal", "tech_owner:dev-team@acme.example", "app_owner:pat@acme.example",
            "exec_owner:Jeffrey Davis", f"site:{site['host']}"} <= rt
    assert {"app:Claims Portal", "env:Prod", "exec_owner:exec@acme.example", f"repo:{repo}", "gcr:grade B"} <= wt
    rows = (await db.execute(select(Vulnerability, Finding).join(Finding, Finding.vuln_id == Vulnerability.id)
                             .where(Finding.device_id.in_([r.id, w.id])))).all()
    by = {v.title.split(" (")[0]: (v, f) for v, f in rows}
    dep, dep_f = by[f"CVE-2099-{n[:4]} in lodash"]
    assert dep.cve_id == f"CVE-2099-{n[:4]}" and dep.cvss_base == 9.1 and dep.is_kev and dep.epss_score == 0.4 and dep_f.is_reachable
    assert by["AWS key committed"][1].status == FindingStatus.risk_accepted
    assert "Use a bound parameter." in by["SQL built from request input"][0].description
    assert by["Git repository metadata is served"][1].device_id == w.id
    assert dep_f.domain == "code" and dep.domain == "code"                                   # repository: Code
    assert by["Git repository metadata is served"][1].domain == "web" and by["Git repository metadata is served"][0].domain == "web"
    # next read: the SQL finding is gone, so it's remediated; the others stay
    await c.store(db, [{"full_name": repo, "archived": False}], found[1:], [site], {site["id"]: scan}, {"critical", "high", "medium"})
    await db.refresh(by["SQL built from request input"][1])
    assert by["SQL built from request input"][1].status == FindingStatus.remediated
    assert by["Git repository metadata is served"][1].status == FindingStatus.open


@pytest.mark.asyncio
async def test_client_pages_and_skips_dast_without_the_scope(monkeypatch):
    from api.integrations.gcr_client import Gcr, GcrError, base_url
    calls = []

    async def fake_get(self, path, params=None, allow_forbidden=False):
        calls.append((path, (params or {}).get("offset")))
        if path.startswith("/external"):
            return None   # 403 with allow_forbidden: no external scope
        total = 1500
        off = params["offset"]
        return {"total": total, "findings": [{"id": i} for i in range(off, min(off + 1000, total))]}
    monkeypatch.setattr(Gcr, "get", fake_get)
    g = Gcr({"base_url": "https://gcr.acme.example/", "api_token": "gcr_x"})
    assert len(await g.findings("open")) == 1500 and [c[1] for c in calls] == [0, 1000]
    assert await g.sites() is None
    with pytest.raises(GcrError):
        base_url({"base_url": "http://gcr.acme.example"})
    with pytest.raises(GcrError):
        Gcr({"base_url": "https://gcr.acme.example"})   # no token


@pytest.mark.asyncio
async def test_integration_form_rejects_a_bad_tag_map(client_admin):
    body = {"vendor": "github_code_review", "name": "GCR", "enabled": False,
            "config": {"base_url": "https://gcr.acme.example", "api_token": "gcr_x", "tag_map": "oops"}}
    r = await client_admin.post("/api/v1/integrations", json=body)
    assert r.status_code == 400 and "line 1" in r.text



@pytest.mark.asyncio
async def test_code_and_web_findings_carry_their_own_details(db, client_admin):
    from sqlalchemy import select

    from api.models.device import Device
    from api.models.vuln import Finding
    n = uuid.uuid4().hex[:6]
    repo = f"acme/claims-{n}"
    dep = _finding(n, 7, kind="dependency", severity="critical", file="package-lock.json", line=0, rule="",
                   title="openssl flaw", package={"name": "openssl", "version": "3.0.13", "fixed_in": "3.0.15",
                                                  "ecosystem": "npm", "declared_in": "package.json"},
                   vulnerability={"id": f"CVE-2099-{n[:4]}", "cvss_score": 9.8}, reachability={"verdict": "reachable", "reason": "imported"},
                   credential={"preview": "AKIA...SECRET", "verified": True})
    dep["repository"] = repo
    dep["risk"] = {"score": 74, "evidence": "inferred", "impact": "high", "impact_reason": "holds PII", "likelihood": "possible"}
    dep["ai_review"] = {"source": "analysis", "rating": "MEDIUM", "confidence": "medium", "summary": "Unpinned fork.",
                        "why": "No advisory.", "fix": "Pin it.", "what_to_check": "The lockfile.", "compensating_controls": "CSP."}
    dep["author"] = {"name": "Pat Dev", "email": "pat@acme.example"}
    dep["url"] = "https://github.com/acme/claims/blob/main/package.json"
    dep["asset"] = {"application": "Claims", "holds": ["PII", "Login"], "visibility": "internal"}
    site = {"id": 9000 + int(n[:3], 16), "host": f"claims-{n}.acme.example", "status": "active",
            "telemetry": {"category": "live", "status_code": 200}, "last_dast": {"scanned_at": "2026-11-19T02:00:00Z"},
            "repositories": [{"full_name": repo}]}
    scan = {"id": 5, "scanned_at": "2026-11-19T02:00:00Z", "server": "nextgen-dast",
            "findings": [{"title": f"Reflected XSS {n}", "severity": "high", "url": f"https://claims-{n}.acme.example/search?q=x",
                          "parameter": "q", "cwe": "CWE-79", "evidence": "<script>alert(1)</script>", "remediation": "Encode output"}]}
    c = GitHubCodeReviewConnector({"base_url": "https://gcr.acme.example", "api_token": "gcr_x"})
    await c.store(db, [{"full_name": repo}], [dep], [site], {site["id"]: scan}, {"critical", "high", "medium"})
    r = (await db.execute(select(Device).where(Device.source_id == f"repo:{repo}"))).scalar_one()
    w = (await db.execute(select(Device).where(Device.source_id == f"site:{site['id']}"))).scalar_one()
    f = (await db.execute(select(Finding).where(Finding.device_id == r.id))).scalar_one()
    x = f.details
    assert x["package"]["fixed_in"] == "3.0.15" and x["reachability"]["verdict"] == "reachable"
    assert x["secret"]["verified"] and "preview" not in str(x) and "SECRET" not in str(x)   # never the secret itself
    assert x["link"] == "https://gcr.acme.example/findings/7" and x["fix"]
    assert x["gcr_risk"]["score"] == 74 and x["validation"]["rating"] == "MEDIUM" and x["validation"]["what_to_check"] == "The lockfile."
    assert x["author"] == "Pat Dev" and "pat@acme.example" not in str(x) and x["file_url"].startswith("https://github.com/")
    assert x["asset"]["holds"] == ["PII", "Login"]
    rows = (await client_admin.get(f"/api/v1/devices/{r.id}/findings", params={"status": "all"})).json()["findings"]
    assert rows[0]["domain"] == "code" and rows[0]["details"]["package"]["name"] == "openssl"
    web = (await client_admin.get(f"/api/v1/devices/{w.id}/findings", params={"status": "all"})).json()["findings"][0]
    assert web["domain"] == "web" and web["details"]["parameter"] == "q" and web["details"]["link"].startswith("https://gcr.acme.example/external/")
    # repositories and sites keep their whole names; the vulnerability page lists them with their details
    dev = (await client_admin.get(f"/api/v1/devices/{w.id}")).json()
    assert dev["hostname"] == f"claims-{n}.acme.example"
    aff = (await client_admin.get(f"/api/v1/vulns/{web['vuln_id']}/findings", params={"status": "all"})).json()["findings"]
    assert aff[0]["hostname"] == f"claims-{n}.acme.example" and aff[0]["details"]["url"].endswith("q=x")


def test_gcr_decisions_count_like_they_do_in_gcr():
    from api.integrations.github_code_review import decided
    from api.models.vuln import FindingStatus
    assert decided({"decision": {"kind": "false_positive"}}, "critical") == (FindingStatus.false_positive, "critical")
    assert decided({"decision": {"kind": "exception", "expires": "2999-01-01"}}, "high") == (FindingStatus.risk_accepted, "high")
    assert decided({"decision": {"kind": "exception", "expires": "2001-01-01"}}, "high") == (FindingStatus.open, "high")   # ended
    assert decided({"decision": {"kind": "severity", "severity": "low"}}, "critical") == (FindingStatus.open, "low")
    assert decided({}, "medium") == (FindingStatus.open, "medium")


def test_appsec_evidence_keeps_the_proof_but_not_credentials():
    from api.integrations.rapid7_appsec import details, scrub
    req = "GET /search?q=1&token=abc123&x=2 HTTP/1.1\nHost: shop.acme.example\nCookie: SESSION=s3cr3t\nAuthorization: Bearer eyJabc\n"
    out = scrub(req)
    assert "s3cr3t" not in out and "eyJabc" not in out and "abc123" not in out and "Cookie: [removed]" in out and "q=1" in out
    v = {"attack_type": "SQL Injection", "root_cause": {"url": "https://shop.acme.example/search", "parameter": "q", "method": "GET"},
         "variances": [{"original_value": "1", "attack_value": "1'--", "message": "SQL error returned", "proof_description": "Error text",
                        "references": {"CWE-89": "x", "OWASP2021-A03": "y"}, "attack_exchanges": [{"request": req, "response": "HTTP/1.1 500\nSet-Cookie: a=b"}]}],
         "insight_ui_url": "https://us.appsec.insight.rapid7.com/op/x", "vulnerability_score": 9.1}
    d = details(v, {"description": "<p>Injection lets an attacker run <b>SQL</b>.</p>", "recommendation": "<p>Use bound parameters.</p>"})
    assert d["cwe"] == "CWE-89" and d["parameter"] == "q" and d["attack_value"] == "1'--"
    assert d["description"] == "Injection lets an attacker run SQL ." and d["fix"] == "Use bound parameters."
    assert "s3cr3t" not in d["request"] and "Set-Cookie: [removed]" in d["response"] and d["link"].startswith("https://")
    assert "link" not in details({**v, "insight_ui_url": "javascript:alert(1)"}, None)


@pytest.mark.asyncio
async def test_ctem_exceptions_are_mirrored_to_gcr(db, client_admin, monkeypatch):
    from datetime import date, timedelta

    from sqlalchemy import select

    from api.integrations import gcr_writeback
    from api.integrations.gcr_client import Gcr
    from api.models.device import Device
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.vuln import Finding, FindingStatus
    n = uuid.uuid4().hex[:6]
    repo = f"acme/wb-{n}"
    code = _finding(n, 41)
    code["repository"] = repo
    site = {"id": 7000 + int(n[:3], 16), "host": f"wb-{n}.acme.example", "status": "active", "telemetry": {"category": "live"},
            "last_dast": {"scanned_at": "2026-11-19T02:00:00Z"}, "repositories": []}
    scan = {"id": 12, "scanned_at": "2026-11-19T02:00:00Z", "findings": [{"title": f"Open redirect {n}", "severity": "high", "key": "abc123def"}]}
    c = GitHubCodeReviewConnector({"base_url": "https://gcr.acme.example", "api_token": "gcr_x"})
    await c.store(db, [{"full_name": repo}], [code], [site], {site["id"]: scan}, {"critical", "high", "medium"})
    db.add(IntegrationConfig(vendor=Vendor.github_code_review, name="GCR", is_enabled=True,
                             config={"base_url": "https://gcr.acme.example", "api_token": "gcr_x"}))
    await db.commit()
    calls = []

    async def fake_post(self, path, body):
        calls.append((path, body))
        if path.endswith("/exceptions"):
            return 201, {"id": 77}
        if path.endswith("/approve"):
            return 403, {}   # an ordinary token: GCR keeps it for an admin
        return 200, {}
    monkeypatch.setattr(Gcr, "post", fake_post)
    r = (await db.execute(select(Device).where(Device.source_id == f"repo:{repo}"))).scalar_one()
    w = (await db.execute(select(Device).where(Device.source_id == f"site:{site['id']}"))).scalar_one()
    ends = (date.today() + timedelta(days=30)).isoformat()
    for dev in (r, w):
        f = (await db.execute(select(Finding).where(Finding.device_id == dev.id))).scalar_one()
        made = (await client_admin.post("/api/v1/exceptions", json={"vuln_id": str(f.vuln_id), "scope": "devices",
                                                                     "device_ids": [str(dev.id)], "reason": "Behind the WAF, fix in Q1 2027",
                                                                     "expires_on": ends})).json()
        assert made["ok"] and made["status"] == "approved", made
    rid, wid = r.id, w.id
    db.expire_all()   # the requests above wrote through their own sessions
    assert await gcr_writeback.push(db) == 2
    paths = [p for p, _ in calls]
    assert "/findings/41/exceptions" in paths and "/exceptions/77/approve" in paths
    assert f"/external/assets/{site['id']}/scans/12/findings/abc123def/decision" in paths
    req = next(b for p, b in calls if p == "/findings/41/exceptions")
    assert req["expires"] == ends and len(req["reason"]) >= 20 and req["reason"].startswith("Accepted in CTEM")
    fc = (await db.execute(select(Finding).where(Finding.device_id == rid))).scalar_one()
    assert fc.details["tool_exception"]["state"] == "requested" and fc.status == FindingStatus.risk_accepted
    # nothing is sent twice, and the next sync neither reopens it nor forgets what was sent
    calls.clear()
    assert await gcr_writeback.push(db) == 0 and not calls
    await c.store(db, [{"full_name": repo}], [code], [site], {site["id"]: scan}, {"critical", "high", "medium"})
    db.expire_all()
    fc = (await db.execute(select(Finding).where(Finding.device_id == rid))).scalar_one()
    assert fc.status == FindingStatus.risk_accepted and fc.details["tool_exception"]["state"] == "requested"


@pytest.mark.asyncio
async def test_false_positive_is_recorded_here_and_sent_to_gcr(db, client_admin, client_it_user, monkeypatch):
    from datetime import date, timedelta

    from sqlalchemy import select

    from api.integrations import gcr_writeback
    from api.integrations.gcr_client import Gcr
    from api.models.device import Device
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.vuln import Finding, FindingStatus
    n = uuid.uuid4().hex[:6]
    site = {"id": 6000 + int(n[:3], 16), "host": f"fp-{n}.acme.example", "status": "active", "telemetry": {"category": "live"},
            "last_dast": {"scanned_at": "2026-11-19T02:00:00Z"}, "repositories": []}
    scan = {"id": 3, "scanned_at": "2026-11-19T02:00:00Z", "findings": [{"title": f"Spring4Shell {n}", "severity": "critical", "key": "k9"}]}
    c = GitHubCodeReviewConnector({"base_url": "https://gcr.acme.example", "api_token": "gcr_x"})
    await c.store(db, [], [], [site], {site["id"]: scan}, {"critical", "high", "medium"})
    if not (await db.execute(select(IntegrationConfig).where(IntegrationConfig.vendor == Vendor.github_code_review))).scalars().first():
        db.add(IntegrationConfig(vendor=Vendor.github_code_review, name="GCR", is_enabled=True,
                                 config={"base_url": "https://gcr.acme.example", "api_token": "gcr_x"}))
    await db.commit()
    w = (await db.execute(select(Device).where(Device.source_id == f"site:{site['id']}"))).scalar_one()
    f = (await db.execute(select(Finding).where(Finding.device_id == w.id))).scalar_one()
    wid, vid = w.id, f.vuln_id
    body = {"vuln_id": str(vid), "scope": "devices", "device_ids": [str(wid)], "kind": "false_positive",
            "reason": "The site is not Spring; the scanner matched a banner", "expires_on": (date.today() + timedelta(days=364)).isoformat()}
    calls = []

    async def fake_post(self, path, b):
        calls.append((path, b))
        return 200, {}
    monkeypatch.setattr(Gcr, "post", fake_post)
    made = (await client_admin.post("/api/v1/exceptions", json=body)).json()
    assert made["status"] == "approved" and made["findings_covered"] == 1
    one = (await client_admin.get(f"/api/v1/exceptions/{made['id']}")).json()
    assert one["kind"] == "false_positive"
    db.expire_all()
    f = (await db.execute(select(Finding).where(Finding.device_id == wid))).scalar_one()
    assert f.status == FindingStatus.false_positive
    await gcr_writeback.push(db, [made["id"]])
    path, sent = calls[-1]
    assert path.endswith("/findings/k9/decision") and sent["kind"] == "false_positive" and "expires" not in sent
    assert sent["reason"].startswith("False positive, per CTEM")


@pytest.mark.asyncio
async def test_writeback_finds_the_gcr_reference_for_older_rows():
    from types import SimpleNamespace

    from api.integrations.gcr_writeback import _find_in_scan

    class G:
        async def latest_scan(self, site):
            assert site == 154
            return {"id": 1861, "findings": [{"title": "Other", "key": "a1"}, {"title": "VMware ESXi SLP - Heap Overflow DoS", "key": "f00d"}]}
    f = SimpleNamespace(device=SimpleNamespace(source_id="site:154"), vuln=SimpleNamespace(title="VMware ESXi SLP - Heap Overflow DoS"))
    assert await _find_in_scan(G(), f) == (154, 1861, "f00d")
    gone = SimpleNamespace(device=SimpleNamespace(source_id="site:154"), vuln=SimpleNamespace(title="Fixed already"))
    assert await _find_in_scan(G(), gone) == (None, None, None)
    assert await _find_in_scan(G(), SimpleNamespace(device=SimpleNamespace(source_id="repo:x"), vuln=None)) == (None, None, None)


@pytest.mark.asyncio
async def test_gcr_requests_retry_and_say_what_failed(monkeypatch):
    import asyncio

    import httpx

    from api.integrations.gcr_client import Gcr, GcrError

    async def no_wait(*a, **k):
        return None
    monkeypatch.setattr(asyncio, "sleep", no_wait)
    tries = {"n": 0}

    def flaky(request):
        tries["n"] += 1
        if tries["n"] < 3:
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(200, json={"total": 1, "findings": [{"id": 1}]})
    g = Gcr({"base_url": "https://gcr.acme.example", "api_token": "gcr_x"})
    g.client = httpx.AsyncClient(transport=httpx.MockTransport(flaky))
    assert len(await g.findings("open")) == 1 and tries["n"] == 3   # two timeouts, then it worked

    def dead(request):
        raise httpx.ReadTimeout("slow", request=request)
    g.client = httpx.AsyncClient(transport=httpx.MockTransport(dead))
    with pytest.raises(GcrError) as e:
        await g.findings("open")
    assert "didn't answer in time" in str(e.value) and "page 1" in str(e.value)


@pytest.mark.asyncio
async def test_many_exceptions_are_saved_in_one_request(db, client_admin, monkeypatch):
    from datetime import date, timedelta

    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, Vulnerability
    queued = []
    monkeypatch.setattr("api.core.tasks.rescore_devices.delay", lambda ids: queued.append(ids))
    n = uuid.uuid4().hex[:6]
    dev = Device(hostname=f"bulk-{n}", device_type=DeviceType.server)
    db.add(dev)
    await db.flush()
    vids = []
    for i in range(30):
        v = Vulnerability(source="test", source_vuln_id=f"b{n}{i}", title=f"bulk {n} {i}", cvss_base=5.0)
        db.add(v)
        await db.flush()
        db.add(Finding(device_id=dev.id, vuln_id=v.id, source="test"))
        vids.append(str(v.id))
    await db.commit()
    ends = (date.today() + timedelta(days=30)).isoformat()
    items = [{"vuln_id": v, "scope": "finding", "device_ids": [str(dev.id)], "reason": "Bulk accepted for the test",
              "expires_on": ends} for v in vids]
    items.append({**items[0]})   # a duplicate is refused, the rest still save
    r = (await client_admin.post("/api/v1/exceptions/batch", json={"items": items})).json()
    assert r["saved"] == 30 and r["rescoring"] and sum(1 for x in r["results"] if not x["ok"]) == 1
    assert len(queued) == 1 and queued[0] == [str(dev.id)]   # rescored once, in the background
    assert (await client_admin.post("/api/v1/exceptions/batch", json={"items": []})).status_code == 422


@pytest.mark.asyncio
async def test_score_follows_the_current_grade_not_the_advisory(db):
    from sqlalchemy import select

    from api.models.vuln import Vulnerability
    n = uuid.uuid4().hex[:6]
    other = f"acme/billing-{n}"
    dep = dict(kind="dependency", file="requirements.txt", rule="", package={"name": "pyarrow", "version": "14.0.0"})
    found = [   # the same advisory (CVSS 9.8): regraded to info in one repository, to high in another, untouched in a third
        _finding(n, 1, severity="info", title="pyarrow deserialization", vulnerability={"id": f"GHSA-{n}-info", "cvss_score": 9.8}, **dep),
        _finding(n, 2, severity="info", title="pyarrow deserialization 2", vulnerability={"id": f"GHSA-{n}-mix", "cvss_score": 9.8}, **dep),
        _finding(n, 3, severity="high", repository=other, title="pyarrow deserialization 2",
                 vulnerability={"id": f"GHSA-{n}-mix", "cvss_score": 9.8}, **dep),
        _finding(n, 4, severity="critical", title="kept", vulnerability={"id": f"GHSA-{n}-keep", "cvss_score": 9.8}, **dep),
    ]
    c = GitHubCodeReviewConnector({"base_url": "https://gcr.acme.example", "api_token": "gcr_x"})
    await c.store(db, [{"full_name": f"acme/claims-portal-{n}"}, {"full_name": other}], found, [], {},
                  {"critical", "high", "medium", "low", "info"})

    async def score(ghsa):
        v = (await db.execute(select(Vulnerability).where(Vulnerability.source == "github_code_review",
                                                          Vulnerability.source_vuln_id.like(f"%{ghsa}%")))).scalar_one()
        return v.cvss_base, v.description or ""
    s, why = await score(f"GHSA-{n}-info")
    assert s == 0.0 and "Advisory CVSS 9.8; Code Review grades it info" in why
    assert (await score(f"GHSA-{n}-mix"))[0] == 7.5        # the highest current grade where it's found: high
    assert (await score(f"GHSA-{n}-keep"))[0] == 9.8       # still critical: the advisory's own score
