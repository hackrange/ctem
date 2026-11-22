"""Code and Web app scoring: severity, the best exploitation evidence, what the asset holds and where it runs, and
how exposed it is. No EDR or "offline" adjustments, which mean nothing for a repository or a site."""
from __future__ import annotations

import json
import uuid

import pytest

from api.scoring import app_score as a
from api.scoring.device_score import device_grade


def test_findings_score_on_evidence_impact_and_exposure():
    prod_pii = a.impact(None, ["Customer Data", "PII", "Login"], ["Prod"])
    dev = a.impact(None, [], ["Dev"])
    live, hidden = a.exposure("web", True), a.exposure("web", False)
    crit_live, _ = a.score_finding(9.5, 0, False, {"gcr_risk": {"likelihood": "likely"}}, "web", prod_pii, live)
    crit_dev, _ = a.score_finding(9.5, 0, False, {"gcr_risk": {"likelihood": "likely"}}, "web", dev, hidden)
    assert device_grade(crit_live) == "F" and crit_live > crit_dev and device_grade(crit_dev) in ("C", "D")
    # a secret confirmed live outranks one that isn't; a package the code doesn't reach drops
    repo = a.exposure("code", False)
    live_secret, why = a.score_finding(9.5, 0, False, {"secret": {"verified": True}}, "code", a.impact(None, [], []), repo)
    old_secret, _ = a.score_finding(9.5, 0, False, {"secret": {"verified": False}}, "code", a.impact(None, [], []), repo)
    unreached, why2 = a.score_finding(9.8, 0, False, {"reachability": {"verdict": "unlikely"}}, "code", a.impact(None, [], []), repo)
    assert live_secret > old_secret > unreached and "secret confirmed live" in why and "unlikely to reach" in why2[1]
    # known exploited is never below 80; the tool's own risk is averaged in
    assert a.score_finding(5.0, 0, True, {}, "code", dev, repo)[0] >= 80
    alone = a.score_finding(7.5, 0, False, {}, "code", dev, repo)[0]
    blended, why3 = a.score_finding(7.5, 0, False, {"gcr_risk": {"score": 95}}, "code", dev, repo)
    assert blended > alone and "averaged with the tool's own risk 95" in why3
    # no EDR or offline reasons, ever
    assert not any("EDR" in r or "offline" in r.lower() for r in why + why2 + why3)


def test_minor_findings_stay_minor_on_a_live_production_site():
    """Context scales a finding; it doesn't add points. A changed banner on a live prod site is not a C."""
    prod, live = a.impact(None, [], ["prod"]), a.exposure("web", True)
    banner, _ = a.score_finding(0.0, 0, False, {"likelihood": "possible", "risk": "low"}, "web", prod, live)
    cipher, _ = a.score_finding(2.5, 0, False, {"likelihood": "possible", "risk": "low"}, "web", prod, live)
    cookie, why = a.score_finding(2.5, 0, False, {"likelihood": "likely", "risk": "high"}, "web", prod, live)
    assert device_grade(banner) == "A" and device_grade(cipher) in ("A", "B") and cookie > cipher > banner
    assert any("context" in r for r in why) and any("risk level high" in r for r in why)


def test_criticality_tag_wins_and_roll_up_counts_breadth():
    assert a.impact("Very High", ["Public"], ["Dev"]) == (1.0, "criticality Very High")
    assert a.impact(None, ["Public"], [])[0] == 0.35
    one, _ = a.roll_up([82.0])
    ten, why = a.roll_up([82.0] * 10)
    assert one == 82.0 and ten == 91.0 and "9 more serious" in why
    assert a.roll_up([82.0] * 40)[0] == 92.0   # at most 10 points of breadth


@pytest.mark.asyncio
async def test_a_live_site_with_critical_findings_grades_f(db):
    from sqlalchemy import select

    from api.core.device_tags import sync_tags
    from api.models.device import Device, DeviceType
    from api.models.risk import RiskScore
    from api.models.vuln import Finding, Vulnerability
    from api.scoring.engine import recalculate_device
    n = uuid.uuid4().hex[:6]
    site = Device(hostname=f"shop-{n}.acme.example", device_type=DeviceType.website, is_internet_exposed=True)
    db.add(site)
    await db.flush()
    await sync_tags(db, site.id, {"env:Prod"}, ("env:",), "manual", {})
    for i in range(3):
        v = Vulnerability(source="github_code_review", source_vuln_id=f"dast:x{n}{i}", title=f"Injection {n}{i}", cvss_base=9.5, domain="web")
        db.add(v)
        await db.flush()
        db.add(Finding(device_id=site.id, vuln_id=v.id, source="github_code_review", domain="web",
                       details={"likelihood": "likely", "risk": "critical", "asset": {"holds": ["PII"]}}))
    await db.commit()
    await recalculate_device(site, db)
    assert site.risk_grade.value == "F" and site.risk_score >= 80
    why = json.loads((await db.execute(select(RiskScore.score_breakdown).where(RiskScore.entity_id == site.id))).scalar_one())
    assert why["model"] == "web" and "holds PII" in why["impact"] and "live on the internet" in why["exposure"]
    assert not any("EDR" in r for r in why["worst"])


@pytest.mark.asyncio
async def test_owners_missing_on_an_asset_come_from_its_application(db, client_admin):
    from api.core.device_tags import sync_tags
    from api.models.device import Device, DeviceType
    n = uuid.uuid4().hex[:6]
    site = Device(hostname=f"self-{n}.acme.example", device_type=DeviceType.website)
    repo = Device(hostname=f"acme/self-{n}", device_type=DeviceType.code_repository)
    db.add_all([site, repo])
    await db.flush()
    await sync_tags(db, site.id, {f"app:Self{n}", "exec_owner:edward@acme.example"}, ("app:", "exec_owner:"), "manual", {})
    await sync_tags(db, repo.id, {f"app:Self{n}", "app_owner:pat@acme.example"}, ("app:", "app_owner:"), "manual", {})
    await db.commit()
    d = (await client_admin.get(f"/api/v1/devices/{site.id}")).json()
    assert d["related_owners"]["application_owner"] == {"values": ["pat@acme.example"], "via": f"Self{n}"}
    assert "executive_owner" not in d["related_owners"]   # it has its own


@pytest.mark.asyncio
async def test_every_score_keeps_its_reason(db, client_admin):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, Vulnerability
    from api.scoring.engine import recalculate_device
    n = uuid.uuid4().hex[:6]
    host = Device(hostname=f"h-{n}", device_type=DeviceType.server)
    site = Device(hostname=f"w-{n}.acme.example", device_type=DeviceType.website, is_internet_exposed=True)
    db.add_all([host, site])
    await db.flush()
    for dev, dom in ((host, "infra"), (site, "web")):
        v = Vulnerability(source="test", source_vuln_id=f"{dom}-{n}", title=f"t {n}", cvss_base=7.5, domain=dom)
        db.add(v)
        await db.flush()
        db.add(Finding(device_id=dev.id, vuln_id=v.id, source="test", domain=dom, details={"likelihood": "likely"} if dom == "web" else None))
    await db.commit()
    for dev in (host, site):
        await recalculate_device(dev, db)
    h = (await client_admin.get(f"/api/v1/devices/{host.id}")).json()["score_why"]
    w = (await client_admin.get(f"/api/v1/devices/{site.id}")).json()["score_why"]
    assert h["model"] == "host" and "worst 1 of 1" in h["why"] and any("CVSS 7.5" in r for r in h["worst"])
    assert w["model"] == "web" and any("context" in r for r in w["worst"])
    f = (await client_admin.get(f"/api/v1/devices/{site.id}/findings")).json()["findings"][0]
    assert any("context" in r for r in f["details"]["score_why"])


@pytest.mark.asyncio
async def test_owners_are_not_borrowed_from_assets_the_viewer_cannot_open(db, client_it_user, it_user):
    from api.core.device_tags import sync_tags
    from api.models.device import Device, DeviceAssignment, DeviceType
    n = uuid.uuid4().hex[:6]
    site = Device(hostname=f"scoped-{n}.acme.example", device_type=DeviceType.website)
    repo = Device(hostname=f"acme/scoped-{n}", device_type=DeviceType.code_repository)
    db.add_all([site, repo])
    await db.flush()
    await sync_tags(db, site.id, {f"app:Scoped{n}"}, ("app:",), "manual", {})
    await sync_tags(db, repo.id, {f"app:Scoped{n}", "app_owner:hidden@acme.example"}, ("app:", "app_owner:"), "manual", {})
    db.add(DeviceAssignment(device_id=site.id, user_id=it_user.id))   # the site is theirs, the repository isn't
    await db.commit()
    d = (await client_it_user.get(f"/api/v1/devices/{site.id}")).json()
    assert d["related_owners"] == {}
    db.add(DeviceAssignment(device_id=repo.id, user_id=it_user.id))   # once they can open it, it counts
    await db.commit()
    d = (await client_it_user.get(f"/api/v1/devices/{site.id}")).json()
    assert d["related_owners"]["application_owner"]["values"] == ["hidden@acme.example"]
