"""Falcon Spotlight and Discover: the shipper's pull (optional, cursor paging, incremental vs full) and CTEM's ingest."""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))
import collector_common as cc  # noqa: E402
import collector_cs_extras as cse  # noqa: E402

AID = "a" * 32
VULN = {"id": "v1_" + "a" * 8, "aid": AID, "status": "open", "created_timestamp": "2026-10-01T00:00:00Z",
        "updated_timestamp": "2026-11-20T00:00:00Z", "host_info": {"hostname": "ws-spot-1"},
        "cve": {"id": "CVE-2026-1111", "name": "Acme Viewer heap overflow", "base_score": 8.8, "severity": "HIGH",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "exprt_rating": "CRITICAL", "exploit_status": 90,
                "cisa_info": {"is_cisa_kev": True}, "actors": ["ACME SPIDER"], "cwes": ["CWE-122"]},
        "apps": [{"product_name_version": "Acme Viewer 3.2"}],
        "remediation": {"entities": [{"title": "Update Acme Viewer to 3.3", "action": "Install the 3.3 update",
                                      "link": "https://acme.example/advisory"}]}}


class Api:
    def __init__(self, pages=None, deny=None):
        self.pages, self.deny, self.paths = pages or {}, deny, []

    def call(self, method, path):
        self.paths.append(path)
        if self.deny and self.deny in path:
            raise cc.HttpError(403, "forbidden")
        for k, v in self.pages.items():
            if path.startswith(k):
                return v.pop(0) if v else {"resources": []}
        raise AssertionError(path)


def test_spotlight_pages_full_then_incremental_and_is_optional():
    api = Api({"/spotlight/": [{"resources": [VULN], "meta": {"pagination": {"after": "next"}}},
                               {"resources": [dict(VULN, id="v2", cve=dict(VULN["cve"]))], "meta": {"pagination": {}}}]})
    state, notes = {}, []
    out = list(cse.spotlight(api, {"client_id": "c" * 32}, state, notes))
    assert len(out) == 2 and out[0]["spotlight_mode"] == "full" and "status%3A%5B%27open%27" in api.paths[0]
    assert "after=next" in api.paths[1]
    v, c = out[0]["spotlight"][0], out[0]["spotlight_cves"][0]
    assert v["aid"] == AID and v["cve_id"] == "CVE-2026-1111" and v["remediation"][0]["link"] == "https://acme.example/advisory"
    assert c["is_kev"] and c["actors"] == ["ACME SPIDER"] and c["exprt_rating"] == "CRITICAL"
    assert out[1]["spotlight_cves"] == []                                 # each CVE described once per run
    api2 = Api({"/spotlight/": [{"resources": []}]})
    list(cse.spotlight(api2, {"client_id": "c" * 32}, state, notes))
    assert "updated_timestamp" in api2.paths[0]                          # then only what changed
    assert list(cse.spotlight(Api(), {"spotlight": "off"}, {}, notes)) == []
    denied = []
    assert list(cse.spotlight(Api(deny="/spotlight/"), {}, {}, denied)) == [] and "Vulnerabilities: Read" in denied[0]


def test_discover_maps_apps_to_software_once_a_day():
    app = {"id": "x", "name": "Acme Viewer", "vendor": "Acme", "version": "3.2", "installation_paths": ["C:\\Program Files\\Acme"],
           "last_used_file_hash": "AB" * 32, "host": {"aid": AID, "hostname": "ws-spot-1"}}
    state, notes = {}, []
    out = list(cse.discover(Api({"/discover/": [{"resources": [app, {"name": "no host"}]}]}), {}, state, notes))
    item = out[0]["software"][0]
    assert len(out[0]["software"]) == 1 and item["hosts"] == ["ws-spot-1"] and item["sha256"] == "ab" * 32
    assert item["install_path"].startswith("C:") and item["version"] == "3.2"
    assert list(cse.discover(Api(), {}, state, notes)) == []             # done today
    denied = []
    assert list(cse.discover(Api(deny="/discover/"), {}, {}, denied)) == [] and "Assets: Read" in denied[0]


@pytest.mark.asyncio
async def test_ingest_spotlight_findings_fixes_and_full_pass_close(db):
    from datetime import datetime, timedelta, timezone

    from api.collector.ingest import apply_batch
    from api.collector.schemas import CrowdStrikeBatch
    from api.integrations.crowdstrike_spotlight import SOURCE, close_unseen
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Fix, Vulnerability
    n = uuid.uuid4().hex[:6]
    aid = uuid.uuid4().hex
    d = Device(hostname=f"ws-spot-{n}", device_type=DeviceType.workstation, edr_device_id=aid, edr_vendor="crowdstrike")
    db.add(d)
    await db.commit()
    v = cse._vuln(dict(VULN, aid=aid))
    c = cse._cve(VULN["cve"])
    batch = CrowdStrikeBatch.model_validate({"kind": "crowdstrike", "run_id": str(uuid.uuid4()), "spotlight_cves": [c], "spotlight": [v],
                                             "spotlight_mode": "full"})
    assert await apply_batch(db, batch) >= 1
    await db.commit()
    f = (await db.execute(select(Finding).where(Finding.source == SOURCE, Finding.source_id == f"{aid}:CVE-2026-1111"))).scalar_one()
    vul = await db.get(Vulnerability, f.vuln_id)
    assert f.status == FindingStatus.open and f.device_id == d.id and f.details["apps"] == ["Acme Viewer 3.2"]
    assert vul.is_kev and vul.threat_actors == ["ACME SPIDER"] and vul.attack_vector == "network" and vul.cvss_base == 8.8
    assert (await db.execute(select(Fix).where(Fix.key == f.fix_key))).scalar_one().title == "Update Acme Viewer to 3.3"
    assert await close_unseen(db, datetime.now(timezone.utc) + timedelta(minutes=1), str(uuid.uuid4())) >= 1   # untagged: any pass
    await db.commit()
    await db.refresh(f)
    assert f.status == FindingStatus.remediated


def test_tracked_adversaries_raise_the_score_with_a_reason():
    from api.scoring.compensating import ControlContext, apply_multipliers
    s, why = apply_multipliers(50.0, ControlContext(edr_active=True, threat_actors=["ACME SPIDER", "FANCY ACME"]))
    assert s == pytest.approx(50 * 1.2 * 0.7) and any("ACME SPIDER, FANCY ACME" in w for w in why)
