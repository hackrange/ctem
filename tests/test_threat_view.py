"""Cyber Threats: one shape for every source, search, worst first, paging and clickable details."""
from __future__ import annotations

import uuid

import pytest


def test_normalize_maps_each_connector_shape():
    from api.core.threat_view import normalize

    cs = normalize("threat_alert_x", {"source": "crowdstrike", "severity": "High", "hostname": "DESKTOP001",
                                      "technique": "Cloud-based ML", "description": "Macro file looked bad."})
    assert (cs["source_code"], cs["severity"], cs["status"], cs["title"]) == ("CS", "high", "new", "Macro file looked bad.")
    assert cs["technique_id"] is None and cs["detected_estimated"]
    s1 = normalize("threat_alert_s1_1", {"source": "sentinelone", "severity": 85, "mitre_ttps": [{"id": "t1059.001"}],
                                         "detected_at": "2026-11-20T10:00:00Z", "link": "https://evil.example/"})
    assert (s1["source_code"], s1["severity"], s1["technique_id"], s1["link"]) == ("S1", "critical", "T1059.001", None)
    assert normalize("k", {"source": "newtool", "hosts": ["server001"]})["source_code"] == "NEWTOOL"


async def _seed(db, rows):
    import json
    from api.models.settings import AppSetting
    for key, item in rows.items():
        db.add(AppSetting(key=f"threat_alert_{key}", value=json.dumps(item), is_sensitive=False))
    await db.commit()


@pytest.mark.asyncio
async def test_alerts_search_sort_page_and_detail(db, client_cyber, client_read_only):
    from api.models.device import Device, DeviceType

    tag, host = uuid.uuid4().hex[:8], f"h{uuid.uuid4().hex[:8]}"
    dev = Device(hostname=host.upper(), device_type=DeviceType.workstation, source="crowdstrike")
    db.add(dev)
    await db.commit()
    await _seed(db, {
        f"{tag}:low": {"source": "crowdstrike", "severity": "Low", "title": f"{tag} low", "hostname": host},
        f"{tag}:crit": {"source": "crowdstrike", "severity": "Critical", "title": f"{tag} crit", "status": "in_progress",
                        "technique_id": "T1003", "detected_at": "2026-11-20T10:00:00Z", "hostname": f"{host}.ad.acme.example"},
        f"{tag}:med": {"source": "splunk", "severity": "medium", "description": f"{tag} medium from splunk"},
    })

    r = await client_cyber.get("/api/v1/threat/alerts", params={"q": tag})
    d = r.json()
    assert d["total"] == 3 and [a["severity"] for a in d["alerts"]] == ["critical", "medium", "low"]  # worst first
    crit = d["alerts"][0]
    assert crit["device_id"] == dev.id and crit["source_code"] == "CS" and crit["status"] == "in_progress"
    assert {"source": "crowdstrike", "code": "CS"} in d["sources"]

    page2 = (await client_cyber.get("/api/v1/threat/alerts", params={"q": tag, "limit": 2, "offset": 2})).json()
    assert page2["total"] == 3 and [a["severity"] for a in page2["alerts"]] == ["low"]
    only = (await client_cyber.get("/api/v1/threat/alerts", params={"q": tag, "source": "SPL"})).json()
    assert [a["source_code"] for a in only["alerts"]] == ["SPL"]
    assert (await client_cyber.get("/api/v1/threat/alerts", params={"q": "T1003", "source": "cs"})).json()["total"] >= 1
    asc = (await client_cyber.get("/api/v1/threat/alerts", params={"q": tag, "sort": "severity", "order": "asc"})).json()
    assert asc["alerts"][0]["severity"] == "low"

    one = await client_cyber.get("/api/v1/threat/alerts/detail", params={"id": crit["id"]})
    assert one.status_code == 200 and one.json()["technique_id"] == "T1003" and one.json()["device_id"] == dev.id
    assert (await client_cyber.get("/api/v1/threat/alerts/detail", params={"id": f"threat_alert_{tag}:nope"})).status_code == 404
    assert (await client_cyber.get("/api/v1/threat/alerts/detail", params={"id": "app_secret_key"})).status_code == 422
    assert (await client_read_only.get("/api/v1/threat/alerts/detail", params={"id": crit["id"]})).status_code in (401, 403)


@pytest.mark.asyncio
async def test_crowdstrike_alert_fields_survive_the_shipper_path(db, client_cyber):
    from api.collector.schemas import CsDetection
    from api.integrations.crowdstrike import CrowdStrikeConnector

    tag = uuid.uuid4().hex[:8]
    det = CsDetection.model_validate({"detection_id": f"cid:ind:{tag}", "max_severity_displayname": "High",
                                      "title": f"{tag} lsass", "status": "new", "detected_at": "2026-11-20T10:00:00Z",
                                      "technique_id": "T1003.001", "link": "https://falcon.crowdstrike.com/x",
                                      "device": {"hostname": "desktop001", "device_id": "b" * 32}})
    await CrowdStrikeConnector({})._cache_threats([det.model_dump(exclude_none=True)] * 2, db)
    a = (await client_cyber.get("/api/v1/threat/alerts", params={"q": tag})).json()["alerts"]
    assert len(a) == 1 and a[0]["title"] == f"{tag} lsass" and a[0]["detected_at"].startswith("2026-11-20T10:00:00")
    assert a[0]["link"] == "https://falcon.crowdstrike.com/x" and not a[0]["detected_estimated"]
    with pytest.raises(ValueError):
        CsDetection.model_validate({"detection_id": "x", "link": "https://falcon.crowdstrike.com.evil.example/x"})
