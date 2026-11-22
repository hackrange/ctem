"""The SIEM alert feed: what raises an alert (once), the shipper's pull, direct HEC, and the box's delivery."""
from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))


@pytest.mark.asyncio
async def test_alerts_are_raised_once_each(db):
    from api.core import alert_feed
    from api.models.alert_feed import FeedAlert
    from api.models.device import Device, DeviceType
    from api.models.settings import AppSetting
    from api.models.vuln import Finding, Vulnerability
    n = uuid.uuid4().hex[:6]
    d = Device(hostname=f"web-kev-{n}", device_type=DeviceType.server, is_internet_exposed=True)
    v = Vulnerability(source="t_feed", source_vuln_id=f"k-{n}", cve_id=f"CVE-2026-{9000 + int(n[:3], 16) % 999}", title=f"Acme RCE {n}",
                      cvss_base=9.8, is_kev=True)
    db.add_all([d, v])
    await db.flush()
    db.add_all([Finding(device_id=d.id, vuln_id=v.id, source="t_feed"),
                AppSetting(key=f"threat_alert_feed{n}", value=json.dumps({"source": "crowdstrike", "id": f"feed{n}", "severity": "Critical",
                                                                          "title": "Credential dumping", "hostname": d.hostname})),
                AppSetting(key=f"threat_alert_low{n}", value=json.dumps({"source": "crowdstrike", "id": f"low{n}", "severity": "Low"}))])
    await db.commit()
    await alert_feed.raise_new(db)
    keys = set((await db.execute(select(FeedAlert.key))).scalars())
    assert f"kev_exposed:{d.id}:{v.cve_id}" in keys and f"edr_alert:feed{n}" in keys and f"edr_alert:low{n}" not in keys
    first = await alert_feed.latest_seq(db)
    await alert_feed.raise_new(db)
    assert (await db.execute(select(FeedAlert).where(FeedAlert.seq > first, FeedAlert.key.like(f"%{n}%")))).scalars().all() == []
    ev = (await db.execute(select(FeedAlert).where(FeedAlert.key == f"kev_exposed:{d.id}:{v.cve_id}"))).scalar_one().event
    assert ev["severity"] == "critical" and ev["hostname"] == d.hostname and ev["cve"] == v.cve_id and ev["key"]


@pytest.mark.asyncio
async def test_shipper_pull_is_closed_unless_forwarding_is_on(client, client_admin, db):
    from api.core import alert_feed
    from api.models.alert_feed import FeedAlert
    from tests.test_collector import _auth, _enroll
    mods = {"splunk": {"settings": {"host": "splunk001", "username": "svc", "forward_alerts": "file"}}}
    p, r, _ = await _enroll(client, client_admin, modules=mods)
    iid, h = p["modules"]["splunk"]["integration_id"], _auth(r.json()["token"])
    start = await client.get(f"/api/v1/collector/alerts/{iid}?after=-1", headers=h)
    assert start.status_code == 200 and start.json()["alerts"] == []
    seq = start.json()["next"]
    db.add(FeedAlert(key=f"t:{uuid.uuid4()}", kind="kev_exposed", severity="critical", title="t", created_at=datetime.now(timezone.utc),
                     event={"kind": "kev_exposed", "title": "t"}))
    await db.commit()
    got = (await client.get(f"/api/v1/collector/alerts/{iid}?after={seq}", headers=h)).json()
    assert [a["kind"] for a in got["alerts"]] == ["kev_exposed"] and got["next"] > seq
    off = {"splunk": {"settings": {"host": "splunk001", "username": "svc"}}}
    p2, r2, _ = await _enroll(client, client_admin, modules=off)
    assert (await client.get(f"/api/v1/collector/alerts/{p2['modules']['splunk']['integration_id']}?after=0",
                             headers=_auth(r2.json()["token"]))).status_code == 404
    assert (await client.get(f"/api/v1/collector/alerts/{iid}?after=0")).status_code == 401
    assert alert_feed.KINDS


def test_box_delivers_to_the_forwarder_file_and_hec(tmp_path, monkeypatch):
    import collector_common as cc
    import collector_splunk as sp
    pages = [{"alerts": [{"kind": "edr_alert", "key": "k1"}], "next": 5, "more": False}]

    class Api:
        def __init__(self):
            self.paths = []

        def call(self, method, path, retries=0):
            self.paths.append(path)
            return pages.pop(0) if pages else {"alerts": [], "next": 5, "more": False}
    posted = []
    monkeypatch.setattr(cc, "pinned_json", lambda *a, **k: posted.append((a, k)) or {})
    state, api = {"ctem_alert_seq:i1": 3}, Api()
    m, s = {"integration_id": "i1"}, {"host": "splunk001", "forward_alerts": "both", "hec_index": "ctem"}
    assert sp.deliver(api, m, s, {"hec_token": "t0ken"}, state, str(tmp_path)) == 1
    assert api.paths[0].endswith("after=3") and state["ctem_alert_seq:i1"] == 5
    line = (tmp_path / "ctem-alerts.json").read_text().strip()
    assert json.loads(line) == {"key": "k1", "kind": "edr_alert"}
    (args, kw) = posted[0]
    assert args[1] == "splunk001" and args[2] == 8088 and kw["headers"]["Authorization"] == "Splunk t0ken"
    assert kw["body"]["sourcetype"] == "ctem:alert" and kw["body"]["index"] == "ctem"
    assert sp.deliver(Api(), m, {"forward_alerts": "hec"}, {}, {}, str(tmp_path)) == 0   # no HEC token: nothing sent


@pytest.mark.asyncio
async def test_direct_hec_keeps_its_place(db, monkeypatch):
    from api.core import alert_delivery, alert_feed
    from api.models.alert_feed import FeedAlert
    from api.models.integration import IntegrationConfig, Vendor
    cfg = IntegrationConfig(vendor=Vendor.splunk, name=f"ACME Splunk Cloud {uuid.uuid4().hex[:4]}", is_enabled=True,
                            config={"base_url": "https://splunk.acme.example:8089", "hec_url": "https://hec.acme.example", "hec_token": "t"})
    db.add(cfg)
    await db.commit()
    sent = []

    class Resp:
        status_code = 200

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, content, headers):
            sent.append((url, content, headers))
            return Resp()
    monkeypatch.setattr("api.core.ssrf.safe_client", lambda **k: Client())
    assert await alert_delivery.deliver(db) == 0                          # first run: start from now
    db.add(FeedAlert(key=f"t:{uuid.uuid4()}", kind="control_failed", severity="high", title="t",
                     created_at=datetime.now(timezone.utc) - timedelta(seconds=1), event={"kind": "control_failed"}))
    await db.commit()
    assert await alert_delivery.deliver(db) >= 1
    url, content, headers = sent[-1]
    assert url == "https://hec.acme.example/services/collector/event" and headers["Authorization"] == "Splunk t"
    assert json.loads(content.splitlines()[-1])["event"]["kind"] == "control_failed"
    assert await alert_delivery.deliver(db) == 0                          # nothing new: nothing sent twice
    assert alert_delivery._hec("http://x") is None and alert_delivery._hec("https://u:p@x") is None
    assert await alert_feed.latest_seq(db) >= 1
