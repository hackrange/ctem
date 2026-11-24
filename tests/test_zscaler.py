"""Zscaler (OneAPI): one token POST to the tenant's ZIdentity and GETs on an allow-list, nothing else; and what its
inventory and policy say about risk."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest


def test_only_the_token_post_and_allow_listed_gets_can_be_sent():
    from api.integrations.zscaler import API, allowed
    assert allowed("POST", "https://acme.zslogin.net/oauth2/v1/token", "acme")
    assert not allowed("POST", "https://evil.zslogin.net/oauth2/v1/token", "acme")
    assert allowed("GET", API + "/zia/api/v1/firewallFilteringRules", "acme")
    assert allowed("GET", API + "/zcc/papi/public/v1/getDevices?page=1", "acme")
    for method, path in (("GET", "/zcc/papi/public/v1/getOtp"), ("GET", "/zcc/papi/public/v1/getPasswords"),
                         ("POST", "/zia/api/v1/firewallFilteringRules"), ("PUT", "/zia/api/v1/firewallFilteringRules/1"),
                         ("DELETE", "/zia/api/v1/adminUsers/1"), ("POST", "/zia/api/v1/status/activate"), ("GET", "/zia/api/v1/status/activate"),
                         ("GET", "/zia/api/v1/users"), ("GET", "/zdx/v1/devices/1/deeptraces")):
        assert not allowed(method, API + path, "acme"), (method, path)
    assert not allowed("GET", "https://api.zsapi.net.evil.example/zia/api/v1/adminUsers", "acme")


@pytest.mark.asyncio
async def test_inventory_and_policy_become_findings_and_nothing_but_reads_is_sent(db, monkeypatch):
    import httpx

    import api.integrations.zscaler as zs
    from api.integrations.base import get_connector
    from api.models.device import Device, DeviceType
    from api.models.identity import PostureFinding
    from api.models.zscaler import ZscalerDevice
    from sqlalchemy import select
    tag = uuid.uuid4().hex[:6].upper()
    now = datetime.now(timezone.utc)
    db.add_all([Device(hostname=f"WS-NOZ{tag}", device_type=DeviceType.workstation, last_seen=now),
                Device(hostname=f"WS-OK{tag}", device_type=DeviceType.workstation, last_seen=now),
                Device(hostname=f"WS-OLD{tag}", device_type=DeviceType.workstation, last_seen=now)])
    await db.commit()
    old = (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    data = {
        "/zcc/papi/public/v1/getDevices": [
            {"udid": f"u1{tag}", "machineHostname": f"WS-OK{tag}", "registrationState": "Registered", "last_seen_time": now.strftime("%Y-%m-%d %H:%M:%S")},
            {"udid": f"u1{tag}", "machineHostname": f"WS-OK{tag}", "registrationState": "Registered", "last_seen_time": "2020-01-01 00:00:00"},
            {"udid": f"u2{tag}", "machineHostname": f"WS-OLD{tag}", "registrationState": "Registered", "last_seen_time": old},
            {"udid": f"u3{tag}", "machineHostname": f"RETIRED{tag}", "registrationState": "Removed", "last_seen_time": old}],
        "/zdx/v1/devices": {"devices": [{"id": 1, "name": f"WS-OK{tag}(Dell Latitude Windows 11)"}]},
        "/zia/api/v1/urlFilteringRules": [{"id": 1, "name": "Let it all in", "state": "ENABLED", "action": "ALLOW", "order": 1,
                                           "urlCategories": ["ANONYMIZER", "NEWS"]},
                                          {"id": 2, "name": "Blocked", "state": "ENABLED", "action": "BLOCK", "urlCategories": ["ANONYMIZER"]}],
        "/zia/api/v1/sslInspectionRules": [{"id": 3, "name": "Skip all", "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["ANY"]},
                                           {"id": 4, "name": "Skip banking", "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"},
                                            "urlCategories": ["FINANCE"]}],
        "/zia/api/v1/firewallFilteringRules": [{"id": 5, "name": "Any any", "state": "ENABLED", "action": "ALLOW"},
                                               {"id": 6, "name": "DNS out", "state": "ENABLED", "action": "ALLOW", "nwServices": [{"id": 1}]}],
        "/zia/api/v1/webDlpRules": [{"id": 7, "name": "PCI", "state": "DISABLED", "action": "BLOCK"}],
        "/zia/api/v1/adminUsers": [{"loginName": "a@acme.example", "isPasswordLoginAllowed": True, "role": {"name": "Super Admin"}}],
    }
    sent = []

    def handler(request):
        sent.append((request.method, request.url.host, request.url.path))
        if request.url.path == "/oauth2/v1/token":
            return httpx.Response(200, json={"access_token": "t", "expires_in": 1800})
        body = data.get(request.url.path, [])
        if request.url.path.endswith("getDevices") and int(request.url.params.get("page", 1)) > 1:
            body = []
        return httpx.Response(200, json=body)
    monkeypatch.setattr(zs, "safe_client", lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    await get_connector("zscaler", {"vanity_domain": "acme", "client_id": "c", "client_secret": "s"}).sync(db)
    assert {m for m, h, p in sent if m != "GET"} == {"POST"} and [p for m, h, p in sent if m == "POST"] == ["/oauth2/v1/token"]
    zd = {z.udid: z for z in (await db.execute(select(ZscalerDevice).where(ZscalerDevice.udid.like(f"%{tag}")))).scalars()}
    assert set(zd) == {f"u1{tag}", f"u2{tag}", f"u3{tag}"} and zd[f"u1{tag}"].zdx and zd[f"u1{tag}"].device_id
    f = {p.external_id: p for p in (await db.execute(select(PostureFinding).where(PostureFinding.source == "zscaler"))).scalars()}
    assert "zia:url:1" in f and "zia:url:2" not in f and "zia:ssl:3" in f and "zia:ssl:4" not in f
    assert "zia:fw:5" in f and "zia:fw:6" not in f and "zia:dlp:7" in f and "zia:admins:password" in f
    assert f"WS-NOZ{tag}" in f["zcc:coverage"].description and f"WS-OK{tag}" not in f["zcc:coverage"].description
    assert f"WS-OLD{tag}" in f["zcc:stale"].description and f"RETIRED{tag}" not in f["zcc:stale"].description
    data["/zia/api/v1/firewallFilteringRules"] = []
    await get_connector("zscaler", {"vanity_domain": "acme", "client_id": "c", "client_secret": "s"}).sync(db)
    fw = (await db.execute(select(PostureFinding).where(PostureFinding.external_id == "zia:fw:5").execution_options(populate_existing=True))).scalar_one()
    assert fw.is_resolved   # fixed in Zscaler: resolved here
