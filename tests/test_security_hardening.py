"""The security review's fixes: probe results can't move the retention clock, one shipper per fleet-wide source,
private findings stay in scope, caches follow access, approved dashboards can't be sliced, SSO-only covers shipper
enrollment, sessions end on the server, and only the reverse proxy picks the client address."""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

NOW = datetime.now(timezone.utc)
CS = {"client_id": "a" * 32}
LDAP = {"host": "dc001.acme.example", "bind_user": "ACME\\svc-ctem"}


def _near_now(t):
    t = t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return abs((t - datetime.now(timezone.utc)).total_seconds()) < 120


# ── 1. Network probe results ──────────────────────────────────────────────────

async def test_probe_times_are_the_servers_and_silence_counts_only_where_ctem_asked(db):
    from api.core import netprobe
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType
    net = f"10.{random.randint(200, 250)}.{random.randint(0, 255)}"

    def host(last, **kw):
        ip = f"{net}.{last}"
        d = Device(hostname=f"h{last}-{uuid.uuid4().hex[:6]}", device_type=DeviceType.server, ip=ip, ip_hash=search_hash(ip),
                   subnet_hash=search_hash(f"{net}.0/24"), **kw)
        db.add(d)
        return d
    unmanaged = host(10, sources=",horizon3,")
    scanned = host(11, sources=",rapid7_insightvm,", last_seen=NOW - timedelta(days=1))     # managed and seen: not asked
    stale = host(12, sources=",rapid7_insightvm,", last_seen=NOW - timedelta(days=60))      # managed, unseen: asked
    await db.flush()
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    v = Vulnerability(source="t_sec", source_vuln_id=f"s{uuid.uuid4().hex[:6]}", title="t")
    db.add(v)
    await db.flush()
    db.add(Finding(device_id=stale.id, vuln_id=v.id, source="t_sec", status=FindingStatus.open))
    await db.commit()
    long_ago = NOW - timedelta(days=40)
    await netprobe.apply(db, [{"ip": d.ip, "alive": False, "at": long_ago} for d in (unmanaged, scanned, stale)])
    await db.commit()
    for d in (unmanaged, stale):
        await db.refresh(d)
        assert d.silent_since is not None and _near_now(d.silent_since)   # not 40 days ago, whatever the shipper said
    await db.refresh(scanned)
    assert scanned.silent_since is None and scanned.probed_at is None     # CTEM never asked about it
    await netprobe.apply(db, [{"ip": unmanaged.ip, "alive": True, "ports": [443], "at": NOW + timedelta(days=9)}])
    await db.refresh(unmanaged)
    assert unmanaged.silent_since is None and _near_now(unmanaged.alive_at)


# ── 2. One shipper per fleet-wide source ──────────────────────────────────────

async def test_only_one_shipper_runs_a_source_that_closes_fleet_wide(client_admin, db, monkeypatch):
    from api.collector import service
    from api.models.collector import CollectorProfile
    monkeypatch.setattr(service, "ONE_PER_FLEET", {"crowdstrike": "CrowdStrike", "rapid7_console": "Rapid7 InsightVM console"})
    for p in (await db.execute(select(CollectorProfile))).scalars():   # earlier tests' shippers
        if "crowdstrike" in (p.modules or {}):
            p.modules = {k: v for k, v in p.modules.items() if k != "crowdstrike"} or {"ldap": {"enabled": True, "settings": LDAP}}
    await db.commit()
    a, b = f"cs-a-{uuid.uuid4().hex[:6]}", f"cs-b-{uuid.uuid4().hex[:6]}"
    r = await client_admin.post("/api/v1/collectors", json={"name": a, "modules": {"crowdstrike": {"enabled": True, "settings": CS}}})
    assert r.status_code == 201, r.json()
    pid = r.json()["id"]
    r = await client_admin.post("/api/v1/collectors", json={"name": b, "modules": {"crowdstrike": {"enabled": True, "settings": CS}}})
    assert r.status_code == 409 and a in r.json()["detail"]
    r = await client_admin.post("/api/v1/collectors", json={"name": b, "modules": {"ldap": {"enabled": True, "settings": LDAP}}})
    assert r.status_code == 201
    bid = r.json()["id"]
    # the first keeps running it through any save
    assert (await client_admin.put(f"/api/v1/collectors/{pid}", json={"schedule_minutes": 120})).status_code == 200
    assert (await client_admin.put(f"/api/v1/collectors/{pid}", json={"modules": {"crowdstrike": {"enabled": True, "settings": CS},
                                                                                 "ldap": {"enabled": True, "settings": LDAP}}})).status_code == 200
    # the second may take it once the first lets go
    assert (await client_admin.put(f"/api/v1/collectors/{bid}", json={"modules": {"crowdstrike": {"enabled": True, "settings": CS}}})).status_code == 409
    assert (await client_admin.put(f"/api/v1/collectors/{pid}", json={"modules": {"ldap": {"enabled": True, "settings": LDAP}}})).status_code == 200
    assert (await client_admin.put(f"/api/v1/collectors/{bid}", json={"modules": {"crowdstrike": {"enabled": True, "settings": CS}}})).status_code == 200
    for x in (pid, bid):
        await client_admin.delete(f"/api/v1/collectors/{x}")


# ── 3 and 4. Private findings in scope, caches follow access ──────────────────

async def test_private_findings_are_read_only_in_scope_and_cache_keys_follow_access(db, client_read_only, read_only_user):
    from api.auth.device_scope import access_key
    from api.models.device import Device, DeviceAssignment, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    tag = uuid.uuid4().hex[:6]
    repo = Device(hostname=f"acme/secret-{tag}", device_type=DeviceType.code_repository)
    host = Device(hostname=f"srv-{tag}", device_type=DeviceType.server)
    code = Vulnerability(source="github_code_review", source_vuln_id=f"code:{tag}", title=f"Key in src/{tag}.py", domain="code")
    cve = Vulnerability(source="rapid7_insightvm", source_vuln_id=f"cve-{tag}", title=f"CVE-2099-{tag}", domain="infra")
    db.add_all([repo, host, code, cve])
    await db.flush()
    db.add_all([Finding(device_id=repo.id, vuln_id=code.id, source="github_code_review", status=FindingStatus.open, domain="code"),
                Finding(device_id=host.id, vuln_id=cve.id, source="rapid7_insightvm", status=FindingStatus.open)])
    await db.commit()
    before = await access_key(read_only_user, db)
    unknown = await client_read_only.get(f"/api/v1/vulns/{uuid.uuid4()}")
    hidden = await client_read_only.get(f"/api/v1/vulns/{code.id}")
    assert hidden.status_code == unknown.status_code == 404 and hidden.json() == unknown.json()
    assert (await client_read_only.get(f"/api/v1/vulns/{cve.id}")).status_code == 200   # public CVE: still readable
    db.add(DeviceAssignment(device_id=repo.id, user_id=read_only_user.id))
    await db.commit()
    assert (await client_read_only.get(f"/api/v1/vulns/{code.id}")).status_code == 200   # theirs now
    assert await access_key(read_only_user, db) != before                               # so a cached view isn't reused


# ── 5. Approved all-data dashboards ───────────────────────────────────────────

async def test_an_approved_dashboard_shows_everything_only_with_its_own_filters(db, cyber_user):
    from api.models.dashboard import Dashboard, Visibility
    from api.routes import dashboards as rd
    saved = {"filters": [{"field": "device_type", "op": "is", "value": "server"}], "match": "all"}
    d = Dashboard(name="wide", owner_id=str(cyber_user.id), owner_name="x", visibility=Visibility.everyone, published=True,
                  data_scope="everything", widgets=[{"id": "w1", "metric": "devices.riskiest", "viz": "table", "params": {}}],
                  filters=rd._dfilters(saved["filters"], "all"))
    db.add(d)
    await db.commit()
    got = await rd._published_wide(db, cyber_user, d.id, saved["filters"], "all")
    assert "w1" in got
    assert await rd._published_wide(db, cyber_user, d.id, [{"field": "device_type", "op": "is", "value": "workstation"}], "all") == {}
    assert await rd._published_wide(db, cyber_user, d.id, [], "all") == {}
    await db.delete(d)
    await db.commit()


# ── 6. SSO only covers shipper enrollment ─────────────────────────────────────

async def test_sso_only_set_in_admin_also_stops_shipper_password_enrollment(db, client, monkeypatch):
    from fastapi import HTTPException

    from api.auth import sso_config
    from api.collector import login

    async def sso_only(_db):
        return "oidc_only", object()
    monkeypatch.setattr(sso_config, "effective", sso_only)
    with pytest.raises(HTTPException) as e:
        await login.check_admin_password(db, "anyone", "x" * 12)
    assert e.value.status_code == 403
    assert (await client.get("/api/v1/collector/info")).json()["password_login"] is False


# ── 7. Sessions end on the server ─────────────────────────────────────────────

class _FakeRedis:
    store: dict = {}

    async def set(self, k, v, ex=None):
        self.store[k] = v

    async def exists(self, k):
        return int(k in self.store)


async def test_signing_out_and_a_new_password_end_sessions_everywhere(db, monkeypatch):
    import re

    from httpx import ASGITransport, AsyncClient

    from api.auth import local, sso_config
    from api.core.config import get_settings
    from api.core.db import get_session
    from api.main import create_app
    from api.models.user import User, UserRole

    async def local_only(_db):
        return "local_only", None
    monkeypatch.setattr(sso_config, "effective", local_only)
    monkeypatch.setattr(get_settings(), "mfa_required", False)
    monkeypatch.setattr(local, "_redis", lambda: _FakeRedis())
    pw = "correct horse battery staple"
    u = User(username=f"sess{uuid.uuid4().hex[:6]}", is_local=True, is_active=True, password_hash=local.hash_password(pw))
    db.add(u)
    await db.flush()
    db.add(UserRole(user_id=u.id, role_name="cyber"))
    await db.commit()
    app = create_app()

    async def _s():
        yield db
    app.dependency_overrides[get_session] = _s

    async def browser():
        c = AsyncClient(transport=ASGITransport(app=app), base_url="https://test", headers={"Sec-Fetch-Site": "same-origin"})
        page = await c.get("/login")
        csrf = re.search(r'name="_csrf" value="([^"]*)"', page.text).group(1)
        assert (await c.post("/auth/login", data={"username": u.username, "password": pw, "_csrf": csrf})).status_code in (302, 303)
        return c
    me = "/api/v1/auth/totp/status"
    a, b = await browser(), await browser()
    stolen = dict(a.cookies)
    assert (await a.get(me)).status_code == 200
    await a.get("/auth/logout")
    thief = AsyncClient(transport=ASGITransport(app=app), base_url="https://test", cookies=stolen)
    assert (await thief.get(me)).status_code == 401            # a copy of the signed-out cookie is dead too
    c = await browser()
    r = await b.post("/api/v1/profile/password", json={"current_password": pw, "new_password": pw + " again"})
    assert r.status_code == 200, r.text
    assert (await b.get(me)).status_code == 200                 # the session that changed it stays
    assert (await c.get(me)).status_code == 401                 # every other one ends
    for x in (a, b, c, thief):
        await x.aclose()


# ── 8. Only the reverse proxy picks the client address ────────────────────────

async def test_forwarded_headers_count_only_from_the_proxy():
    from api.core.trusted_proxy import TrustedProxyMiddleware
    seen = {}

    async def app(scope, receive, send):
        seen["client"], seen["scheme"] = scope["client"], scope["scheme"]

    def scope(peer):
        return {"type": "http", "client": (peer, 5555), "scheme": "http",
                "headers": [(b"x-forwarded-for", b"203.0.113.9"), (b"x-forwarded-proto", b"https")]}
    mw = TrustedProxyMiddleware(app, "localhost")
    via = scope("127.0.0.1")
    await mw(via, None, None)
    assert seen == {"client": ("203.0.113.9", 0), "scheme": "https"}
    assert via["client"] == ("203.0.113.9", 0)   # the server's own scope too, for its access log
    await mw(scope("10.100.142.8"), None, None)                 # another container on the network
    assert seen == {"client": ("10.100.142.8", 5555), "scheme": "http"}
    await TrustedProxyMiddleware(app, "")(scope("127.0.0.1"), None, None)   # no proxy configured: headers ignored
    assert seen["client"] == ("127.0.0.1", 5555)
    await TrustedProxyMiddleware(app, "no-such-proxy.invalid")(scope("10.1.1.1"), None, None)   # unresolvable: as before
    assert seen["client"] == ("203.0.113.9", 0)


async def test_only_the_api_docs_page_may_load_its_pinned_cdn_files(client_admin):
    page = await client_admin.get("/api/docs")
    other = await client_admin.get("/api/v1/impersonate")
    assert page.status_code == 200 and "cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/" in page.headers["content-security-policy"]
    assert "cdnjs" not in other.headers["content-security-policy"]


@pytest.mark.asyncio
async def test_sign_in_allows_no_inline_script_json_loads_nothing_and_health_has_no_version(client):
    page = await client.get("/login")
    csp = page.headers["content-security-policy"]
    assert "script-src 'self';" in csp and "unsafe-inline" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    assert "<script" not in page.text and " onclick=" not in page.text   # the page really has no script to break
    h = await client.get("/healthz")
    assert h.json() == {"status": "ok"}
    assert h.headers["content-security-policy"].startswith("default-src 'none'") and "frame-ancestors 'none'" in h.headers["content-security-policy"]
    for r in (h, page, await client.get("/api")):
        assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
        assert "includeSubDomains" in r.headers["strict-transport-security"] and r.headers["cross-origin-opener-policy"] == "same-origin"
        assert r.headers["cross-origin-resource-policy"] == "same-origin" and "content-security-policy" in r.headers
    assert h.headers["cache-control"] == "no-store"
