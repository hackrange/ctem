"""Admin > Maintenance API: admin-only, browser-only, step-up before anything that lets a backup out or in."""
from __future__ import annotations

import os
import time
import uuid

import httpx
import pytest
import pytest_asyncio

from api.maintenance import agent_link
from api.maintenance import backup_archive as ba
from api.maintenance import host_agent as ha
from tests.test_maintenance_agent import box  # noqa: F401 - shared fixture

pytestmark = pytest.mark.skipif(os.geteuid() != 0, reason="the agent chowns to root")
EXAMPLE_PW = "Correct-Horse-9"   # example-only test credential
BACKUP_PW = "Backup-Example-Pass-2026"   # example-only test credential
API = "/api/v1/admin/maintenance"


@pytest.fixture(autouse=True)
def _fast_kdf(monkeypatch):
    monkeypatch.setattr(ba, "KDF", {"name": "scrypt", "n": 1 << 14, "r": 8, "p": 1})


async def _user(db, role: str, password: str | None = EXAMPLE_PW):
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from api.auth.local import hash_password
    from api.models.user import User, UserRole
    uid = str(uuid.uuid4())
    db.add(User(id=uid, username=f"{role}-{uid[:6]}", is_local=password is not None, is_active=True, is_locked=False,
                password_hash=hash_password(password) if password else None))
    db.add(UserRole(user_id=uid, role_name=role))
    await db.commit()
    return (await db.execute(select(User).where(User.id == uid).options(selectinload(User.roles)))).scalar_one()


def _client(db, user):
    from api.auth.middleware import get_current_user
    from api.core.db import get_session
    from api.main import create_app

    async def _s():
        yield db
    app = create_app()
    app.dependency_overrides[get_session] = _s
    app.dependency_overrides[get_current_user] = lambda: user
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://test",
                             headers={"Origin": "https://test", "Accept": "application/json"})


@pytest_asyncio.fixture
async def admin(db, box):  # noqa: F811
    u = await _user(db, "admin")
    ha.heartbeat(box)
    async with _client(db, u) as c:
        yield c


async def _step_up(c):
    r = await c.post(f"{API}/step-up", json={"password": EXAMPLE_PW})
    assert r.status_code == 200, r.text


def _real_backup(lay, name="ctem-server001-20261123-010203Z.ctembak") -> str:
    src = os.path.join(lay.root, "dotenv")
    open(src, "w").write("A=1\n")
    path = os.path.join(lay.backups, name)
    ba.pack(path, BACKUP_PW, [("env/dotenv", src)], {"format": ba.FORMAT, "host": "server001", "git_commit": "a" * 40,
                                                       "app_version": "1.0.1", "created_utc": "2026-11-23T01:02:03Z"})
    os.chmod(path, 0o640)
    return name


@pytest.mark.asyncio
async def test_only_admins_at_a_browser(db, box):  # noqa: F811
    cyber = await _user(db, "cyber")
    async with _client(db, cyber) as c:
        assert (await c.get(API)).status_code == 403
        assert (await c.post(f"{API}/backups", json={"password_mode": "default"})).status_code == 403
    adm = await _user(db, "admin")
    async with _client(db, adm) as c:
        r = await c.get(API, headers={"Authorization": "Bearer " + "0" * 64})
        assert r.status_code == 403 and "browser" in r.json()["detail"]
        assert (await c.get("/admin/maintenance", headers={"Accept": "text/html"})).status_code == 200


@pytest.mark.asyncio
async def test_overview_and_backup_requests(admin, box):  # noqa: F811
    d = (await admin.get(API)).json()
    assert d["agent"]["installed"] and d["agent"]["alive"] and d["step_up"]["needs"] == ["password"]
    assert (await admin.post(f"{API}/backups", json={"password_mode": "nope"})).status_code == 400
    bad = {"password_mode": "custom", "password": "Long-Enough-Pass-2026", "confirm": "Long-Enough-Pass-2027"}
    assert "don't match" in (await admin.post(f"{API}/backups", json=bad)).json()["detail"]
    weak = {"password_mode": "custom", "password": "short", "confirm": "short"}
    assert "stronger" in (await admin.post(f"{API}/backups", json=weak)).json()["detail"]
    r = await admin.post(f"{API}/backups", json={"password_mode": "default"})
    assert r.status_code == 200
    jid = r.json()["job"]
    assert (await admin.get(f"{API}/jobs/{jid}")).json()["job"]["status"] == "queued"
    ha.run(box)
    got = (await admin.get(f"{API}/jobs/{jid}")).json()
    assert got["job"]["status"] == "ok" and "Backup ready" in got["log"]
    assert (await admin.get(f"{API}/jobs/../../etc")).status_code == 404


@pytest.mark.asyncio
async def test_agent_missing_or_silent(admin, box):  # noqa: F811
    os.chmod(box.inbox, 0o500)
    os.unlink(os.path.join(box.state, "agent.json"))
    r = await admin.post(f"{API}/backups", json={"password_mode": "default"})
    assert r.status_code == 409 and "--maintenance-setup" in r.json()["detail"]
    os.chmod(box.inbox, 0o770)
    ha.heartbeat(box)
    path = os.path.join(box.state, "agent.json")
    os.utime(path, None)
    import json
    hb = json.load(open(path))
    hb["time"] = int(time.time()) - 3600
    open(path, "w").write(json.dumps(hb))
    assert "checked in" in (await admin.post(f"{API}/backups", json={"password_mode": "default"})).json()["detail"]


@pytest.mark.asyncio
async def test_download_needs_step_up_and_a_real_name(admin, box):  # noqa: F811
    name = _real_backup(box)
    r = await admin.get(f"{API}/backups/{name}/download")
    assert r.status_code == 403 and r.headers.get("x-step-up") == "required"
    assert (await admin.post(f"{API}/step-up", json={"password": "wrong-one"})).status_code == 401
    await _step_up(admin)
    r = await admin.get(f"{API}/backups/{name}/download")
    assert r.status_code == 200 and r.content.startswith(ba.MAGIC) and "attachment" in r.headers["content-disposition"]
    for bad in ("..%2F..%2Fetc%2Fpasswd", "x.txt", ".ctembak", "nope.ctembak"):
        assert (await admin.get(f"{API}/backups/{bad}/download")).status_code == 404
    os.symlink("/etc/hostname", os.path.join(box.backups, "link.ctembak"))
    assert (await admin.get(f"{API}/backups/link.ctembak/download")).status_code == 404


@pytest.mark.asyncio
async def test_step_up_for_sso_accounts_needs_a_recent_sign_in(db, box):  # noqa: F811
    ha.heartbeat(box)
    sso = await _user(db, "admin", password=None)
    async with _client(db, sso) as c:
        r = await c.post(f"{API}/step-up", json={})
        assert r.status_code == 403 and "Sign out and back in" in r.json()["detail"]


@pytest.mark.asyncio
async def test_upload_checks_the_file_and_names_it_itself(admin, box):  # noqa: F811
    r = await admin.post(f"{API}/uploads", content=b"PK\x03\x04 a zip, not a backup" * 10)
    assert r.status_code == 400 and os.listdir(box.uploads) == [] and os.listdir(box.tmp) == []
    r = await admin.post(f"{API}/uploads", content=ba.MAGIC + b"\0" * 100, headers={"X-Filename": "../../evil.ctembak"})
    assert r.status_code == 200
    name = r.json()["name"]
    assert agent_link.UPLOAD_RE.match(name) and os.listdir(box.uploads) == [name]
    assert (await admin.delete(f"{API}/uploads/{name}")).status_code == 200 and os.listdir(box.uploads) == []


@pytest.mark.asyncio
async def test_check_and_restore(admin, box):  # noqa: F811
    name = _real_backup(box)
    body = {"source": "backups", "name": name, "password": BACKUP_PW}
    assert (await admin.post(f"{API}/restore/check", json=body)).status_code == 403   # step-up first
    await _step_up(admin)
    wrong = await admin.post(f"{API}/restore/check", json={**body, "password": "Not-The-Right-Pass-1"})
    assert wrong.status_code == 400
    m = (await admin.post(f"{API}/restore/check", json=body)).json()
    assert m["manifest"]["host"] == "server001" and m["same_commit"] is False
    assert (await admin.post(f"{API}/restore/check", json={**body, "source": "/etc"})).status_code == 404
    assert (await admin.post(f"{API}/restore", json=body)).status_code == 400   # no RESTORE typed
    r = await admin.post(f"{API}/restore", json={**body, "confirm": "RESTORE"})
    assert r.status_code == 200
    raw = open(os.path.join(box.inbox, f"{r.json()['job']}.json")).read()
    assert BACKUP_PW not in raw


@pytest.mark.asyncio
async def test_restore_switched_off(admin, box, monkeypatch):  # noqa: F811
    from api.core.config import get_settings
    name = _real_backup(box)
    await _step_up(admin)
    monkeypatch.setattr(get_settings(), "maintenance_ui_restore", False)
    r = await admin.post(f"{API}/restore", json={"source": "backups", "name": name, "password": BACKUP_PW, "confirm": "RESTORE"})
    assert r.status_code == 403 and "turned off" in r.json()["detail"]


@pytest.mark.asyncio
async def test_schedule_and_delete(admin, box):  # noqa: F811
    name = _real_backup(box)
    await _step_up(admin)
    for bad in ({"enabled": True, "hour": 24, "keep": 7}, {"enabled": "yes", "hour": 2, "keep": 7},
                {"enabled": True, "hour": 2, "keep": 0}):
        assert (await admin.put(f"{API}/schedule", json=bad)).status_code == 400
    assert (await admin.put(f"{API}/schedule", json={"enabled": True, "hour": 23, "keep": 5})).status_code == 200
    assert (await admin.delete(f"{API}/backups/{name}")).status_code == 200
    ha.run(box)
    d = (await admin.get(API)).json()
    assert d["schedule"] == {**d["schedule"], "enabled": True, "hour": 23, "keep": 5}
    assert all(b["name"] != name for b in d["backups"])
