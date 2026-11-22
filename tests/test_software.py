"""Software inventory: normalized titles, ingest from the shipper, review decisions, scope, the asset view."""
from __future__ import annotations

import uuid

import pytest

from api.core.software_norm import normalize


@pytest.mark.parametrize("vendor,product,family,title", [
    ("Mozilla", "Mozilla Firefox (x64 en-US)", None, "Mozilla Firefox"),
    ("Mozilla", "Firefox ESR 115.2", None, "Mozilla Firefox"),
    ("Google LLC", "Chrome", "Chrome", "Google Chrome"),
    ("Microsoft Corporation", "Microsoft Office Professional Plus 2016", None, "Microsoft Office"),
    ("Microsoft", "Office 2019", "Office", "Microsoft Office"),
    ("Oracle Corporation", "Java 8 Update 381", None, "Oracle Java"),
    ("Notepad++ Team", "Notepad++ (64-bit x64)", None, "Notepad++"),
    ("7-Zip", "7-Zip 23.01 (x64)", None, "7-Zip"),
    ("Microsoft", "Microsoft 365 Apps for enterprise - en-us", None, "Microsoft 365 Apps for enterprise"),
])
def test_one_title_per_product(vendor, product, family, title):
    assert normalize(vendor, product, family)["title"] == title


def test_os_and_system_components_are_classed_as_system():
    for v, p in (("Microsoft", "Windows 10 Enterprise"), ("Microsoft Corporation", "Microsoft Visual C++ 2015-2022 Redistributable (x64)"),
                 ("Microsoft", "Security Update for Microsoft Office 2016 (KB5002)"), ("Red Hat", "openssl-libs"),
                 ("Microsoft", "Microsoft .NET Runtime - 8.0.1")):
        assert normalize(v, p)["system"], p
    assert not normalize("Google LLC", "Google Chrome")["system"]
    assert normalize("Acme", "Thing", cpe="cpe:/o:acme:os:1")["system"]
    assert normalize("", "") is None


async def _ingest(db, n):
    from api.collector.ingest import apply_batch
    from api.collector.schemas import Rapid7Batch
    from api.models.device import Device, DeviceType
    a, b = Device(hostname=f"ws-{n}", device_type=DeviceType.workstation), Device(hostname=f"srv-{n}", device_type=DeviceType.server)
    db.add_all([a, b])
    await db.commit()
    batch = Rapid7Batch.model_validate({"kind": "rapid7_console", "run_id": str(uuid.uuid4()), "software": [
        {"vendor": "Google LLC", "product": f"Chrome{n}", "family": f"Chrome{n}", "version": "120.0", "hosts": [f"ws-{n}", f"srv-{n}"]},
        {"vendor": "Google LLC", "product": f"Chrome{n}", "family": f"Chrome{n}", "version": "121.0", "hosts": [f"ws-{n}"]},
        {"vendor": "Microsoft", "product": "Windows 11 Pro", "version": "23H2", "hosts": [f"ws-{n}"]},
        {"vendor": "Acme", "product": f"Tool{n}", "version": "1.0", "hosts": [f"unknown-{n}"]}]})
    assert await apply_batch(db, batch) >= 3
    return a, b


@pytest.mark.asyncio
async def test_inventory_titles_versions_assets_and_decisions(db, client_admin, client_it_user):
    n = uuid.uuid4().hex[:6]
    a, b = await _ingest(db, n)
    d = (await client_admin.get("/api/v1/software", params={"q": f"chrome{n}"})).json()
    assert len(d["titles"]) == 1
    t = d["titles"][0]
    assert t["title"] == f"Google Chrome{n}" and t["versions"] == 2 and t["assets"] == 2 and t["status"] == "unreviewed"
    win = (await client_admin.get("/api/v1/software", params={"q": "windows"})).json()["titles"]
    assert not any(x["title"].startswith("Microsoft Windows") for x in win)              # system hidden by default
    assert any(x["title"].startswith("Microsoft Windows") for x in
               (await client_admin.get("/api/v1/software", params={"q": "windows", "include_system": True})).json()["titles"])
    one = (await client_admin.get(f"/api/v1/software/{t['id']}")).json()
    assert [v["version"] for v in one["versions"]] == ["121.0", "120.0"] and one["versions"][1]["assets"] == 2
    on = (await client_admin.get(f"/api/v1/software/{t['id']}/assets", params={"version": "121.0"})).json()
    assert on["total"] == 1 and on["assets"][0]["id"] == str(a.id)
    # decisions: admins and cyber only, audited
    assert (await client_it_user.put(f"/api/v1/software/{t['id']}/status", json={"status": "approved"})).status_code == 404
    r = (await client_admin.put(f"/api/v1/software/{t['id']}/status", json={"status": "unauthorized", "note": "Use the managed browser"})).json()
    assert r["ok"] and r["title"]["status"] == "unauthorized" and r["title"]["decided_by"]
    assert (await client_admin.put(f"/api/v1/software/{t['id']}/status", json={"status": "approved", "note": "<b>x</b>"})).status_code == 422
    listed = (await client_admin.get("/api/v1/software", params={"status": "unauthorized", "q": f"chrome{n}"})).json()
    assert len(listed["titles"]) == 1 and listed["counts"]["unauthorized"] >= 1
    mine = (await client_admin.get(f"/api/v1/software/device/{b.id}")).json()["software"]
    assert [s["title"] for s in mine] == [f"Google Chrome{n}"] and mine[0]["versions"] == ["120.0"] and mine[0]["status"] == "unauthorized"


@pytest.mark.asyncio
async def test_scoped_people_see_their_assets_software_only(db, client_it_user, it_user):
    from api.models.device import DeviceAssignment
    n = uuid.uuid4().hex[:6]
    a, b = await _ingest(db, n)
    db.add(DeviceAssignment(device_id=a.id, user_id=it_user.id))
    await db.commit()
    from api.core import user_access
    user_access.forget()
    d = (await client_it_user.get("/api/v1/software", params={"q": f"chrome{n}"})).json()
    assert d["scoped"] and d["titles"][0]["assets"] == 1 and d["can_decide"] is False
    tid = d["titles"][0]["id"]
    on = (await client_it_user.get(f"/api/v1/software/{tid}/assets")).json()
    assert {x["id"] for x in on["assets"]} == {str(a.id)} and on["total"] == 1   # both its versions; not the server they can't see
    assert (await client_it_user.get(f"/api/v1/software/device/{b.id}")).status_code == 404


@pytest.mark.asyncio
async def test_unauthorized_software_check():
    import contextlib
    import os
    import tempfile
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from api.grc.checks import REGISTRY, evaluate
    from api.models.base import Base
    from api.models.device import Device, DeviceType
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    from api.models.software import SoftwareInstall, SoftwareTitle
    from api.rules.doc import RuleDoc
    path = tempfile.mktemp(prefix="ctem_sw_", suffix=".db")
    eng = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    check = REGISTRY["ctem_unauthorized_software"]
    now = datetime.now(timezone.utc)
    try:
        async with async_sessionmaker(eng, expire_on_commit=False)() as db:
            cfg = IntegrationConfig(vendor=Vendor("rapid7_insightvm"), name="r7", is_enabled=True, config={})
            db.add(cfg)
            await db.flush()
            db.add(SyncJob(integration_id=str(cfg.id), vendor="rapid7_insightvm", status=SyncStatus.success, started_at=now, finished_at=now))
            await db.commit()
            assert (await evaluate(db, check, {}))[0]["result"] == "error"            # no inventory is never a pass
            ws, srv = Device(hostname="WS-01", device_type=DeviceType.workstation), Device(hostname="JUMP-01", device_type=DeviceType.server)
            bad = SoftwareTitle(key="acme|torrent", vendor="Acme", title="Acme Torrent", status="unauthorized", status_note="Not allowed")
            ok = SoftwareTitle(key="google|google chrome", vendor="Google", title="Google Chrome", status="approved")
            db.add_all([ws, srv, bad, ok])
            await db.flush()
            db.add_all([SoftwareInstall(title_id=bad.id, device_id=ws.id, version="2.1", source="r7", last_seen=now),
                        SoftwareInstall(title_id=bad.id, device_id=srv.id, version="2.0", source="r7", last_seen=now),
                        SoftwareInstall(title_id=ok.id, device_id=ws.id, version="120", source="r7", last_seen=now)])
            await db.commit()
            body, out = await evaluate(db, check, {}, detail=True)
            assert body["result"] == "fail" and body["details"]["assets_with_unauthorized"] == 2
            assert {(r["hostname"], r["software"], r["version"]) for r in out.rows} == {("WS-01", "Acme Torrent", "2.1"), ("JUMP-01", "Acme Torrent", "2.0")}
            assert out.rows[0]["why_unauthorized"] == "Not allowed"
            row = SimpleNamespace(id="r", name="Unauthorized software: not jump servers", version=1)
            doc = RuleDoc.model_validate({"schema": "open-ctem/curated-rule@1", "name": "Unauthorized software: not jump servers",
                                          "check": "ctem_unauthorized_software", "scope": {"exclude": {"hostname_patterns": ["JUMP-*"]}}})
            assert (await evaluate(db, check, {}, rules=[(row, doc)]))[0]["details"]["assets_with_unauthorized"] == 1
            from api.models.software import SoftwareException
            db.add(SoftwareException(title_id=bad.id, device_id=ws.id, decision="allowed", reason="Lab use", decided_by="admin"))
            await db.commit()
            body = (await evaluate(db, check, {}))[0]
            assert body["details"]["assets_with_unauthorized"] == 1 and body["details"]["allowed_by_exception"] == 1
            db.add(SoftwareException(title_id=ok.id, device_id=ws.id, decision="denied", reason="Not on this kiosk", decided_by="admin"))
            bad.status = "approved"
            await db.commit()
            body, out = await evaluate(db, check, {}, detail=True)
            assert body["details"]["assets_with_unauthorized"] == 1 and out.rows[0]["software"] == "Google Chrome"
            assert "exception" in out.rows[0]["why_unauthorized"]
            await db.execute(SoftwareException.__table__.delete())
            await db.commit()
            assert (await evaluate(db, check, {}))[0]["result"] == "pass"
    finally:
        await eng.dispose()
        with contextlib.suppress(OSError):
            os.unlink(path)


@pytest.mark.asyncio
async def test_per_asset_exceptions_and_file_details(db, client_admin, client_it_user):
    from datetime import date, datetime, timedelta, timezone

    from pydantic import ValidationError

    from api.collector.ingest import apply_batch
    from api.collector.schemas import Rapid7Batch
    from api.models.software import SoftwareException
    n = uuid.uuid4().hex[:6]
    a, b = await _ingest(db, n)
    sha = "ab" * 32
    batch = Rapid7Batch.model_validate({"kind": "rapid7_console", "run_id": str(uuid.uuid4()), "software": [
        {"vendor": "Acme", "product": f"Torrent{n}", "version": "2.0", "publisher": "Acme Software Ltd",
         "install_path": "C:\\\\Program Files\\\\Acme\\\\torrent.exe", "sha256": sha.upper(), "md5": "cd" * 16, "hosts": [f"ws-{n}", f"srv-{n}"]}]})
    await apply_batch(db, batch)
    with pytest.raises(ValidationError):
        Rapid7Batch.model_validate({"kind": "rapid7_console", "run_id": str(uuid.uuid4()),
                                    "software": [{"vendor": "Acme", "product": "x", "sha256": "not-a-hash", "hosts": ["h"]}]})
    tid = (await client_admin.get("/api/v1/software", params={"q": f"torrent{n}"})).json()["titles"][0]["id"]
    await client_admin.put(f"/api/v1/software/{tid}/status", json={"status": "unauthorized"})
    on_a = (await client_admin.get(f"/api/v1/software/device/{a.id}")).json()
    row = next(s for s in on_a["software"] if s["id"] == tid)
    assert row["status_here"] == "unauthorized" and on_a["can_decide"]
    assert row["files"][0]["publisher"] == "Acme Software Ltd" and row["files"][0]["sha256"] == sha and row["files"][0]["md5"] == "cd" * 16
    # allowed on the workstation only
    url = f"/api/v1/software/{tid}/exceptions/{a.id}"
    assert (await client_it_user.put(url, json={"decision": "allowed", "reason": "Needed for the lab"})).status_code == 404
    assert (await client_admin.put(url, json={"decision": "allowed", "reason": "no"})).status_code == 422
    far = (date.today() + timedelta(days=1000)).isoformat()
    assert (await client_admin.put(url, json={"decision": "allowed", "reason": "Needed for the lab", "expires_on": far})).status_code == 422
    assert (await client_admin.put(url, json={"decision": "allowed", "reason": "Needed for the lab"})).json()["ok"]
    here = next(s for s in (await client_admin.get(f"/api/v1/software/device/{a.id}")).json()["software"] if s["id"] == tid)
    there = next(s for s in (await client_admin.get(f"/api/v1/software/device/{b.id}")).json()["software"] if s["id"] == tid)
    assert here["status_here"] == "approved" and here["exception"]["decision"] == "allowed" and there["status_here"] == "unauthorized"
    listed = (await client_admin.get(f"/api/v1/software/{tid}/assets")).json()["assets"]
    assert {x["id"]: x["status_here"] for x in listed} == {str(a.id): "approved", str(b.id): "unauthorized"}
    # not allowed on the server although Chrome is approved
    chrome = (await client_admin.get("/api/v1/software", params={"q": f"chrome{n}"})).json()["titles"][0]["id"]
    await client_admin.put(f"/api/v1/software/{chrome}/status", json={"status": "approved"})
    assert (await client_admin.put(f"/api/v1/software/{chrome}/exceptions/{b.id}", json={"decision": "denied", "reason": "No browsers on servers"})).json()["ok"]
    srv = {s["id"]: s["status_here"] for s in (await client_admin.get(f"/api/v1/software/device/{b.id}")).json()["software"]}
    assert srv[chrome] == "unauthorized" and srv[tid] == "unauthorized"
    # an expired exception stops counting; removing one restores the title's status
    e = (await db.execute(__import__("sqlalchemy").select(SoftwareException).where(SoftwareException.device_id == a.id))).scalar_one()
    e.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
    await db.commit()
    assert next(s for s in (await client_admin.get(f"/api/v1/software/device/{a.id}")).json()["software"] if s["id"] == tid)["status_here"] == "unauthorized"
    assert (await client_admin.delete(f"/api/v1/software/{chrome}/exceptions/{b.id}")).json()["ok"]
    assert (await client_admin.delete(f"/api/v1/software/{chrome}/exceptions/{b.id}")).status_code == 404


def test_names_from_real_inventories():
    from api.core.software_norm import normalize as n
    assert n("JetBrains s.r.o.", "PyCharm Community")["title"] == "JetBrains PyCharm"
    assert n("Hewlett-Packard", "HP Smart")["vendor"] == "HP" and n("HP Inc.", "HP Smart")["key"] == n("Hewlett-Packard", "HP Smart")["key"]
    assert n("AcmeSoftware\\Acme-Browser", "Acme OnlineExpress") == {"key": "|acme onlineexpress", "vendor": "",
                                                                    "title": "Acme OnlineExpress", "system": False}
    assert n("Shenzhen Acmecam Technology Co., Ltd.", "Acmecam")["title"] == "Acmecam"
    assert n("BeyondTrust", "Remote Support Jump Client remotesupport.acme.example.com")["title"] == "BeyondTrust Remote Support Jump Client"
    assert n("The Document Foundation", "LibreOffice 24.2")["title"] == "LibreOffice"
    assert n("Node.js Foundation", "Node.js")["title"] == "Node.js"


@pytest.mark.asyncio
async def test_renormalize_regroups_and_a_software_run_mirrors_the_source(db):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select

    from api.core.software_ingest import prune_run
    from api.maintenance.renormalize_software import run
    from api.models.device import Device, DeviceType
    from api.models.software import SoftwareInstall, SoftwareTitle
    n = uuid.uuid4().hex[:6]
    d = Device(hostname=f"ws-rn-{n}", device_type=DeviceType.workstation)
    old = SoftwareTitle(key=f"jetbrains s.r.o|jetbrains s.r.o pycharm{n}", vendor="JetBrains s.r.o", title=f"JetBrains s.r.o PyCharm{n}")
    db.add_all([d, old])
    await db.flush()
    db.add(SoftwareInstall(title_id=old.id, device_id=d.id, version="2024.1", source="t_rn", product=f"PyCharm{n} Community",
                           last_seen=datetime.now(timezone.utc)))
    await db.commit()
    out = await run(db)
    assert out["installs_moved"] >= 1
    t = (await db.execute(select(SoftwareTitle).where(SoftwareTitle.key == f"jetbrains|jetbrains pycharm{n}"))).scalar_one()
    assert (await db.execute(select(SoftwareInstall).where(SoftwareInstall.title_id == t.id))).scalar_one().version == "2024.1"
    assert (await db.execute(select(SoftwareTitle).where(SoftwareTitle.key == old.key))).scalar_one_or_none() is None

    start = datetime.now(timezone.utc)
    stale = SoftwareInstall(title_id=t.id, device_id=d.id, version="2023.1", source="t_rn", last_seen=start - timedelta(hours=1))
    db.add(stale)
    await db.commit()
    assert await prune_run(db, "t_rn", start) == 0        # this run sent no software: nothing touched
    (await db.execute(select(SoftwareInstall).where(SoftwareInstall.version == "2024.1", SoftwareInstall.source == "t_rn"))
     ).scalar_one().last_seen = datetime.now(timezone.utc)
    await db.commit()
    assert await prune_run(db, "t_rn", start) == 1        # it did: what it no longer reports goes


@pytest.mark.asyncio
async def test_regroup_runs_once_per_rules_version_and_waits_for_runs(db, monkeypatch):
    from datetime import datetime, timezone

    from sqlalchemy import delete, select

    from api.core import software_norm
    from api.maintenance import renormalize_software as rn
    from api.models.integration import SyncJob, SyncStatus
    from api.models.settings import AppSetting
    calls = []

    async def fake(db):
        calls.append(1)
        return {"installs_moved": 0, "titles_removed": 0}
    monkeypatch.setattr(rn, "run", fake)
    from sqlalchemy import update

    from api.models.integration import IntegrationConfig, Vendor
    await db.execute(delete(AppSetting).where(AppSetting.key == rn.VERSION_KEY))
    # runs other tests left open would hold the regroup back too; close them so this test sees only its own
    await db.execute(update(SyncJob).where(SyncJob.status == SyncStatus.running).values(status=SyncStatus.failed))
    cfg = IntegrationConfig(vendor=Vendor.rapid7_insightvm, name="ACME console rn", is_enabled=True, config={})
    db.add(cfg)
    await db.flush()
    job = SyncJob(integration_id=cfg.id, vendor="rapid7_insightvm", status=SyncStatus.running,
                  started_at=datetime.now(timezone.utc), records_imported=0)
    db.add(job)
    await db.commit()
    assert await rn.if_rules_changed(db) is None and not calls          # a run is going: wait
    job.status = SyncStatus.success
    await db.commit()
    assert await rn.if_rules_changed(db) is not None and len(calls) == 1
    assert await rn.if_rules_changed(db) is None and len(calls) == 1    # once per version
    monkeypatch.setattr(software_norm, "RULES_VERSION", software_norm.RULES_VERSION + 1)
    assert await rn.if_rules_changed(db) is not None and len(calls) == 2
    row = (await db.execute(select(AppSetting).where(AppSetting.key == rn.VERSION_KEY))).scalar_one()
    assert row.value == str(software_norm.RULES_VERSION)
