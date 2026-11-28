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
    # The names a title was reported as come from this person's assets only, not the server they can't see
    from datetime import datetime, timezone

    from api.models.software import SoftwareInstall
    db.add(SoftwareInstall(title_id=tid, device_id=b.id, version="9.9", source="t_scope", product=f"Chrome{n} Secret Server Build",
                           last_seen=datetime.now(timezone.utc)))
    await db.commit()
    names = (await client_it_user.get(f"/api/v1/software/{tid}")).json()["reported_as"]
    assert f"Chrome{n}" in names and f"Chrome{n} Secret Server Build" not in names


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
    for pkg in ("Microsoft.AAD.BrokerPlugin", "MicrosoftWindows.Client.CBS", "Windows.PrintDialog", "MICROSOFT.UI.XAML.CBS"):
        assert n("Microsoft Corporation", pkg)["system"], pkg
    assert not n("Microsoft Corporation", "Microsoft Teams")["system"]
    assert n("JetBrains s.r.o.", "PyCharm Community")["title"] == "JetBrains PyCharm"
    assert n("Hewlett-Packard", "HP Smart")["vendor"] == "HP" and n("HP Inc.", "HP Smart")["key"] == n("Hewlett-Packard", "HP Smart")["key"]
    assert n("AcmeSoftware\\Acme-Browser", "Acme OnlineExpress") == {"key": "acme onlineexpress", "vendor": "",
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
                           vendor_raw="JetBrains s.r.o.", last_seen=datetime.now(timezone.utc)))
    legacy = SoftwareTitle(key=f"acme|acme widget{n}", vendor="Acme", title=f"Acme Widget{n}")
    pkg = SoftwareTitle(key=f"microsoft|microsoft.aad.brokerplugin{n}", vendor="Microsoft", title=f"Microsoft.AAD.BrokerPlugin{n}")
    db.add_all([legacy, pkg])
    await db.flush()
    db.add_all([SoftwareInstall(title_id=legacy.id, device_id=d.id, version="1", source="t_rn", product=f"Widget{n} Pro Edition",
                                last_seen=datetime.now(timezone.utc)),
                SoftwareInstall(title_id=pkg.id, device_id=d.id, version="1", source="t_rn", product=f"MICROSOFT.AAD.BROKERPLUGIN{n}",
                                vendor_raw="Microsoft Corporation", family="Windows", last_seen=datetime.now(timezone.utc))])
    await db.commit()
    out = await run(db)
    assert out["installs_moved"] >= 1
    t = (await db.execute(select(SoftwareTitle).where(SoftwareTitle.key == f"jetbrains pycharm{n}"))).scalar_one()
    assert (await db.execute(select(SoftwareInstall).where(SoftwareInstall.title_id == t.id))).scalar_one().version == "2024.1"
    assert (await db.execute(select(SoftwareTitle).where(SoftwareTitle.key == old.key))).scalar_one_or_none() is None
    await db.refresh(legacy)
    rows = (await db.execute(select(SoftwareInstall.title_id).where(SoftwareInstall.product == f"Widget{n} Pro Edition"))).scalars().all()
    assert rows == [legacy.id]                            # no reported names kept: left for its next upload
    win = (await db.execute(select(SoftwareTitle).join(SoftwareInstall, SoftwareInstall.title_id == SoftwareTitle.id)
                             .where(SoftwareInstall.product == f"MICROSOFT.AAD.BROKERPLUGIN{n}"))).scalar_one()
    assert win.system                                     # family "Windows" and a package name: a system component

    start = datetime.now(timezone.utc)
    stale = SoftwareInstall(title_id=t.id, device_id=d.id, version="2023.1", source="t_rn", last_seen=start - timedelta(hours=1))
    db.add(stale)
    await db.commit()
    assert await prune_run(db, "t_rn", start) is None     # this run sent no software: nothing touched
    (await db.execute(select(SoftwareInstall).where(SoftwareInstall.version == "2024.1", SoftwareInstall.source == "t_rn"))
     ).scalar_one().last_seen = datetime.now(timezone.utc)
    await db.commit()
    assert await prune_run(db, "t_rn", start) == 3        # it did: what it no longer reports goes (all but 2024.1)


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


@pytest.mark.asyncio
async def test_bulk_decisions_are_for_deciders_and_audited(db, client_admin, client_cyber, client_it_user):
    from sqlalchemy import func, select

    from api.models.settings import AuditLog
    from api.models.software import SoftwareTitle
    n = uuid.uuid4().hex[:6]
    ts = [SoftwareTitle(key=f"acme|acme bulk{i}{n}", vendor="Acme", title=f"Acme Bulk{i}{n}") for i in range(3)]
    db.add_all(ts)
    await db.flush()
    ids = [str(t.id) for t in ts]
    await db.commit()
    body = {"ids": ids[:2] + [str(uuid.uuid4())], "status": "unauthorized", "note": "not on the approved list"}
    assert (await client_it_user.put("/api/v1/software/bulk-status", json=body)).status_code in (403, 404)
    r = await client_cyber.put("/api/v1/software/bulk-status", json=body)
    assert r.status_code == 200 and r.json()["updated"] == 2 and r.json()["not_found"] == 1
    fresh = select(SoftwareTitle).where(SoftwareTitle.id.in_(ids)).execution_options(populate_existing=True)
    got = {t.id: t for t in (await db.execute(fresh)).scalars()}
    assert got[ids[0]].status == got[ids[1]].status == "unauthorized" and got[ids[2]].status == "unreviewed"
    assert got[ids[0]].status_note == "not on the approved list" and got[ids[0]].decided_by
    audits = (await db.execute(select(func.count()).select_from(AuditLog).where(
        AuditLog.action == "software.status", AuditLog.resource_id.in_(ids)))).scalar_one()
    assert audits == 2
    back = await client_admin.put("/api/v1/software/bulk-status", json={"ids": ids[:1], "status": "unreviewed"})
    assert back.json()["updated"] == 1
    t0 = {t.id: t for t in (await db.execute(fresh)).scalars()}[ids[0]]
    assert t0.status == "unreviewed" and t0.decided_by is None
    assert (await client_admin.put("/api/v1/software/bulk-status", json={"ids": [], "status": "approved"})).status_code == 422
    assert (await client_admin.put("/api/v1/software/bulk-status", json={"ids": ids, "status": "approved", "note": "<b>"})).status_code == 422


@pytest.mark.asyncio
async def test_bracketed_ids_merge_and_the_strictest_decision_stays(db):
    from sqlalchemy import select

    from api.core.software_norm import normalize as nz
    from api.maintenance.renormalize_software import run
    from api.models.device import Device, DeviceType
    from api.models.software import SoftwareInstall, SoftwareTitle
    assert nz("BeyondTrust", "Remote Support Jump Client 23.3.5 [remotesupport.acme.example] [673DECE6]")["title"] == \
        "BeyondTrust Remote Support Jump Client"
    assert nz("Acme", "Acme Tool [en-US]")["title"] == "Acme Tool [en-US]"      # an ordinary bracket stays
    n = uuid.uuid4().hex[:6]
    d = Device(hostname=f"ws-bt-{n}", device_type=DeviceType.workstation)
    a = SoftwareTitle(key=f"beyondtrust|beyondtrust jump{n} 23.3.5 [remotesupport.acme.example] [673dece6]", vendor="BeyondTrust",
                      title=f"BeyondTrust Jump{n} 23.3.5 [remotesupport.acme.example] [673DECE6]", status="unauthorized", decided_by="admin")
    b = SoftwareTitle(key=f"beyondtrust|beyondtrust jump{n} 23.3.5 [remotesupport.acme.example] [67603d12]", vendor="BeyondTrust",
                      title=f"BeyondTrust Jump{n} 23.3.5 [remotesupport.acme.example] [67603D12]", status="approved", decided_by="admin")
    db.add_all([d, a, b])
    await db.flush()
    from datetime import datetime, timezone
    for t in (a, b):
        db.add(SoftwareInstall(title_id=t.id, device_id=d.id, version="23.3.5", source=f"t_bt{t.id[:4]}", last_seen=datetime.now(timezone.utc)))
    await db.commit()
    out = await run(db)
    assert out["titles_renamed"] >= 2
    merged = (await db.execute(select(SoftwareTitle).where(SoftwareTitle.key == f"beyondtrust jump{n}"))).scalar_one()
    assert merged.status == "unauthorized"                                       # the stricter one wins
    assert len((await db.execute(select(SoftwareInstall).where(SoftwareInstall.title_id == merged.id))).scalars().all()) == 2


@pytest.mark.asyncio
async def test_bulk_approve_only_here_touches_this_asset_and_its_own_titles(db, client_admin, client_it_user):
    from sqlalchemy import select

    from api.models.device import Device, DeviceType
    from api.models.software import SoftwareException
    n = uuid.uuid4().hex[:6]
    a, b = await _ingest(db, n)
    titles = (await client_admin.get(f"/api/v1/software/device/{a.id}", params={"include_system": True})).json()["software"]
    ids = [s["id"] for s in titles]
    url = f"/api/v1/software/device/{a.id}/exceptions"
    body = {"ids": ids, "decision": "allowed", "reason": "Standard engineering tools"}
    assert (await client_it_user.put(url, json=body)).status_code == 404            # not a decider
    assert (await client_admin.put(f"/api/v1/software/device/{uuid.uuid4()}/exceptions", json=body)).status_code == 404
    assert (await client_admin.put(url, json={**body, "reason": "x"})).status_code == 422
    assert (await client_admin.put(url, json={**body, "ids": []})).status_code == 422
    assert (await client_admin.put(url, json={**body, "ids": [str(uuid.uuid4())] * 501})).status_code == 422
    # a title that isn't on this asset is skipped, not given an exception
    other = Device(hostname=f"lonely-{n}", device_type=DeviceType.workstation)
    db.add(other)
    await db.commit()
    r = (await client_admin.put(f"/api/v1/software/device/{other.id}/exceptions", json=body)).json()
    assert r["updated"] == 0 and r["not_found"] == len(ids)
    r = (await client_admin.put(url, json=body)).json()
    assert r["updated"] == len(ids)
    here = (await client_admin.get(f"/api/v1/software/device/{a.id}", params={"include_system": True})).json()["software"]
    assert {s["status_here"] for s in here} == {"approved"}
    there = (await client_admin.get(f"/api/v1/software/device/{b.id}")).json()["software"]
    assert {s["status_here"] for s in there} == {"unreviewed"}
    excs = (await db.execute(select(SoftwareException).where(SoftwareException.device_id.in_([b.id, other.id])))).scalars().all()
    assert not excs
    # approve everywhere: the titles' own status
    r = (await client_admin.put("/api/v1/software/bulk-status", json={"ids": ids, "status": "approved"})).json()
    assert r["updated"] == len(ids)
    there = (await client_admin.get(f"/api/v1/software/device/{b.id}")).json()["software"]
    assert {s["status_here"] for s in there} == {"approved"}
