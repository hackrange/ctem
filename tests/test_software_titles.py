"""Software titles across tools: one title whatever the vendor's spelling (or none, from Tanium), and a Linux
distribution's own packages classed as system components while vendors' packages stay third-party."""
from __future__ import annotations

import uuid

import pytest


@pytest.mark.asyncio
async def test_one_title_whatever_vendor_spelling_or_none(db):
    """The same product from a scanner (with its vendor, in any spelling) and an agent that sends no vendor (Tanium):
    one title. Stored titles regroup the same way, keeping the vendor and the strictest decision."""
    from datetime import datetime, timezone

    from sqlalchemy import delete, select

    from api.core.software_ingest import upsert
    from api.core.software_norm import normalize as nz
    from api.maintenance.renormalize_software import run
    from api.models.device import Device, DeviceType
    from api.models.software import SoftwareInstall, SoftwareTitle
    ver = "SolarWinds Client Components - x64 (2024.2.0.50539)"
    assert nz("SolarWinds Worldwide, LLC.", "SolarWinds Client Components")["key"] == nz("SolarWinds", ver)["key"] == nz(None, ver)["key"]
    assert nz(None, "Rapid7 InsightVM Scan Assistant v1.4.0.5")["key"] == nz("Rapid7", "Rapid7 InsightVM Scan Assistant")["key"]
    n = uuid.uuid4().hex[:6]
    d = Device(hostname=f"ws-sw-{n}", device_type=DeviceType.workstation)
    db.add(d)
    await db.commit()
    await upsert(db, [{"vendor": "Microsoft Corporation", "product": f"Teams{n} Machine-Wide Installer", "version": "1.7", "hosts": [d.hostname]}], "scan_x")
    await upsert(db, [{"product": f"Teams{n} Machine-Wide Installer", "version": "1.7", "hosts": [d.hostname]},
                      {"product": f"Zed{n} Tool 2.1", "version": "2.1", "hosts": [d.hostname]}], "agent_x")
    rows = (await db.execute(select(SoftwareTitle.title, SoftwareInstall.source).join(SoftwareInstall, SoftwareInstall.title_id == SoftwareTitle.id)
                             .where(SoftwareInstall.device_id == d.id))).all()
    assert sorted(rows) == [(f"Microsoft Teams{n} Machine-Wide Installer", "agent_x"), (f"Microsoft Teams{n} Machine-Wide Installer", "scan_x"),
                            (f"Zed{n} Tool", "agent_x")]
    # Titles stored under the old rules: a vendor-less one and a vendor spelling merge into the vendor's title
    now = datetime.now(timezone.utc)
    a = SoftwareTitle(key=f"acme{n}|acme{n} widget", vendor=f"Acme{n}", title=f"Acme{n} Widget", status="approved")
    b = SoftwareTitle(key=f"|widget{n}x", vendor="", title=f"Widget{n}x", status="unauthorized")
    c = SoftwareTitle(key=f"acme{n} worldwide|acme{n} widget", vendor=f"Acme{n} Worldwide", title=f"Acme{n} Widget")
    e = SoftwareTitle(key=f"acme{n}|acme{n} widget{n}x", vendor=f"Acme{n}", title=f"Acme{n} Widget{n}x")
    db.add_all([a, b, c, e])
    await db.flush()
    for t, src in ((a, "s1"), (b, "agent"), (c, "s2"), (e, "s1")):
        db.add(SoftwareInstall(title_id=t.id, device_id=d.id, version="1", source=src, last_seen=now))
    await db.commit()
    await run(db)
    got = {t: sorted(s for (s,) in (await db.execute(select(SoftwareInstall.source).join(SoftwareTitle, SoftwareTitle.id == SoftwareInstall.title_id)
                                                     .where(SoftwareTitle.title == t, SoftwareInstall.device_id == d.id))).all())
           for t in (f"Acme{n} Widget", f"Acme{n} Widget{n}x", f"Widget{n}x")}
    assert got == {f"Acme{n} Widget": ["s1", "s2"], f"Acme{n} Widget{n}x": ["agent", "s1"], f"Widget{n}x": []}
    led = (await db.execute(select(SoftwareTitle).where(SoftwareTitle.title == f"Acme{n} Widget{n}x"))).scalar_one()
    assert led.status == "unauthorized" and led.vendor == f"Acme{n}"
    await db.execute(delete(Device).where(Device.id == d.id))
    await db.execute(delete(SoftwareTitle).where(SoftwareTitle.title.like(f"%{n}%")))
    await db.commit()


@pytest.mark.parametrize("product,version,os_pkg", [
    ("NetworkManager", "1:1.40.16-15.el8_10", True), ("acl", "2.4.0-1.amzn2023.0.1", True), ("bash", "5.1-6ubuntu1", True),
    ("openssl", "3.0.11-1~deb12u2", True), ("libzypp", "17.31.15-150400.3.49.1", True), ("gpg-pubkey", "05707a62", True),
    ("falcon-sensor", "6.12.0-10913.el7", False), ("mysql-community-libs", "8.0.46-1.el7", False), ("TaniumClient", "7.6.4.2086-1.rhe9", False),
    ("CARKpsmp", "14.1.4-4", False), ("google-chrome-stable", "158.0.8127.36-1", False), ("qualys-cloud-agent", "3.1.0-45", False),
])
def test_a_distributions_own_packages_are_system(product, version, os_pkg):
    from api.core.software_norm import os_package
    assert os_package("Linux", product, version) is os_pkg
    assert os_package("Acme", product, version) is False   # only what a scanner reports as a Linux package


@pytest.mark.asyncio
async def test_linux_packages_are_classed_and_never_meet_a_windows_product(db):
    from sqlalchemy import delete, select

    from api.core.software_ingest import upsert
    from api.models.device import Device, DeviceType
    from api.models.software import SoftwareInstall, SoftwareTitle
    n = uuid.uuid4().hex[:6]
    lx, win = Device(hostname=f"lx-{n}", device_type=DeviceType.server), Device(hostname=f"win-{n}", device_type=DeviceType.workstation)
    db.add_all([lx, win])
    await db.commit()
    await upsert(db, [{"vendor": "Linux", "product": f"netman{n}", "version": "1.40.16-15.el8_10", "hosts": [lx.hostname]},
                      {"vendor": "Linux", "product": f"Agent{n}", "version": "2.1.1574", "hosts": [lx.hostname]}], "scan_x")
    await upsert(db, [{"vendor": "Linux", "product": f"netman{n}", "version": "1.40.16", "hosts": [lx.hostname]},   # Tanium, Linux host
                      {"product": f"Agent{n}", "version": "2.1.1574", "hosts": [win.hostname]}], "agent_x")         # Tanium, Windows host
    got = {(t.title, t.system): sorted(s for (s,) in (await db.execute(select(SoftwareInstall.source).where(SoftwareInstall.title_id == t.id))).all())
           for t in (await db.execute(select(SoftwareTitle).where(SoftwareTitle.title.like(f"%{n}%")))).scalars()}
    assert got == {(f"Linux netman{n}", True): ["agent_x", "scan_x"], (f"Linux Agent{n}", False): ["scan_x"], (f"Agent{n}", False): ["agent_x"]}
    await db.execute(delete(Device).where(Device.id.in_([lx.id, win.id])))
    await db.execute(delete(SoftwareTitle).where(SoftwareTitle.title.like(f"%{n}%")))
    await db.commit()
