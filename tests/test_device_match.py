"""One device per host: name matching, CrowdStrike user, and the duplicate merge."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from api.core.device_match import find_device, find_devices, host_key


def _tag() -> str:
    return f"t{uuid.uuid4().hex[:8]}"


def test_host_key_normalizes_every_spelling():
    assert host_key("DESKTOP001") == "desktop001"
    assert host_key("desktop001.ad.acme.example") == "desktop001"
    assert host_key("DESKTOP001$") == "desktop001"
    assert host_key(" Server001.ACME.example. ") == "server001"
    assert host_key("192.0.2.10") == "192.0.2.10"
    assert host_key("") is None and host_key(None) is None


@pytest.mark.asyncio
async def test_find_device_matches_short_and_fqdn_but_not_other_domains(db):
    from api.models.device import Device, DeviceType

    n = _tag()
    short = Device(hostname=n.upper(), device_type=DeviceType.workstation, source="crowdstrike")
    corp = Device(hostname=f"{n}-srv.corp.acme.example", device_type=DeviceType.server, source="rapid7_insightvm")
    db.add_all([short, corp])
    await db.flush()
    assert short.host_key == n
    assert (await find_device(db, f"{n}.ad.acme.example")).id == short.id
    assert (await find_device(db, n.upper())).id == short.id
    assert await find_device(db, f"{n}-srv.dmz.acme.example") is None  # same name, other domain
    assert (await find_device(db, f"{n.upper()}-SRV")).id == corp.id
    found = await find_devices(db, [(f"{n}-SRV", f"{n}-srv.corp.acme.example"), f"{n}.ad.acme.example", "nothing-here"])
    assert found[f"{n}-SRV"].id == corp.id and found[f"{n}.ad.acme.example"].id == short.id
    assert "nothing-here" not in found


@pytest.mark.asyncio
async def test_apps_never_match_hosts_by_name(db):
    from api.models.device import Device, DeviceType

    n = _tag()
    db.add(Device(hostname=n, device_type=DeviceType.server, source="rapid7_appsec", source_id=n))
    await db.flush()
    assert await find_device(db, n.upper()) is None


@pytest.mark.asyncio
async def test_crowdstrike_fills_edr_and_user_on_the_rapid7_row(db):
    from api.core.encryption import search_hash
    from api.integrations.crowdstrike import CrowdStrikeConnector
    from api.models.device import Device, DeviceType

    n = _tag()
    r7 = Device(hostname=f"{n}.ad.acme.example", device_type=DeviceType.workstation, source="rapid7_insightvm")
    db.add(r7)
    await db.commit()
    await CrowdStrikeConnector({})._upsert([
        {"hostname": n.upper(), "status": "contained", "os_version": "Windows 11", "last_login_user": "ACME\\jdoe"},
        {"hostname": f"{n}b", "status": "normal", "last_login_user": "bad\x07user"},
    ], [], db)
    rows = list((await db.execute(select(Device).where(Device.host_key.in_([n, f"{n}b"])))).scalars())
    assert len(rows) == 2
    got = next(d for d in rows if d.id == r7.id)
    assert got.edr_vendor == "crowdstrike" and got.edr_active is True
    assert got.last_login_user == "ACME\\jdoe" and got.last_login_user_hash == search_hash("jdoe")
    assert next(d for d in rows if d.id != r7.id).last_login_user is None


def test_shipped_last_login_user_is_validated():
    from pydantic import ValidationError

    from api.collector.schemas import CsDevice

    assert CsDevice(hostname="desktop001", last_login_user="jdoe").last_login_user == "jdoe"
    with pytest.raises(ValidationError):
        CsDevice(hostname="desktop001", last_login_user="j\ndoe")


@pytest.mark.asyncio
async def test_merge_moves_findings_tags_and_paths_and_skips_cross_domain(db):
    from api.maintenance.merge_devices import _merge_one, plan
    from api.models.device import Device, DeviceTag, DeviceType
    from api.models.risk import AttackPath
    from api.models.tag import Tag
    from api.models.vuln import Finding, Vulnerability

    n = _tag()
    r7 = Device(hostname=f"{n}.ad.acme.example", device_type=DeviceType.workstation, source="rapid7_insightvm")
    cs = Device(hostname=n.upper(), device_type=DeviceType.workstation, source="crowdstrike",
                edr_vendor="crowdstrike", edr_active=True, last_login_user="jdoe")
    a = Device(hostname=f"{n}x.corp.acme.example", device_type=DeviceType.server, source="rapid7_insightvm")
    b = Device(hostname=f"{n}x.dmz.acme.example", device_type=DeviceType.server, source="qualys")
    vuln = Vulnerability(title="test", source="rapid7_insightvm")
    tag = Tag(name=f"env:{n}", source="manual")
    db.add_all([r7, cs, a, b, vuln, tag])
    await db.flush()
    db.add_all([Finding(device_id=r7.id, vuln_id=vuln.id, source="rapid7_insightvm"),
                DeviceTag(device_id=cs.id, tag_id=tag.id),
                AttackPath(source_device_id=cs.id, target_device_id=a.id, path_score=1.0)])
    await db.commit()

    merges, skipped = plan([r7, cs, a, b], {r7.id: 1})
    assert [(k.id, [d.id for d in l]) for k, l in merges] == [(r7.id, [cs.id])]
    assert skipped and skipped[0][0] == f"{n}x"
    cs_id = cs.id
    await _merge_one(db, r7, cs)
    await db.commit()

    assert await db.get(Device, cs_id) is None
    kept = await db.get(Device, r7.id)
    assert kept.edr_active and kept.edr_vendor == "crowdstrike" and kept.last_login_user == "jdoe"
    assert (await db.execute(select(DeviceTag).where(DeviceTag.device_id == r7.id))).scalar_one().tag_id == tag.id
    path = (await db.execute(select(AttackPath).where(AttackPath.target_device_id == a.id))).scalar_one()
    assert path.source_device_id == r7.id
    assert (await db.execute(select(Finding).where(Finding.device_id == r7.id))).scalar_one()


def _dev(name, fqdn=None, ad=False, source="rapid7_insightvm", age=0):
    import datetime as dt
    from types import SimpleNamespace
    return SimpleNamespace(id=uuid.uuid4().hex, hostname=name, fqdn=fqdn, ad_joined=ad, source=source,
                           created_at=dt.datetime(2026, 1, 1) + dt.timedelta(minutes=age))


def test_parent_and_child_domains_are_one_host():
    from api.core.device_match import same_domain
    from api.maintenance.merge_devices import plan

    assert same_domain("ad.acme.example", "acme.example") and same_domain(None, "acme.example")
    assert not same_domain("ec2.internal", "us-west-2.compute.internal")
    cs = _dev("server001", source="crowdstrike")
    ad = _dev("SERVER001", fqdn="server001.acme.example", ad=True, source="ldap", age=1)
    r7 = _dev("server001.ad.acme.example", age=2)
    merges, skipped = plan([cs, ad, r7], {r7.id: 3})
    assert len(merges) == 1 and merges[0][0] is r7 and {d.id for d in merges[0][1]} == {cs.id, ad.id}
    assert not skipped


def test_short_name_joins_the_main_domain_and_other_domains_stay_apart():
    from api.maintenance.merge_devices import plan

    fleet = [_dev(f"desktop{i:03d}.ad.acme.example") for i in range(3)]  # makes ad.acme.example the main domain
    cs = _dev("evodevdb", source="crowdstrike")
    corp = _dev("evodevdb.ad.acme.example", age=1)
    cloud = _dev("evodevdb.db.acme.oraclevcn.example", age=2)
    a = _dev("ip-192-0-2-13.ec2.internal")
    b = _dev("ip-192-0-2-13.us-west-2.compute.internal")
    merges, skipped = plan(fleet + [cs, corp, cloud, a, b], {})
    assert [{k.id, *(d.id for d in l)} for k, l in merges] == [{corp.id, cs.id}]
    assert {k for k, _ in skipped} == {"evodevdb", "ip-192-0-2-13"}


@pytest.mark.asyncio
async def test_lookup_accepts_parent_domain_and_prefers_ad_joined(db):
    from api.models.device import Device, DeviceType

    n = _tag()
    old = Device(hostname=f"{n}.cloud.acme.example", device_type=DeviceType.server, source="rapid7_insightvm")
    db.add(old)
    await db.flush()
    joined = Device(hostname=n.upper(), fqdn=f"{n}.acme.example", device_type=DeviceType.server,
                    source="ldap", ad_joined=True)
    db.add(joined)
    await db.flush()
    assert (await find_device(db, f"{n}.ad.acme.example")).id == joined.id
    assert (await find_device(db, n)).id == joined.id


@pytest.mark.asyncio
async def test_crowdstrike_policy_flags_and_server_type_are_stored(db):
    from api.integrations.crowdstrike import CrowdStrikeConnector
    from api.models.device import Device, DeviceType

    n = _tag()
    await CrowdStrikeConnector({})._upsert([{"hostname": n.upper(), "status": "normal", "product_type": "Domain Controller",
                                             "firewall_enabled": True, "usb_storage_blocked": False}], [], db)
    dev = (await db.execute(select(Device).where(Device.host_key == n))).scalar_one()
    assert dev.device_type == DeviceType.server and dev.firewall_enabled is True and dev.usb_storage_blocked is False
    assert dev.sources == ",crowdstrike,"


@pytest.mark.asyncio
async def test_ad_account_health_is_stored_and_not_blanked_by_older_shippers(db):
    import datetime as dt

    from api.integrations.ldap_ingest import upsert_directory
    from api.models.user import User

    name = _tag()
    when = dt.datetime(2026, 1, 2, tzinfo=dt.timezone.utc)
    await upsert_directory([{"username": name, "disabled": False, "last_logon": when, "pwd_last_set": when,
                             "pwd_expired": True, "pwd_never_expires": False, "locked_out": True}], [], db)
    await upsert_directory([{"username": name, "disabled": True}], [], db)  # an old shipper's payload
    u = (await db.execute(select(User).where(User.username == name))).scalar_one()
    assert u.ad_disabled is True and u.ad_pwd_expired is True and u.ad_locked_out is True
    assert u.ad_last_logon.year == 2026


def test_ad_hygiene_raises_user_risk():
    from api.scoring.user_score import compute_user_score

    base = dict(device_scores=[], ad_groups=[], mfa_enabled=True, is_service_account=False, last_login_days_ago=0)
    clean, _, _ = compute_user_score(**base, ad={"days_since_logon": 2, "pwd_age_days": 30})
    risky, _, why = compute_user_score(**base, ad={"days_since_logon": 200, "pwd_age_days": 500,
                                                   "pwd_never_expires": True, "locked_out": True})
    off, _, _ = compute_user_score(**base, ad={"disabled": True, "days_since_logon": 200, "pwd_never_expires": True})
    assert risky > clean and off <= clean
    assert {"ad_dormant_account_penalty", "ad_old_password_penalty", "ad_pwd_never_expires_penalty"} <= set(why)


@pytest.mark.asyncio
async def test_contained_host_scores_zero_and_findings_show_as_info(db, client_admin):
    from api.integrations.crowdstrike import CrowdStrikeConnector
    from api.models.device import Device
    from api.models.vuln import Finding, Vulnerability
    from api.scoring.engine import recalculate_device

    n = _tag()
    await CrowdStrikeConnector({})._upsert([{"hostname": n.upper(), "status": "contained"}], [], db)
    dev = (await db.execute(select(Device).where(Device.host_key == n))).scalar_one()
    vuln = Vulnerability(title="bad", source="rapid7_insightvm", cvss_base=9.8, is_kev=True)
    db.add(vuln)
    await db.flush()
    db.add(Finding(device_id=dev.id, vuln_id=vuln.id, source="rapid7_insightvm"))
    await db.commit()
    await recalculate_device(dev, db)
    assert dev.edr_contained is True and dev.risk_score == 0.0
    body = (await client_admin.get(f"/api/v1/devices/{dev.id}/findings")).json()
    assert body["contained"] is True
    assert [(f["severity"], f["composite_score"]) for f in body["findings"]] == [("info", 0.0)]
    f = body["findings"][0]
    assert f["raw_score"] > 0 and f["raw_grade"] and f["risk_grade"] == "A"  # original kept beside the adjusted one
    assert dev.raw_risk_score > 0 and dev.risk_grade == "A"

    # Released from containment: the real risk comes straight back
    await CrowdStrikeConnector({})._upsert([{"hostname": n.upper(), "status": "normal"}], [], db)
    await recalculate_device(dev, db)
    assert dev.edr_contained is False and dev.risk_score > 0


def test_rapid7_tag_mapping():
    from api.core.device_tags import r7_tags

    names, crit = r7_tags([{"type": "CUSTOM", "name": "Production"}, {"type": "location", "name": "Dallas  DC"},
                           {"type": "OWNER", "name": "IT Ops"}, {"type": "criticality", "name": "Very High"},
                           {"type": "weird", "name": "x"}, {"type": "custom", "name": "bad\x07\nname"}, "nope"])
    assert crit == "Very High"
    assert names == {"r7:production", "location:Dallas DC", "owner:IT Ops", "criticality:very high", "r7:badname"}


@pytest.mark.asyncio
async def test_console_tags_sync_criticality_and_cmdb_fields(db, client_cyber):
    from api.integrations.rapid7_insightvm import InsightVMConnector
    from api.models.device import Device

    n = _tag()
    conn = InsightVMConnector({})
    tags = [{"type": "custom", "name": "Production"}, {"type": "location", "name": "Dallas"},
            {"type": "owner", "name": "IT Ops"}, {"type": "criticality", "name": "High"}]
    await conn._console_upsert_assets([{"hostName": f"{n}.ad.acme.example", "tags": tags}], db)
    rec = next(r for r in (await client_cyber.get("/api/v1/cmdb", params={"q": n})).json()["records"])
    assert (rec["environment"], rec["location"], rec["owner"], rec["criticality"]) == ("Production", "Dallas", "IT Ops", "High")

    # Tag removed in Rapid7 -> gone here; a tag from elsewhere stays; an older shipper (no tags key) changes nothing
    from api.core.device_tags import sync_tags
    dev = (await db.execute(select(Device).where(Device.host_key == n))).scalar_one()
    await sync_tags(db, dev.id, {"edr:manual"}, ("edr:",), "manual", {})
    await conn._console_upsert_assets([{"hostName": f"{n}.ad.acme.example", "tags": [{"type": "location", "name": "Austin"}]}], db)
    await conn._console_upsert_assets([{"hostName": f"{n}.ad.acme.example"}], db)
    rec = next(r for r in (await client_cyber.get("/api/v1/cmdb", params={"q": n})).json()["records"])
    assert (rec["location"], rec["criticality"], rec["environment"]) == ("Austin", None, None)
    names = (await client_cyber.get(f"/api/v1/devices/{dev.id}")).json()["tags"]
    assert sorted(names) == ["edr:manual", "location:Austin"]


def test_scanner_criticality_weights_risk():
    from api.scoring.engine import _CRITICALITY
    assert _CRITICALITY["Very High"] > _CRITICALITY["Medium"] > _CRITICALITY["Very Low"]


def test_phone_numbers_normalize_to_e164():
    from api.core.phone import normalize

    assert normalize("(201) 555-0123") == "+12015550123"
    assert normalize("201.555.0123 x45") == "+12015550123;ext=45"
    assert normalize("+44 20 7946 0958") == "+442079460958"
    assert normalize("0044 20 7946 0958") == "+442079460958"
    assert normalize("020 7946 0958", country="GB") == "+442079460958"
    assert normalize("030 901820", country="de") == "+4930901820"
    assert normalize("1234") is None and normalize("call me") is None and normalize(None) is None


@pytest.mark.asyncio
async def test_directory_profile_fields_are_stored(db, client_admin):
    from api.integrations.ldap_ingest import upsert_directory

    name = _tag()
    await upsert_directory([{"username": name, "first_name": "Jane", "last_name": "Doe", "title": "Analyst",
                             "phone": "(201) 555-0123", "mobile": "ext 4", "country": "US"}], [], db)
    users = (await client_admin.get("/api/v1/directory/users", params={"q": name})).json()["users"]
    u = next(x for x in users if x["username"] == name)
    assert (u["first_name"], u["last_name"], u["title"], u["phone"]) == ("Jane", "Doe", "Analyst", "+12015550123")
    assert u["mobile"] == "ext 4"  # not a number we can normalize, so it's kept as entered


def test_wsl_is_a_subsystem_not_the_host_os():
    from api.core.device_match import host_os, is_guest_os, type_from_os
    from api.models.device import DeviceType
    assert is_guest_os("WSL 2.0") and is_guest_os("Windows Subsystem for Linux") and not is_guest_os("Windows 11")
    assert host_os("Windows 11 Enterprise", "WSL 2.0") == "Windows 11 Enterprise"   # the EDR's answer stays
    assert host_os(None, "WSL 2.0") == "Windows" and host_os("WSL 2.0", "WSL 2.0") == "Windows"
    assert host_os("WSL 2.0", "Windows 11 Pro") == "Windows 11 Pro"
    assert host_os("Ubuntu 22.04", None) == "Ubuntu 22.04"
    assert type_from_os("Windows 11 Enterprise", DeviceType.server) == DeviceType.workstation
    assert type_from_os("Windows Server 2022", DeviceType.workstation) == DeviceType.server
    assert type_from_os("Ubuntu 22.04", DeviceType.server) == DeviceType.server
    assert type_from_os("macOS 15", DeviceType.unknown) == DeviceType.workstation
