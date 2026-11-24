"""Where things are: the shipper's AD office fields and Falcon's site and addresses, checked and stored (encrypted)."""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import select, text

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))

import collector_crowdstrike as cs  # noqa: E402
import collector_ldap as ldapmod  # noqa: E402


def test_shipper_sends_ad_office_fields():
    u = ldapmod._user({"dn": "CN=J Doe,DC=acme", "attributes": {
        "sAMAccountName": "jdoe", "l": "Springfield", "st": "IL", "physicalDeliveryOfficeName": "Branch 0412",
        "postalCode": "62701", "department": "Field Ops", "userAccountControl": 512}}, True)
    assert (u["city"], u["state"], u["office"], u["postal_code"], u["department"]) == ("Springfield", "IL", "Branch 0412", "62701", "Field Ops")
    assert ldapmod._user({"dn": "x", "attributes": {"sAMAccountName": "a", "l": "bad\x00city"}}, True)["city"] is None


def test_shipper_sends_falcon_site_and_addresses_only_when_well_formed():
    d = cs._device({"device_id": "a" * 32, "hostname": "desktop001", "site_name": "SPI-0412", "machine_domain": "ad.acme.example",
                    "external_ip": "203.0.113.7", "local_ip": "10.0.12.5", "mac_address": "AA-BB-CC-00-11-22",
                    "ou": ["Workstations", "Branches", 7]})
    assert d["site_name"] == "SPI-0412" and d["external_ip"] == "203.0.113.7" and d["local_ip"] == "10.0.12.5"
    assert d["mac"] == "aa:bb:cc:00:11:22" and d["ou"] == ["Workstations", "Branches"] and d["machine_domain"] == "ad.acme.example"
    bad = cs._device({"hostname": "desktop002", "external_ip": "198.51.100.999", "mac_address": "nope", "ou": "notalist"})
    assert bad["external_ip"] is None and bad["mac"] is None and bad["ou"] is None


def test_server_checks_the_new_fields():
    from api.collector.schemas import CsDevice, LdapUser
    ok = CsDevice(hostname="desktop001", external_ip="2001:db8::1", local_ip="10.0.0.5", site_name="SPI-0412", mac="aa:bb:cc:00:11:22")
    assert ok.external_ip == "2001:db8::1"
    assert CsDevice(hostname="desktop001", external_ip="1.2.3").external_ip is None   # shaped like one, isn't one
    with pytest.raises(ValidationError):
        CsDevice(hostname="desktop001", mac="zz:zz:zz:zz:zz:zz")
    with pytest.raises(ValidationError):
        LdapUser(username="jdoe", postal_code="<script>")
    assert LdapUser(username="jdoe", city="Springfield", state="IL").state == "IL"


@pytest.mark.asyncio
async def test_falcon_location_is_stored_and_public_ip_encrypted(db):
    from api.core.encryption import search_hash
    from api.integrations.crowdstrike import _where
    from api.models.device import Device, DeviceType
    n = uuid.uuid4().hex[:6]
    dev = Device(hostname=f"loc-{n}", device_type=DeviceType.workstation, ip="10.9.9.9", ip_hash=search_hash("10.9.9.9"))
    db.add(dev)
    await db.flush()
    _where(dev, {"site_name": "SPI-0412", "ou": ["Workstations", "Branches"], "machine_domain": "ad.acme.example",
                 "external_ip": "203.0.113.7", "local_ip": "10.0.12.5", "mac": "aa:bb:cc:00:11:22"})
    await db.commit()
    assert dev.edr_site == "SPI-0412" and dev.edr_ou == "Workstations | Branches" and dev.public_ip_hash == search_hash("203.0.113.7")
    assert dev.ip == "10.9.9.9"   # the scanner's address is kept; Falcon's fills only a gap
    raw = (await db.execute(text("select public_ip from devices where id = :i"), {"i": dev.id})).scalar_one()
    assert raw and "203.0.113.7" not in raw


@pytest.mark.asyncio
async def test_ad_office_fields_are_stored_encrypted(db):
    from api.integrations.ldap_ingest import upsert_directory
    from api.models.user import User
    name = f"loc{uuid.uuid4().hex[:6]}"
    await upsert_directory([{"username": name, "city": "Springfield", "state": "IL", "office": "Branch 0412",
                             "postal_code": "62701", "department": "Field Ops"}], [], db)
    u = (await db.execute(select(User).where(User.username == name))).scalar_one()
    assert (u.city, u.state, u.office, u.postal_code, u.department) == ("Springfield", "IL", "Branch 0412", "62701", "Field Ops")
    raw = (await db.execute(text("select city, office from users where id = :i"), {"i": u.id})).one()
    assert "Springfield" not in raw[0] and "Branch" not in raw[1]


def test_subnet_of():
    from api.core.location import subnet_of
    assert subnet_of("10.82.180.50") == "10.82.180.0/24"
    assert subnet_of("203.0.113.7") is None and subnet_of("nope") is None and subnet_of(None) is None


@pytest.mark.asyncio
async def test_a_camera_takes_its_neighborhoods_office(db):
    import random

    from api.core import location
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType
    from api.models.user import User
    net = f"10.{random.randint(200, 250)}.{random.randint(0, 255)}"
    tag = uuid.uuid4().hex[:6]
    people = []
    for i in range(3):
        u = User(username=f"loc{tag}{i}", is_local=False, office="Branch 0412", city="Springfield", state="IL")
        db.add(u)
        people.append(u)
    db.add(User(username=f"loc{tag}x", is_local=False, office="HQ", city="Dallas", state="TX"))
    await db.flush()

    def host(name, last, ip, kind=DeviceType.workstation, **kw):
        d = Device(hostname=f"{name}-{tag}", device_type=kind, ip=ip, ip_hash=search_hash(ip), last_login_user=last, **kw)
        db.add(d)
        return d
    ws = [host(f"ws{i}", f"ACME\\loc{tag}{i}", f"{net}.{10 + i}", edr_site=f"SPI-{tag}") for i in range(3)]
    traveler = host("ws9", f"loc{tag}x", f"{net}.19")              # one person from HQ signs in here too
    camera = host("cam", None, f"{net}.50", kind=DeviceType.unknown)
    far = host("far", None, f"10.{random.randint(1, 99)}.{random.randint(0, 255)}.5", kind=DeviceType.unknown)
    await db.commit()
    await location.recompute(db)
    for d in (*ws, traveler, camera, far):
        await db.refresh(d)
    assert (ws[0].loc_site, ws[0].loc_office, ws[0].loc_city, ws[0].loc_state, ws[0].loc_confidence) == (
        f"SPI-{tag}", "Branch 0412", "Springfield", "IL", "high")
    assert (camera.loc_city, camera.loc_state, camera.loc_office) == ("Springfield", "IL", "Branch 0412")
    assert camera.loc_confidence == "medium" and any(f"{net}.0/24" in r for r in camera.loc_evidence)
    assert all(f"loc{tag}" not in r for r in camera.loc_evidence + ws[0].loc_evidence)   # counts, never names
    assert camera.subnet_hash == ws[0].subnet_hash == search_hash(f"{net}.0/24")
    assert far.loc_city is None and far.loc_confidence is None   # nothing near it knows anything


@pytest.mark.asyncio
async def test_context_tab_shows_neighbors_gaps_and_is_for_the_security_team(db, client_cyber, client_read_only):
    import random

    from api.core import location
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType
    net = f"10.{random.randint(200, 250)}.{random.randint(0, 255)}"
    tag = uuid.uuid4().hex[:6]
    pub = f"198.51.100.{random.randint(1, 254)}"
    cam = Device(hostname=f"cam-{tag}", device_type=DeviceType.unknown, ip=f"{net}.50", ip_hash=search_hash(f"{net}.50"), sources=",horizon3,")
    ws = Device(hostname=f"ws-{tag}", device_type=DeviceType.workstation, ip=f"{net}.11", ip_hash=search_hash(f"{net}.11"),
                sources=",crowdstrike,rapid7_insightvm,ldap,", edr_vendor="crowdstrike", edr_site=f"SPI-{tag}",
                public_ip=pub, public_ip_hash=search_hash(pub))
    db.add_all([cam, ws])
    await db.commit()
    cam_id = cam.id
    await location.recompute(db)
    db.expire(cam)   # the engine writes in bulk; a request in production gets a fresh session
    db.expire(ws)
    r = await client_cyber.get(f"/api/v1/devices/{cam_id}/context")
    assert r.status_code == 200
    body = r.json()
    assert body["subnet"] == f"{net}.0/24" and body["neighbors_total"] == 1
    assert body["neighbors"][0]["name"].lower().startswith(f"ws-{tag}") and body["neighbors"][0]["coverage"]["scanner"]
    assert body["gaps"] == ["Seen by the pentest, not by your vulnerability scanner", "Only the pentest knows this asset: nothing manages it"]
    assert body["location"]["site"] == f"SPI-{tag}"   # taken from its only neighbor with one
    assert body["subnet_coverage"]["edr"] == 1
    assert (await client_read_only.get(f"/api/v1/devices/{cam_id}/context")).status_code == 404
    assert (await client_cyber.get(f"/api/v1/devices/{uuid.uuid4()}/context")).status_code == 404
