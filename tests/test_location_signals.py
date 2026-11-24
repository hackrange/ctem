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
    bad = cs._device({"hostname": "desktop002", "external_ip": "999.1.1.1", "mac_address": "nope", "ou": "notalist"})
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
