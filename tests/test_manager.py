"""A person's manager from the directory: AD names the manager by DN (through Okta's profile); the manager is the person
whose own DN matches (case and spacing ignored). Shown on Discovered Users and, for a device's detected user, on the
asset's Details to admins and cyber only."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete


def test_a_dn_matches_whatever_its_case_and_spacing():
    from api.core.manager import dn_key, is_dn
    assert dn_key("CN=Jane Doe,OU=IT,DC=acme,DC=example") == dn_key("cn=jane doe, ou=IT ,dc=ACME,dc=example")
    assert not is_dn("Jane Doe") and not is_dn("jane@acme.example") and dn_key(None) is None


def test_okta_brings_the_manager_and_the_persons_own_dn():
    from types import SimpleNamespace

    from api.core.manager import dn_key
    from api.integrations.okta_ingest import merge_user
    u = SimpleNamespace(upn=None, upn_local_hash=None, okta_id=None, idp=None, title=None, department=None, first_name=None,
                        last_name=None, city=None, state=None, mobile=None, phone=None, display_name=None, ad_dn=None,
                        ad_dn_hash=None, manager_dn=None)
    merge_user(u, {"profile": {"dn": "CN=Wile E Coyote,OU=Staff,DC=acme,DC=example", "manager": "CN=Road Runner,OU=Staff,DC=acme,DC=example"},
                   "oid": None, "status": "ACTIVE", "last_login": None, "password_changed": None})
    assert u.ad_dn_hash == dn_key("CN=Wile E Coyote,OU=Staff,DC=acme,DC=example") and u.manager_dn.startswith("CN=Road Runner")
    merge_user(u, {"profile": {"manager": "Road Runner"}, "oid": None, "status": "ACTIVE", "last_login": None, "password_changed": None})
    assert u.manager_dn is None   # not a DN: nothing to look up


@pytest.mark.asyncio
async def test_the_manager_shows_on_the_person_and_on_their_asset(db, client_cyber, client_admin, client_it_user):
    from api.core.manager import set_dn
    from api.models.device import Device, DeviceType
    from api.models.user import User
    n = uuid.uuid4().hex[:6]
    boss = User(username=f"rrunner{n}", is_local=False, first_name="Road", last_name="Runner", email=f"rr{n}@acme.example",
                title="Director", department="Acme Labs")
    set_dn(boss, f"CN=Road Runner {n},OU=Staff,DC=acme,DC=example")
    me = User(username=f"wcoyote{n}", is_local=False, first_name="Wile", last_name="Coyote",
              manager_dn=f"cn=road runner {n}, ou=Staff,dc=acme,dc=example")
    lost = User(username=f"elmer{n}", is_local=False, manager_dn=f"CN=Gone Person {n},OU=Staff,DC=acme,DC=example")
    db.add_all([boss, me, lost])
    await db.flush()
    dev = Device(hostname=f"ws-mgr-{n}", device_type=DeviceType.workstation, owner_user_id=me.id)
    db.add(dev)
    await db.commit()
    m = (await client_cyber.get(f"/api/v1/directory/users/{me.id}")).json()["manager"]
    assert m["found"] and m["first_name"] == "Road" and m["last_name"] == "Runner" and m["email"] == f"rr{n}@acme.example"
    assert m["title"] == "Director" and m["id"] == str(boss.id)
    m = (await client_cyber.get(f"/api/v1/directory/users/{lost.id}")).json()["manager"]
    assert m == {"name": f"Gone Person {n}", "found": False}          # named by the directory, not one CTEM has
    assert (await client_cyber.get(f"/api/v1/directory/users/{boss.id}")).json()["manager"] is None
    d = (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()
    assert d["detected_user_manager"]["email"] == f"rr{n}@acme.example"
    r = await client_it_user.get(f"/api/v1/devices/{dev.id}")
    assert r.status_code != 200 or r.json().get("detected_user_manager") is None   # personal: admins and cyber only
    await db.execute(delete(Device).where(Device.id == dev.id))
    await db.execute(delete(User).where(User.id.in_([boss.id, me.id, lost.id])))
    await db.commit()
