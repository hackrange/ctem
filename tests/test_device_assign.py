"""Device assignment: set by people, kept through syncs, and the only owner link that grants access."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select


def _n() -> str:
    return f"a{uuid.uuid4().hex[:8]}"


async def _dir_user(db, name):
    from api.models.user import User
    u = User(username=name, is_local=False, is_active=True)
    db.add(u)
    await db.commit()
    return u


def test_sign_in_names_resolve_to_directory_users():
    from api.core.user_match import UserIndex, bare

    assert bare("ACME\\JDoe") == "jdoe" and bare("jdoe@ad.acme.example") == "jdoe"
    idx = UserIndex({"jdoe": "u1"}, ("sulocal_",))
    assert idx.resolve("ACME\\JDoe") == ("u1", False)
    assert idx.resolve("sulocal_jdoe") == ("u1", True)
    assert idx.resolve("kioskuser0") == (None, False) and idx.resolve(None) == (None, False)


@pytest.mark.asyncio
async def test_assignment_survives_syncs_and_shows_who_signed_in(db, client_admin):
    from api.integrations.crowdstrike import CrowdStrikeConnector
    from api.models.device import Device

    name, other, host = _n(), _n(), _n()
    alice, bob = await _dir_user(db, name), await _dir_user(db, other)
    await CrowdStrikeConnector({})._upsert([{"hostname": host.upper(), "status": "normal", "last_login_user": f"sulocal_{name}"}], [], db)
    dev = (await db.execute(select(Device).where(Device.host_key == host))).scalar_one()
    assert dev.owner_user_id == alice.id  # detected through the admin-account prefix

    r = await client_admin.put(f"/api/v1/devices/{dev.id}/assignment", json={"user_id": str(alice.id), "note": "laptop"})
    assert r.status_code == 200
    # Someone else signs in; the sync updates detection but never the assignment
    await CrowdStrikeConnector({})._upsert([{"hostname": host.upper(), "status": "normal", "last_login_user": f"ACME\\{other}"}], [], db)
    d = (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()
    assert d["assigned_user"]["username"] == name and d["assigned_user"]["note"] == "laptop"
    assert d["detected_user"] == other and d["user"] == name
    listed = (await client_admin.get("/api/v1/devices", params={"q": host})).json()["devices"][0]
    assert listed["assigned_user"]["id"] == str(alice.id) and listed["last_login_user"] == f"ACME\\{other}"

    assert (await client_admin.delete(f"/api/v1/devices/{dev.id}/assignment")).status_code == 204
    d = (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()
    assert d["assigned_user"] is None and d["user"] == other


@pytest.fixture
async def client_inventory(db):
    from api.main import create_app
    from tests.conftest import _authed_client, _make_user
    user = await _make_user(db, "inventory")
    async with _authed_client(create_app(), db, user) as c:
        yield c


@pytest.mark.asyncio
async def test_only_admin_and_inventory_edit_and_inputs_are_checked(db, client_inventory, client_cyber,
                                                                      client_read_only, admin_user):
    from api.models.device import Device, DeviceType

    dev = Device(hostname=_n(), device_type=DeviceType.workstation)
    db.add(dev)
    await db.commit()
    person = await _dir_user(db, _n())
    url = f"/api/v1/devices/{dev.id}/assignment"
    for c in (client_cyber, client_read_only):  # cyber can read devices but not run inventory
        assert (await c.put(url, json={"user_id": str(person.id)})).status_code == 403
        assert (await c.put(f"/api/v1/devices/{dev.id}/status", json={"status": "lost"})).status_code == 403
        assert (await c.get("/api/v1/devices/assignable-users", params={"q": "ab"})).status_code == 403
    assert (await client_inventory.put(url, json={"user_id": str(uuid.uuid4())})).status_code == 400
    assert (await client_inventory.put(url, json={"user_id": str(admin_user.id)})).status_code == 400  # local app account
    assert (await client_inventory.put(url, json={"user_id": str(person.id), "role": "x"})).status_code == 422
    assert (await client_inventory.put(f"/api/v1/devices/{uuid.uuid4()}/assignment",
                                       json={"user_id": str(person.id)})).status_code == 404
    found = (await client_inventory.get("/api/v1/devices/assignable-users", params={"q": person.username})).json()["users"]
    assert [u["id"] for u in found] == [str(person.id)]
    assert (await client_inventory.put(url, json={"user_id": str(person.id)})).status_code == 200
    # Inventory sees every device, but not its vulnerabilities
    assert (await client_inventory.get(f"/api/v1/devices/{dev.id}")).status_code == 200
    assert (await client_inventory.get(f"/api/v1/devices/{dev.id}/findings")).status_code == 403
    assert (await client_inventory.get(f"/api/v1/devices/{dev.id}/findings/export")).status_code == 403
    assert (await client_inventory.get("/api/v1/vulns")).status_code == 403


@pytest.mark.asyncio
async def test_status_shipped_needs_carrier_and_tracking(db, client_inventory, client_admin):
    from api.models.device import Device, DeviceType

    dev = Device(hostname=_n(), device_type=DeviceType.workstation)
    db.add(dev)
    await db.commit()
    url = f"/api/v1/devices/{dev.id}/status"
    assert (await client_inventory.put(url, json={"status": "shipped"})).status_code == 422
    assert (await client_inventory.put(url, json={"status": "shipped", "carrier": "dhl",
                                                  "tracking_number": "bad #1"})).status_code == 422
    assert (await client_inventory.put(url, json={"status": "lost", "carrier": "ups",
                                                  "tracking_number": "1Z999AA10123456784"})).status_code == 422
    assert (await client_inventory.put(url, json={"status": "teleported"})).status_code == 422
    r = await client_inventory.put(url, json={"status": "shipped", "carrier": "dhl", "tracking_number": "jd0146000037"})
    assert r.status_code == 200 and r.json()["tracking_number"] == "JD0146000037"
    st = (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()["inventory_status"]
    assert (st["status"], st["carrier"], st["tracking_number"]) == ("shipped", "dhl", "JD0146000037")
    listed = (await client_admin.get("/api/v1/devices", params={"status": "shipped", "q": dev.hostname})).json()
    assert listed["total"] == 1
    # Marked stolen: the shipping details go, the status stays even with nobody assigned
    assert (await client_admin.put(url, json={"status": "stolen", "note": "car break-in"})).status_code == 200
    st = (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()["inventory_status"]
    assert (st["status"], st["carrier"], st["note"]) == ("stolen", None, "car break-in")
    assert (await client_admin.delete(f"/api/v1/devices/{dev.id}/assignment")).status_code == 204
    assert (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()["inventory_status"]["status"] == "stolen"
    assert (await client_admin.put(url, json={"status": None})).status_code == 200
    assert (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()["inventory_status"] is None


@pytest.mark.asyncio
async def test_scoped_user_cannot_assign_devices_they_cannot_see(db, client_it_user):
    from api.models.device import Device, DeviceType

    dev = Device(hostname=_n(), device_type=DeviceType.server)
    db.add(dev)
    await db.commit()
    person = await _dir_user(db, _n())
    r = await client_it_user.put(f"/api/v1/devices/{dev.id}/assignment", json={"user_id": str(person.id)})
    assert r.status_code in (403, 404)


@pytest.mark.asyncio
async def test_user_counts_and_risk_use_assignments(db, client_admin):
    from api.models.device import Device, DeviceAssignment, DeviceType
    from api.scoring.engine import recalculate_user

    name = _n()
    person = await _dir_user(db, name)
    a = Device(hostname=_n(), device_type=DeviceType.server, risk_score=80.0)
    b = Device(hostname=_n(), device_type=DeviceType.workstation, risk_score=40.0, owner_user_id=person.id)
    c = Device(hostname=_n(), device_type=DeviceType.workstation, risk_score=90.0, owner_user_id=person.id)
    other = await _dir_user(db, _n())
    db.add_all([a, b, c])
    await db.flush()
    db.add_all([DeviceAssignment(device_id=a.id, user_id=person.id),
                DeviceAssignment(device_id=c.id, user_id=other.id)])  # c is someone else's, even if person signs in
    await db.commit()
    u = next(x for x in (await client_admin.get("/api/v1/directory/users", params={"q": name})).json()["users"]
             if x["username"] == name)
    assert (u["devices_assigned"], u["devices_detected"]) == (1, 1)
    risk = await recalculate_user(person, db)
    assert risk is not None and risk.score > 0


@pytest.mark.asyncio
async def test_inventory_rest_api_with_a_bearer_token(db, client, api_token_for):
    """Scripts and other tools drive the same endpoints with an inventory user's API token."""
    from api.models.device import Device, DeviceType
    from tests.conftest import _make_user

    clerk = await _make_user(db, "inventory")
    plain, _ = await api_token_for(clerk)
    auth = {"Authorization": f"Bearer {plain}"}
    dev = Device(hostname=_n(), device_type=DeviceType.workstation)
    db.add(dev)
    await db.commit()
    person = await _dir_user(db, _n())
    r = await client.put(f"/api/v1/devices/{dev.id}/assignment", json={"user_id": str(person.id)}, headers=auth)
    assert r.status_code == 200
    r = await client.put(f"/api/v1/devices/{dev.id}/status", headers=auth,
                         json={"status": "shipped", "carrier": "ups", "tracking_number": "1Z999AA10123456784"})
    assert r.status_code == 200
    d = (await client.get(f"/api/v1/devices/{dev.id}", headers=auth)).json()
    assert d["assigned_user"]["id"] == str(person.id) and d["inventory_status"]["carrier"] == "ups"


@pytest.mark.asyncio
async def test_api_docs_only_for_signed_in_admin_or_cyber(client_no_auth, client_read_only, client_admin):
    for path in ("/api/docs", "/api/openapi.json"):
        assert (await client_no_auth.get(path)).status_code in (401, 403)
        assert (await client_read_only.get(path)).status_code == 403
    page = await client_admin.get("/api/docs")
    assert page.status_code == 200 and 'integrity="sha384-' in page.text
    paths = (await client_admin.get("/api/openapi.json")).json()["paths"]
    for p in ("/api/v1/devices/{device_id}/assignment", "/api/v1/devices/{device_id}/status",
              "/api/v1/devices/assignable-users", "/api/v1/devices"):
        assert p in paths
    assert "/api/docs" not in paths
