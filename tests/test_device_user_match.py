"""Finding the person behind a device: admin aliases, first names, and inventory search."""
from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select


def _n() -> str:
    return f"a{uuid.uuid4().hex[:8]}"


def _row(uid, username, first=None, display=None, active=True, service=False):
    return SimpleNamespace(id=uid, username=username, first_name=first, display_name=display, is_active=active,
                           ad_disabled=False, is_service_account=service)


def test_alias_with_a_unique_first_name_finds_the_person():
    from api.core.user_match import UserIndex, _unique_first_names

    rows = [_row("u1", "AJangala", display="Jangala, Akash"), _row("u2", "PNair", display="Nair, Prakash"),
            _row("u3", "PLee", first="Prakash"), _row("u4", "adms1", display="Akash X - ADMS", service=True),
            _row("u5", "KOld", display="Old, Kim", active=False)]
    idx = UserIndex({r.username.lower(): r.id for r in rows}, ("sulocal_",), _unique_first_names(rows))
    assert idx.resolve("sulocal_akash") == ("u1", True)
    assert idx.resolve("sulocal_prakash") == (None, False)  # two of them, so no guessing
    assert idx.resolve("sulocal_kim") == (None, False)  # disabled people don't count
    assert idx.resolve("akash") == (None, False)  # first names only through an alias
    assert idx.resolve("sulocal_ajangala") == ("u1", True)


async def _dir_user(db, name, display=None):
    from api.models.user import User
    u = User(username=name, display_name=display, is_local=False, is_active=True)
    db.add(u)
    await db.commit()
    return u


@pytest.mark.asyncio
async def test_inventory_search_finds_people_by_partial_name_and_alias(db, client_admin):
    from api.integrations.crowdstrike import CrowdStrikeConnector
    from api.models.device import Device

    first, name, host, host2 = f"zq{uuid.uuid4().hex[:6]}", _n(), _n(), _n()
    person = await _dir_user(db, name, display=f"Smith, {first.capitalize()}")
    await CrowdStrikeConnector({})._upsert([{"hostname": host.upper(), "status": "normal", "last_login_user": f"sulocal_{first}"}], [], db)
    dev = (await db.execute(select(Device).where(Device.host_key == host))).scalar_one()
    assert dev.owner_user_id == person.id

    hits = (await client_admin.get("/api/v1/devices", params={"q": name[:6]})).json()["devices"]
    assert [d["id"] for d in hits] == [dev.id]  # partial username

    # Unlinked alias sign-in still turns up for the bare name
    await CrowdStrikeConnector({})._upsert([{"hostname": host2.upper(), "status": "normal", "last_login_user": "sulocal_nobodyhere"}], [], db)
    hits = (await client_admin.get("/api/v1/devices", params={"q": "nobodyhere"})).json()["devices"]
    assert any(d["hostname"].lower() == host2 for d in hits)

    # Assigned (not detected) devices match their assignee too
    other = await _dir_user(db, _n())
    dev2 = (await db.execute(select(Device).where(Device.host_key == host2))).scalar_one()
    assert (await client_admin.put(f"/api/v1/devices/{dev2.id}/assignment", json={"user_id": str(other.id)})).status_code == 200
    hits = (await client_admin.get("/api/v1/devices", params={"q": other.username[2:]})).json()["devices"]
    assert [d["id"] for d in hits] == [dev2.id]


@pytest.mark.asyncio
async def test_upn_links_sign_ins_finds_devices_and_shows_on_the_device(db, client_admin):
    from api.integrations.crowdstrike import CrowdStrikeConnector
    from api.integrations.ldap_ingest import upsert_directory
    from api.models.device import Device

    name, host, tail = _n(), _n(), uuid.uuid4().hex[:6]
    upn = f"Mark.Langston{tail}@ad.acme.example"
    await upsert_directory([{"username": name, "upn": upn, "title": "Field Tech"},
                            {"username": _n(), "upn": "bad\nupn@x"}], [], db)
    # Signed in with the UPN, whose local part isn't the username
    await CrowdStrikeConnector({})._upsert([{"hostname": host.upper(), "status": "normal", "last_login_user": upn}], [], db)
    dev = (await db.execute(select(Device).where(Device.host_key == host))).scalar_one()
    assert dev.owner_user_id is not None

    for q in (upn.lower(), upn.upper(), name[:6]):
        hits = (await client_admin.get("/api/v1/devices", params={"q": q})).json()["devices"]
        assert [d["id"] for d in hits] == [dev.id], q
    d = (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()
    assert (d["detected_user_upn"], d["detected_user_title"]) == (upn, "Field Tech")
    users = (await client_admin.get("/api/v1/directory/users", params={"q": upn})).json()["users"]
    assert [u["username"] for u in users] == [name] and users[0]["upn"] == upn


@pytest.mark.asyncio
async def test_login_history_finds_the_owner_behind_kiosk_sign_ins(db, client_admin):
    from api.integrations.crowdstrike import CrowdStrikeConnector
    from api.maintenance.backfill_sources import run as backfill
    from api.models.device import Device

    name, host = _n(), _n()
    person = await _dir_user(db, name)
    await CrowdStrikeConnector({})._upsert([{"hostname": host.upper(), "status": "normal", "last_login_user": "SpecopsClient_150209",
                                             "recent_logins": ["SpecopsClient_150209", f"sulocal_{name}", f"ACME\\{name}"]}], [], db)
    dev = (await db.execute(select(Device).where(Device.host_key == host))).scalar_one()
    assert dev.owner_user_id == person.id and dev.last_login_user == "SpecopsClient_150209"

    # A run without history (older shipper) keeps what we learned; so does the backfill
    await CrowdStrikeConnector({})._upsert([{"hostname": host.upper(), "status": "normal", "last_login_user": "kioskUser0"}], [], db)
    await backfill(db)
    await db.refresh(dev)
    assert dev.owner_user_id == person.id
    d = (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()
    assert d["recent_logins"][1] == f"sulocal_{name}" and d["detected_user"] == name


def test_source_chips_read_ad_r7_cs():
    from types import SimpleNamespace as NS

    from api.routes.device_query import source_codes

    assert source_codes(NS(sources=",crowdstrike,ldap,rapid7_insightvm,", source="rapid7_insightvm")) == ["AD", "R7", "CS"]
    assert source_codes(NS(sources=",newthing,crowdstrike,", source=None)) == ["CS", "NEWTHING"]
