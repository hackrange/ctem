"""Discovered Users: one person in full, password expiry, and search by name or phone."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from api.models.user import User

NOW = datetime.now(timezone.utc)


async def _people(db):
    from api.models.device import Device, DeviceType
    tag = uuid.uuid4().hex[:6]
    soon = User(username=f"dsoon{tag}", is_local=False, is_active=True, first_name="Quintessa", last_name=f"Vale{tag}",
                phone="+15550100" + str(uuid.uuid4().int % 900 + 100), office="Branch 9", city="Tampa", state="FL",
                ad_disabled=False, ad_pwd_expires=NOW + timedelta(days=5, hours=2), ad_pwd_never_expires=False, ad_pwd_expired=False)
    never = User(username=f"dnever{tag}", is_local=False, is_active=True, first_name="Ike", last_name=f"Stone{tag}",
                 ad_disabled=False, ad_pwd_never_expires=True, ad_pwd_expired=False)
    login = User(username=f"dlocal{tag}", is_local=True, is_active=True)
    db.add_all([soon, never, login])
    await db.flush()
    db.add(Device(hostname=f"lap-{tag}", device_type=DeviceType.workstation, owner_user_id=soon.id, last_seen=NOW))
    await db.commit()
    return tag, soon, never, login


async def _cleanup(db, tag):
    from api.models.device import Device
    await db.execute(delete(Device).where(Device.hostname == f"lap-{tag}"))
    await db.execute(delete(User).where(User.username.like(f"%{tag}")))
    await db.commit()


async def test_one_person_in_full_and_password_expiry(client_cyber, client_read_only, db):
    tag, soon, never, login = await _people(db)
    r = await client_cyber.get(f"/api/v1/directory/users/{soon.id}")
    assert r.status_code == 200
    d = r.json()
    assert d["ad"]["pwd_days_left"] == 5 and d["where"]["city"] == "Tampa"
    assert [x["hostname"] for x in d["devices"]] == [f"lap-{tag}"] and d["devices"][0]["how"] == "signs in"
    assert (await client_cyber.get(f"/api/v1/directory/users/{never.id}")).json()["ad"]["pwd_days_left"] is None
    assert (await client_cyber.get(f"/api/v1/directory/users/{login.id}")).status_code == 404   # a sign-in account
    assert (await client_cyber.get(f"/api/v1/directory/users/{uuid.uuid4()}")).status_code == 404
    assert (await client_read_only.get(f"/api/v1/directory/users/{soon.id}")).status_code == 403

    def names(r):
        return {u["username"] for u in r.json()["users"]}
    got = await client_cyber.get("/api/v1/directory/users", params={"pwd": "expiring", "within": 7, "q": tag})
    assert names(got) == {soon.username}
    assert names(await client_cyber.get("/api/v1/directory/users", params={"pwd": "never", "q": tag})) == {never.username}
    assert (await client_cyber.get("/api/v1/directory/users", params={"pwd": "bogus"})).status_code == 422
    assert (await client_cyber.get("/api/v1/directory/users", params={"pwd": "expiring", "within": 9999})).status_code == 422
    await _cleanup(db, tag)


async def test_search_by_name_or_phone(client_cyber, db):
    tag, soon, never, _ = await _people(db)

    async def find(q):
        return {u["username"] for u in (await client_cyber.get("/api/v1/directory/users", params={"q": q, "limit": 200})).json()["users"]}
    assert soon.username in await find(f"quintessa vale{tag}")
    assert soon.username in await find(f"VALE{tag}")
    assert never.username in await find(f"ike stone{tag}") and soon.username not in await find(f"ike stone{tag}")
    digits = soon.phone[-7:]
    assert soon.username in await find(f"{digits[:3]}-{digits[3:]}")
    assert soon.username in await find(f"({soon.phone[2:5]}) {soon.phone[5:8]} {soon.phone[8:]}")
    assert soon.username not in await find("12")   # too few digits to be a phone search
    await _cleanup(db, tag)
