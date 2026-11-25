"""Hosts by UPN: whole or its first half (jane.doe), for the detected user, the assigned user, and anyone the
identity provider saw signed in on the computer. UPNs are encrypted at rest, so these are exact matches."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select


async def _found(db, q, device_id):
    from api.models.device import Device
    from api.routes.device_query import build_query
    stmt = build_query(None, q, None, None, None, None).where(Device.id == device_id)
    return bool((await db.execute(stmt.with_only_columns(func.count()))).scalar())


@pytest.mark.asyncio
async def test_hosts_are_found_by_upn_whole_or_first_half(db):
    from api.core.user_match import set_upn, upn_keys
    from api.models.device import Device, DeviceType
    from api.models.user import User
    t = uuid.uuid4().hex[:6]
    owner = User(username=f"jd{t}", is_local=False)
    set_upn(owner, f"jane.doe{t}@acme.example")
    db.add(owner)
    await db.flush()
    mine = Device(hostname=f"laptop-{t}", device_type=DeviceType.workstation, owner_user_id=owner.id)
    shared = Device(hostname=f"kiosk-{t}", device_type=DeviceType.workstation)
    keys = sorted({k for login in (f"pat.lee{t}@acme.example",) for k in upn_keys(login)})
    shared.idp_login_keys = "," + ",".join(keys) + ","   # as the identity provider's device pull writes it
    db.add_all([mine, shared])
    await db.commit()
    for q in (f"jane.doe{t}@acme.example", f"JANE.DOE{t}@ACME.EXAMPLE", f"jane.doe{t}", f"jd{t}"):
        assert await _found(db, q, mine.id), q
    assert not await _found(db, f"jane.do{t}", mine.id)   # encrypted at rest: no partial matches
    for q in (f"pat.lee{t}@acme.example", f"pat.lee{t}"):   # someone else Okta saw on the kiosk
        assert await _found(db, q, shared.id), q
    assert not await _found(db, f"pat.lee{t}", mine.id)


@pytest.mark.asyncio
async def test_the_okta_device_pull_writes_who_signed_in(db, monkeypatch):
    from api.core.user_match import upn_keys
    from api.integrations.okta import OktaConnector
    from api.models.device import Device, DeviceType
    from tests.test_okta import ORG, _dev
    t = uuid.uuid4().hex[:6]
    d = Device(hostname=f"WS-{t}", device_type=DeviceType.workstation)
    db.add(d)
    await db.commit()
    data = {"/api/v1/devices": [_dev(f"WS-{t}", users=[(f"00uA{t}".ljust(20, "A"), f"a{t}@acme.example", "ACTIVE", "2026-11-01"),
                                                        (f"00uB{t}".ljust(20, "A"), f"b{t}@acme.example", "ACTIVE", "2026-11-02")])]}

    async def fetch(self, url, client):
        return data.get(url.split("?", 1)[0].replace(f"https://{ORG}", ""), []), None
    monkeypatch.setattr(OktaConnector, "fetch", fetch)
    conn = OktaConnector({"base_url": f"https://{ORG}", "api_token": "example-not-a-real-token", "device_interval_days": "0"})
    conn.integration_id = str(uuid.uuid4())
    await conn.sync(db)
    await db.refresh(d)
    for login in (f"a{t}@acme.example", f"b{t}@acme.example"):
        assert all(f",{k}," in d.idp_login_keys for k in upn_keys(login))
