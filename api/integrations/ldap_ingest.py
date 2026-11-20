"""Directory upsert shared by the direct LDAP connector and the on-prem collector push."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

_IN_CHUNK = 500  # keeps IN (...) lists well under every driver's bind limit


# shipper field -> User column; only copied when sent, so an older shipper can't blank them
_AD_STATE = (("last_logon", "ad_last_logon"), ("pwd_last_set", "ad_pwd_last_set"), ("pwd_expires", "ad_pwd_expires"),
             ("pwd_expired", "ad_pwd_expired"), ("pwd_never_expires", "ad_pwd_never_expires"),
             ("locked_out", "ad_locked_out"))


def _chunks(items: list, size: int = _IN_CHUNK):
    for i in range(0, len(items), size):
        yield items[i:i + size]


async def upsert_directory(users: list[dict], computers: list[dict], db: AsyncSession, commit: bool = True) -> int:
    from api.core.device_match import add_source, find_devices, type_from_os
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType
    from api.models.user import User

    count = 0
    users = [u for u in users if u.get("username")]
    known: dict[str, User] = {}
    for part in _chunks(list({u["username"] for u in users})):
        for row in (await db.execute(select(User).where(User.username.in_(part)))).scalars():
            known.setdefault(row.username, row)
    for u in users:
        user = known.get(u["username"])
        if user is None:
            user = User(username=u["username"], is_local=False)
            db.add(user)
            known[u["username"]] = user
        if user.is_local:
            continue  # never let a directory feed rewrite a local break-glass account
        if u.get("email"):
            user.email = u["email"]
            user.email_hash = search_hash(u["email"])
        if u.get("display_name"):
            user.display_name = u["display_name"]
        if u.get("ad_dn"):
            user.ad_dn = u["ad_dn"]
        user.ad_groups = u.get("groups", [])
        user.ad_disabled = bool(u.get("disabled"))
        for src, dst in _AD_STATE:
            if src in u and u[src] is not None:
                setattr(user, dst, u[src])
        if u.get("pwd_never_expires"):
            user.ad_pwd_expires = None
        count += 1

    computers = [c for c in computers if c.get("hostname")]
    devices = await find_devices(db, [(c["hostname"], c.get("fqdn")) for c in computers])
    for c in computers:
        device = devices.get(c["hostname"])
        if device is None:
            device = Device(hostname=c["hostname"], device_type=DeviceType.workstation, source="ldap")
            db.add(device)
            devices[c["hostname"]] = device
        add_source(device, "ldap")
        device.fqdn = c.get("fqdn") or device.fqdn
        device.ad_dn = c.get("ad_dn")
        device.os = c.get("os") or device.os
        device.device_type = type_from_os(device.os, device.device_type)
        device.ad_joined = True
        last = c.get("last_logon")
        if isinstance(last, datetime):
            device.ad_last_logon = last
        count += 1

    if commit:
        await db.commit()
    else:
        await db.flush()
    return count
