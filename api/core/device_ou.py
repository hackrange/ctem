"""Directory OUs a device sits in, as keyed hashes, so dashboards and filters can include or leave out an OU
("not in OU=Blocked_Computers") while the DN itself stays encrypted at rest.

ad_ou_keys holds ",k1,k2," with one key per OU name in the DN (any depth), each the first 24 hex characters of
the keyed search hash of the lowercased name. Nothing readable is stored."""
from __future__ import annotations

import logging
import re

from sqlalchemy import select

log = logging.getLogger("open-ctem.device_ou")
_SPLIT = re.compile(r"(?<!\\),")   # DN parts, leaving escaped commas inside a name alone


def ou_names(dn: str | None) -> list[str]:
    """The OU names in a DN, innermost first: "CN=PC1,OU=Blocked_Computers,OU=HQ,DC=acme" -> ["Blocked_Computers", "HQ"]."""
    out = []
    for part in _SPLIT.split(dn or ""):
        k, _, v = part.strip().partition("=")
        if k.strip().upper() == "OU" and v.strip():
            out.append(v.strip().replace("\\,", ","))
    return out


def clean_name(value: str) -> str:
    """What people type: "OU=Blocked_Computers", "ou=blocked_computers" or "Blocked_Computers"."""
    v = value.strip()
    if v.upper().startswith("OU="):
        v = v[3:]
    return v.split(",")[0].strip()


def ou_key(name: str) -> str:
    from api.core.encryption import search_hash
    return search_hash("ou:" + clean_name(name).lower())[:24]


def ou_keys(dn: str | None) -> str | None:
    names = ou_names(dn)
    return ("," + ",".join(dict.fromkeys(ou_key(n) for n in names)) + ",") if names else None


async def backfill(db, limit: int = 50000) -> int:
    """Fill ad_ou_keys for devices that have a DN but no keys yet (a one-off after upgrade; cheap afterwards)."""
    from api.models.device import Device
    rows = (await db.execute(select(Device).where(Device.ad_dn.is_not(None), Device.ad_ou_keys.is_(None)).limit(limit))).scalars().all()
    for d in rows:
        d.ad_ou_keys = ou_keys(d.ad_dn) or ","
    if rows:
        await db.commit()
        log.info("OU keys filled for %d devices", len(rows))
    return len(rows)


_names_cache: dict = {"at": 0.0, "names": []}


async def names_in_use(db, ttl: float = 600.0) -> list[str]:
    """Distinct OU names across devices, for the filter suggestions (decrypted in memory, cached 10 minutes)."""
    import time
    if time.monotonic() - _names_cache["at"] < ttl:
        return _names_cache["names"]
    from api.models.device import Device
    seen: dict[str, str] = {}
    for (dn,) in (await db.execute(select(Device.ad_dn).where(Device.ad_dn.is_not(None)))).all():
        for n in ou_names(dn):
            seen.setdefault(n.lower(), n)
    _names_cache.update(at=time.monotonic(), names=sorted(seen.values(), key=str.lower)[:1000])
    return _names_cache["names"]
