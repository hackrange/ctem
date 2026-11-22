"""One device row per host, however each source spells the name."""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

_CHUNK = 500
# Apps and cloud resources, keyed by their own ids; never matched to a host by name
NOT_HOSTS = frozenset({"rapid7_appsec", "rapid7_cloudsec"})


def _is_ip(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def host_key(name: str | None) -> str | None:
    """DESKTOP001, desktop001$ and desktop001.ad.acme.example all become desktop001."""
    name = (name or "").strip().lower()
    if not name:
        return None
    if _is_ip(name):
        return name[:253]
    return name.split(".", 1)[0].rstrip("$")[:253] or None


def _domain(name: str | None) -> str | None:
    name = (name or "").strip().lower().rstrip(".")
    if not name or "." not in name or _is_ip(name):
        return None
    return name.split(".", 1)[1]


def device_domain(dev) -> str | None:
    return _domain(dev.fqdn) or _domain(dev.hostname)


def same_domain(a: str | None, b: str | None) -> bool:
    """ad.acme.example and acme.example are one namespace; acme.example and acme.cloud aren't."""
    if a is None or b is None:
        return True
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _pick(candidates: list, name: str, fqdn: str | None = None):
    """Exact name wins; then a row whose domain fits ours, AD-joined first, oldest first."""
    wanted = {n.strip().lower() for n in (name, fqdn) if n}
    for dev in candidates:
        if (dev.hostname or "").lower() in wanted or (dev.fqdn or "").lower() in wanted:
            return dev
    ours = _domain(fqdn) or _domain(name)
    fits = [d for d in candidates if same_domain(ours, device_domain(d))]
    return min(fits, key=lambda d: (not d.ad_joined, d.created_at is None, d.created_at), default=None)


async def find_device(db: AsyncSession, hostname: str | None, fqdn: str | None = None):
    from api.models.device import Device

    key = host_key(hostname) or host_key(fqdn)
    if key is None:
        return None
    rows = list((await db.execute(select(Device).where(Device.host_key == key))).scalars())
    return _pick(rows, hostname or fqdn, fqdn)


async def find_devices(db: AsyncSession, items: Iterable) -> dict:
    """Bulk find_device over names or (name, fqdn) pairs: {name: Device} for every match."""
    from api.models.device import Device

    pairs = {}
    for it in items:
        name, fqdn = (it, None) if isinstance(it, str) else it
        if host_key(name):
            pairs.setdefault(name, fqdn)
    keys = list({host_key(n) for n in pairs})
    by_key: dict[str, list] = {}
    for i in range(0, len(keys), _CHUNK):
        for dev in (await db.execute(select(Device).where(Device.host_key.in_(keys[i:i + _CHUNK])))).scalars():
            by_key.setdefault(dev.host_key, []).append(dev)
    out = {}
    for name, fqdn in pairs.items():
        dev = _pick(by_key.get(host_key(name), []), name, fqdn)
        if dev is not None:
            out[name] = dev
    return out


def remember_fqdn(dev, name: str | None) -> None:
    if not dev.fqdn and _domain(name):
        dev.fqdn = name.strip().lower()[:512]


# Short codes for the inventory's Sources column
# Display order too: directory, then scanners, then EDR
SOURCE_CODES = {"ldap": "AD", "rapid7_insightvm": "R7", "crowdstrike": "CS", "qualys": "QL",
                "msdefender": "MDE", "sentinelone": "S1", "cortex_xdr": "XDR", "tanium": "TAN",
                "guardicore": "GC", "rapid7_appsec": "R7-APP", "rapid7_cloudsec": "R7-CLOUD",
                "aws": "AWS", "azure": "AZ", "oci": "OCI",
                "github_code_review": "GCR"}


def source_list(dev) -> list[str]:
    return [s for s in (dev.sources or "").split(",") if s]


def add_source(dev, name: str | None) -> None:
    """Remember every feed that reported this device; stored as ",a,b," so filters can LIKE it."""
    have = source_list(dev)
    if name and name not in have:
        dev.sources = "," + ",".join(sorted(have + [name])) + ","


def type_from_os(os_name: str | None, current):
    """Windows Server, Domain Controller and friends are servers whatever the feed assumed."""
    from api.models.device import DeviceType

    text = (os_name or "").lower()
    if "server" in text or "domain controller" in text:
        return DeviceType.server
    return current

