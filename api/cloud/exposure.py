"""Shared cloud-exposure logic: every provider connector reduces its cloud to the same facts, and this module
matches instances to CTEM devices, records what each one exposes, and answers per port for scoring.

Reach per open port, strongest first:
  internet      a public IP and a firewall rule open to any address (0.0.0.0/0 or ::/0)
  any_internal  open to any address, but the instance has no public IP (reachable from the private network)
  restricted    open only to listed sources (CIDRs, other security groups, prefix lists)
A port no rule opens is closed. Only facts the cloud APIs return are used."""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.cloud")
ANY = ("0.0.0.0/0", "::/0", "*", "internet", "any")
RANK = {"internet": 3, "any_internal": 2, "restricted": 1}
_PROTO = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmp", "-1": "all", "all": "all", "*": "all",
          "tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmp"}


def proto(p) -> str:
    return _PROTO.get(str(p if p is not None else "all").lower(), str(p).lower()[:8])


def is_any(source: str | None) -> bool:
    return str(source or "").strip().lower() in ANY


@dataclass
class Opening:
    """One inbound allow: protocol, port range (None = all ports), and its sources."""
    proto: str
    lo: int | None
    hi: int | None
    sources: list[str]
    via: str


@dataclass
class Instance:
    provider: str
    resource_id: str
    name: str | None = None
    account: str | None = None
    region: str | None = None
    hostname: str | None = None                      # a DNS or host name to match on, when the cloud gives one
    private_ips: list[str] = field(default_factory=list)
    public_ips: list[str] = field(default_factory=list)
    openings: list[Opening] = field(default_factory=list)


def ports(inst: Instance) -> list[dict]:
    """The instance's open ports, each with its reach. Public only with a public IP."""
    out = []
    for o in inst.openings:
        if o.proto == "icmp":
            continue
        anyone = any(is_any(s) for s in o.sources)
        reach = ("internet" if inst.public_ips else "any_internal") if anyone else "restricted"
        out.append({"proto": o.proto, "from": o.lo, "to": o.hi, "reach": reach,
                    "sources": sorted(set(o.sources))[:20], "via": o.via[:120]})
    out.sort(key=lambda p: (-RANK[p["reach"]], p["from"] if p["from"] is not None else -1))
    return out[:200]


def reach_of(port_list: list[dict], port: int, pr: str) -> tuple[str, dict | None]:
    """'internet', 'any_internal', 'restricted' or 'closed' for one port, and the rule that decided it."""
    best, why = "closed", None
    for p in port_list or []:
        if p["proto"] not in ("all", pr):
            continue
        lo, hi = p.get("from"), p.get("to")
        if lo is not None and not (lo <= port <= (hi if hi is not None else lo)):
            continue
        if RANK[p["reach"]] > RANK.get(best, 0):
            best, why = p["reach"], p
    return best, why


def describe_port(p: dict) -> str:
    rng = "all ports" if p.get("from") is None else (str(p["from"]) if p["from"] == p.get("to") else f"{p['from']}-{p['to']}")
    return f"{rng}/{p['proto']}"


def _ip_ok(ip) -> str | None:
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return None


async def _match(db: AsyncSession, inst: Instance):
    """The CTEM device for an instance: a unique private-IP match, else a hostname or name match."""
    from api.core.device_match import find_device
    from api.core.encryption import search_hash
    from api.models.device import Device
    from api.routes import device_query as dq
    hashes = [search_hash(ip) for ip in inst.private_ips if ip]
    if hashes:
        rows = (await db.execute(select(Device).where(Device.ip_hash.in_(hashes)))).scalars().all()
        if len(rows) == 1:
            return rows[0]
        if rows:   # same private IP in several networks: the name decides
            names = {(dq.short_name(n) or "").upper() for n in (inst.hostname, inst.name) if n}
            named = [d for d in rows if (dq.short_name(d.hostname) or "").upper() in names]
            if len(named) == 1:
                return named[0]
            return None
    for n in (inst.hostname, inst.name):
        if n:
            d = await find_device(db, n)
            if d is not None:
                return d
    return None


async def store(db: AsyncSession, integration_id: str, instances: list[Instance], create_devices: bool = True) -> int:
    """Record every instance, match it to a device, set the device's exposure; forget instances that are gone."""
    from api.core.device_match import add_source
    from api.core.encryption import search_hash
    from api.models.cloud import CloudAsset
    from api.models.device import Device, DeviceType
    started, count = datetime.now(timezone.utc), 0
    for inst in instances:
        inst.private_ips = [ip for ip in (_ip_ok(x) for x in inst.private_ips) if ip][:20]
        inst.public_ips = [ip for ip in (_ip_ok(x) for x in inst.public_ips) if ip][:20]
        port_list = ports(inst)
        exposed = any(p["reach"] == "internet" for p in port_list)
        row = (await db.execute(select(CloudAsset).where(CloudAsset.provider == inst.provider,
                                                         CloudAsset.resource_id == inst.resource_id[:512]))).scalar_one_or_none()
        if row is None:
            row = CloudAsset(provider=inst.provider, resource_id=inst.resource_id[:512], integration_id=integration_id,
                             seen_at=started)
            db.add(row)
        dev = await _match(db, inst)
        if dev is None and create_devices and (inst.hostname or inst.name):
            dev = Device(hostname=(inst.hostname or inst.name)[:253], device_type=DeviceType.cloud_instance,
                         source=inst.provider)
            if inst.private_ips:
                dev.ip, dev.ip_hash = inst.private_ips[0], search_hash(inst.private_ips[0])
            db.add(dev)
            await db.flush()
        if dev is not None:
            add_source(dev, inst.provider)
            dev.is_internet_exposed = exposed
        row.integration_id, row.account, row.region = integration_id, (inst.account or "")[:128] or None, (inst.region or "")[:64] or None
        row.name = (inst.name or "")[:255] or None
        row.private_ips, row.public_ips, row.ports, row.internet_exposed = inst.private_ips, inst.public_ips, port_list, exposed
        row.device_id, row.seen_at = (str(dev.id) if dev is not None else None), started
        count += 1
        if count % 200 == 0:
            await db.commit()
    gone = (await db.execute(select(CloudAsset).where(CloudAsset.integration_id == integration_id,
                                                      CloudAsset.seen_at < started))).scalars().all()
    for g in gone:   # terminated instances: their device is no longer exposed through this cloud
        if g.device_id:
            dev = await db.get(Device, g.device_id)
            if dev is not None and g.internet_exposed:
                dev.is_internet_exposed = False
    if gone:
        await db.execute(delete(CloudAsset).where(CloudAsset.id.in_([g.id for g in gone])))
    await db.commit()
    log.info("cloud %s: %d instances, %d gone", integration_id, count, len(gone))
    return count


async def for_device(db: AsyncSession, device_id: str) -> list[dict]:
    """Every cloud record for a device, for the device page and for scoring."""
    from api.models.cloud import CloudAsset
    rows = (await db.execute(select(CloudAsset).where(CloudAsset.device_id == str(device_id)))).scalars().all()
    return [{"provider": r.provider, "account": r.account, "region": r.region, "resource_id": r.resource_id,
             "name": r.name, "private_ips": r.private_ips, "public_ips": r.public_ips, "ports": r.ports,
             "internet_exposed": r.internet_exposed, "seen_at": r.seen_at.isoformat() if r.seen_at else None} for r in rows]
