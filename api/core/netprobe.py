"""The shipper's network discovery (api/collector/agent/collector_netprobe.py), CTEM's half.

targets(): what to probe. Only addresses nothing manages: hosts with an internal address that no vulnerability
scanner, EDR or directory covers (a pentest or cloud inventory found them), plus the /24s they sit in so unknown
devices turn up, minus every managed host in those /24s. The box limits it again to its own approved scope.

apply(): what came back. An answering address CTEM knows gets "alive" with its open ports; one it doesn't know is a
new asset from source netprobe: a device on the network no tool manages."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import or_, select

from api.grc.checks import DIRECTORY, EDR, SCANNERS
from api.models.device import Device, NON_HOST_TYPES

SOURCE = "netprobe"
MAX_HOSTS, MAX_NETS = 20000, 2000
_MANAGERS = SCANNERS + EDR + DIRECTORY


def _managed(d: Device) -> bool:
    have = {s for s in (d.sources or "").split(",") if s}
    return bool(have & set(_MANAGERS)) or bool(d.edr_vendor) or bool(d.ad_joined)


async def targets(db) -> dict:
    from api.core.location import subnet_of
    rows = (await db.execute(select(Device).where(Device.subnet_hash.is_not(None), Device.device_type.not_in(NON_HOST_TYPES))
                             .limit(200_000))).scalars().all()
    hosts, nets, managed_by_net = [], {}, {}
    for d in rows:
        net = subnet_of(d.ip)
        if not net:
            continue
        if _managed(d):
            managed_by_net.setdefault(net, set()).add(str(d.ip).strip())
        else:
            hosts.append(str(d.ip).strip())
            nets[net] = nets.get(net, 0) + 1
    sweep = sorted(nets, key=lambda n: -nets[n])[:MAX_NETS]   # the /24s with the most unmanaged hosts first
    skip = sorted({ip for n in sweep for ip in managed_by_net.get(n, ())})
    return {"hosts": sorted(set(hosts))[:MAX_HOSTS], "sweep": sweep, "skip": skip[:MAX_HOSTS * 2]}


async def apply(db, probes: list[dict]) -> int:
    from api.core.device_match import add_source
    from api.core.encryption import search_hash
    from api.models.device import DeviceType
    now, n = datetime.now(timezone.utc), 0
    hashes = {search_hash(p["ip"]): p for p in probes}
    known = {d.ip_hash: d for d in (await db.execute(select(Device).where(Device.ip_hash.in_(list(hashes))))).scalars()}
    for h, p in hashes.items():
        when = p.get("at") or now
        ports = " ".join(f"{x}/tcp" for x in p.get("ports") or []) or ("icmp" if p.get("icmp") else None)
        d = known.get(h)
        if d is None:
            if not p.get("alive"):
                continue
            d = Device(hostname=p["ip"], device_type=DeviceType.unknown, source=SOURCE, ip=p["ip"], ip_hash=h)
            db.add(d)   # something answered that no tool knows
        d.probed_at = when
        if p.get("alive"):
            d.alive_at, d.alive_ports = when, (ports or "")[:256] or None
            add_source(d, SOURCE)
        n += 1
    await db.flush()
    return n
