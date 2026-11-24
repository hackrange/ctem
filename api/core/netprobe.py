"""The shipper's network discovery (api/collector/agent/collector_netprobe.py), CTEM's half.

targets(): what to probe. Addresses nothing manages: hosts with an internal address that no vulnerability scanner,
EDR or directory covers (a pentest or cloud inventory found them), plus the /24s they sit in so unknown devices turn
up, minus every managed host in those /24s. Also any host no tool has seen in the retention window, so it can be
confirmed offline before its findings are removed (api/core/stale_hosts.py). The box limits it to its own scope.

apply(): what came back. An answering address CTEM knows gets "alive" with its open ports; one it doesn't know is a
new asset from source netprobe: a device on the network no tool manages. Every time is the server's own (when the
result arrived), never one the shipper reports, and silence only counts for an address CTEM asked about (one
targets() hands out), since silence is what lets api/core/stale_hosts.py remove a host's findings."""
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
    # Hosts no tool has seen in the retention window are tried too, so they're confirmed offline before anything goes
    from api.core.stale_hosts import candidates
    stale = set(await candidates(db))
    skip = sorted({ip for n in sweep for ip in managed_by_net.get(n, ())} - stale)
    return {"hosts": sorted(set(hosts) | stale)[:MAX_HOSTS], "sweep": sweep, "skip": skip[:MAX_HOSTS * 2]}


async def apply(db, probes: list[dict]) -> int:
    from api.core.device_match import add_source
    from api.core.encryption import search_hash
    from api.models.device import DeviceType
    now, n = datetime.now(timezone.utc), 0
    hashes = {search_hash(p["ip"]): p for p in probes}
    known = {d.ip_hash: d for d in (await db.execute(select(Device).where(Device.ip_hash.in_(list(hashes))))).scalars()}
    asked = None   # the stale hosts CTEM asked about, read once and only if a managed host is reported silent
    for h, p in hashes.items():
        when = now   # the shipper's own clock can't move a silence back (or an answer forward)
        ports = " ".join(f"{x}/tcp" for x in p.get("ports") or []) or ("icmp" if p.get("icmp") else None)
        d = known.get(h)
        if d is None:
            if not p.get("alive"):
                continue
            d = Device(hostname=p["ip"], device_type=DeviceType.unknown, source=SOURCE, ip=p["ip"], ip_hash=h)
            db.add(d)   # something answered that no tool knows
        elif not p.get("alive") and _managed(d):
            # A managed host is only a target while no tool has seen it in the retention window; otherwise CTEM never
            # asked, and a reported silence must not start its clock
            if asked is None:
                from api.core.stale_hosts import candidates
                asked = set(await candidates(db))
            if str(d.ip or "").strip() not in asked:
                continue
        d.probed_at = when
        if p.get("alive"):
            d.alive_at, d.alive_ports, d.silent_since = when, (ports or "")[:256] or None, None
            add_source(d, SOURCE)
        elif d.silent_since is None:
            d.silent_since = when   # the start of a silence; only an unbroken one counts toward "gone"
        n += 1
    await db.flush()
    return n
