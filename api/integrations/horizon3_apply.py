"""Apply one completed NodeZero pentest (api/integrations/horizon3.py): its weaknesses, proof, and closed ports."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

SOURCE = "horizon3"
CLOSED = "horizon3_closed"   # a finding's reachability when NodeZero tested the host and the port wasn't open
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _dt(v):
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00")) if v else None
    except ValueError:
        return None
    return t.replace(tzinfo=timezone.utc) if t is not None and t.tzinfo is None else t   # NodeZero's times are UTC


async def _device(db, ip: str | None, name: str | None, cache: dict, create: bool = True, ips=None, names=None):
    """The CTEM asset for a host NodeZero saw: by any of its IPs (an asset's own, or a cloud instance's private IP),
    then any of its names; a host with something on it becomes an asset if nothing else knows it."""
    from api.core.device_match import add_source, find_device
    from api.core.encryption import search_hash
    from api.models.cloud import CloudAsset
    from api.models.device import Device, DeviceType
    ips = [i for i in dict.fromkeys([ip, *(ips or [])]) if i]
    names = [n for n in dict.fromkeys([name, *(names or [])]) if n]
    for k in [("ip", i) for i in ips] + [("name", n.lower()) for n in names]:
        if k in cache and (cache[k] is not None or not create):
            return cache[k]
    d = None
    if ips:
        d = (await db.execute(select(Device).where(Device.ip_hash.in_([search_hash(i) for i in ips])).limit(1))).scalars().first()
    if d is None and ips:   # a cloud instance CTEM knows by its private IP
        if "cloud_ips" not in cache:   # once per pentest: private IP -> the instance's asset
            cache["cloud_ips"] = {i: dev for dev, pips in (await db.execute(select(CloudAsset.device_id, CloudAsset.private_ips).where(
                CloudAsset.device_id.is_not(None)))).all() for i in (pips or [])}
        hit = next((cache["cloud_ips"][i] for i in ips if i in cache["cloud_ips"]), None)
        d = await db.get(Device, hit) if hit else None
    for n in names if d is None else []:
        d = await find_device(db, n)
        if d is not None:
            break
    if d is None and create and (names or ips):
        d = Device(hostname=(names[0] if names else ips[0])[:253], device_type=DeviceType.unknown, source=SOURCE)
        if ips:
            d.ip, d.ip_hash = ips[0], search_hash(ips[0])
        db.add(d)
        await db.flush()
    if d is not None:
        add_source(d, SOURCE)
    for k in [("ip", i) for i in ips] + [("name", n.lower()) for n in names]:
        cache[k] = d
    return d


async def op(db: AsyncSession, pentest: dict, weaknesses: list[dict], services: list[dict] | None, extra: dict | None = None,
             findings: bool = True) -> int:
    """findings=False when NodeZero's weakness series write the findings (api/integrations/horizon3_series.py): the
    pentest then adds its closed ports and its attacker view only."""
    from api.integrations import horizon3_view as view
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    when = _dt(pentest.get("completed_at")) or datetime.now(timezone.utc)
    cache, tested, n = {}, set(), 0
    extra = extra or {}
    busy = view.hosts_with_something(weaknesses, extra)
    for h in extra.get("hosts") or []:   # every host it tested, matched to CTEM's assets first
        if not h.get("is_in_scope", True):
            continue
        ips, names = h.get("ip_addresses") or [h.get("ip")], h.get("host_names") or [h.get("host_name")]
        d = await _device(db, None, None, cache, create=bool(set(ips) & busy), ips=ips, names=names)
        if d is not None:
            tested.add(str(d.id))
    for w in weaknesses if findings else []:
        vid = str(w.get("vuln_id") or "")[:200]
        if not vid:
            continue
        d = await _device(db, w.get("ip"), w.get("host_name"), cache)
        if d is None:
            continue
        tested.add(str(d.id))
        cves = [a for a in (w.get("vuln_aliases") or []) if isinstance(a, str) and _CVE.match(a)]
        cve = vid if _CVE.match(vid) else (cves[0] if cves else None)
        v = (await db.execute(select(Vulnerability).where(Vulnerability.source == SOURCE, Vulnerability.source_vuln_id == vid))).scalar_one_or_none()
        if v is None:
            v = Vulnerability(source=SOURCE, source_vuln_id=vid, title=str(w.get("vuln_name") or vid)[:512], domain="infra")
            db.add(v)
        v.title, v.cve_id = str(w.get("vuln_name") or v.title)[:512], cve or v.cve_id
        if isinstance(w.get("base_score"), (int, float)) and 0 <= w["base_score"] <= 10:
            v.cvss_base = float(w["base_score"])
        v.is_kev = bool(w.get("vuln_cisa_kev")) or v.is_kev
        v.exploit_available = bool(w.get("has_proof")) or v.exploit_available
        await db.flush()
        sid = f"{d.id}:{vid}"[:256]
        f = (await db.execute(select(Finding).where(Finding.source == SOURCE, Finding.source_id == sid))).scalar_one_or_none()
        if f is None:
            f = Finding(device_id=str(d.id), vuln_id=str(v.id), source=SOURCE, source_id=sid, domain="infra", first_detected=when)
            db.add(f)
        f.status, f.last_seen = FindingStatus.open, when
        f.first_detected = min(filter(None, [f.first_detected, when]))
        proof = bool(w.get("has_proof"))
        f.is_reachable, f.reachability_source, f.reachability_updated_at = (True if proof else None), SOURCE, when
        f.details = {"has_proof": proof, "context_score": w.get("context_score"), "category": w.get("vuln_category"),
                     "impact_paths": w.get("impact_paths_count"), "where": str(w.get("affected_asset_text") or "")[:300],
                     "ransomware_use": bool(w.get("vuln_known_ransomware_campaign_use")),
                     "pentest": {"id": pentest.get("op_id"), "name": str(pentest.get("name") or "")[:200], "completed_at": when.isoformat()}}
        n += 1
        if proof and cve:   # proved here: the same CVE on this host, from every source, is reachable
            for other in (await db.execute(select(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id).where(
                    Finding.device_id == d.id, Vulnerability.cve_id == cve, Finding.source != SOURCE))).scalars():
                other.is_reachable, other.reachability_source, other.reachability_updated_at = True, SOURCE, when
    open_ports = await _services(db, services, cache, tested) if services is not None else None
    # NodeZero tested these hosts in this pentest: its weaknesses there that it no longer found are gone
    for f in (await db.execute(select(Finding).where(Finding.source == SOURCE, Finding.device_id.in_(list(tested) or ["-"]),
                                                     Finding.status == FindingStatus.open, Finding.last_seen < when))).scalars() if findings else []:
        f.status = FindingStatus.remediated
    if open_ports is not None:
        n += await _closed(db, open_ports, when, pentest)
    if extra:
        extra = {**extra, "services": services or [], "weaknesses": weaknesses}
        await view.apply(db, pentest, when, extra, cache, lambda ip, name: _device(db, ip, name, cache, create=False))
    await db.commit()
    return n


async def _services(db, services, cache, tested) -> dict:
    """device id -> the ports NodeZero found open on it in this pentest."""
    out: dict[str, set] = {}
    for s in services:
        port = s.get("port")
        if not isinstance(port, int) or not 0 < port < 65536:
            continue
        d = await _device(db, s.get("ip"), s.get("host_name"), cache, create=False)   # only assets CTEM knows
        if d is None:
            continue
        tested.add(str(d.id))
        out.setdefault(str(d.id), set()).add(port)
    return out


async def _closed(db, open_ports: dict, when, pentest) -> int:
    """Network findings other sources saw listening on a port NodeZero found closed on a host it tested."""
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    n = 0
    rows = (await db.execute(select(Finding, Vulnerability.attack_vector).join(Vulnerability, Vulnerability.id == Finding.vuln_id).where(
        Finding.device_id.in_(list(open_ports) or ["-"]), Finding.status == FindingStatus.open, Finding.source != SOURCE,
        Finding.exposure == "listening", Finding.ports.is_not(None)))).all()
    for f, av in rows:
        if (av or "network") != "network" or f.reachability_source == SOURCE and f.is_reachable:
            continue   # a local or physical flaw doesn't depend on a port; NodeZero's own proof wins
        ports = {int(p.split("/")[0]) for p in f.ports.split() if p.split("/")[0].isdigit()}
        if not ports:
            continue
        if ports & open_ports[str(f.device_id)]:
            if f.reachability_source == CLOSED:   # open again
                f.is_reachable, f.reachability_source = None, None
            continue
        f.is_reachable, f.reachability_source, f.reachability_updated_at = False, CLOSED, when
        f.details = {**(f.details or {}), "nodezero_closed": {"ports": sorted(ports), "pentest": str(pentest.get("name") or "")[:200],
                                                              "tested_at": when.isoformat()}}
        n += 1
    return n
