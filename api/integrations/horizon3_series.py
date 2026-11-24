"""NodeZero's open weaknesses across every pentest (its "weakness series", api/integrations/horizon3.py).

A weakness series follows one weakness on one host and port from pentest to pentest; NodeZero keeps it OPEN until
a later pentest shows it fixed. CTEM mirrors that: each open series is a finding on its host, whichever pentest last
saw it, and a NodeZero finding whose series is no longer open is closed. NodeZero found it from inside the network,
so the finding is reachable; one it proved by exploiting it is marked proved. Field names were confirmed against
the live API (it doesn't allow schema introspection)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from sqlalchemy import select, update

SOURCE = "horizon3"
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
QUERY = """query q($page_input: PageInput!) { weakness_series_page(page_input: $page_input) { weakness_series {
  uuid vuln_id vuln_name vuln_category severity score ip port protocol status is_open first_seen_at last_seen_at
  last_op_id attack_paths_count affected_asset_short_name vuln { aliases cisa_kev known_ransomware_campaign_use base_score } } } }"""
OPEN = {"filter_by_inputs": [{"field_name": "status", "values": ["OPEN"]}]}
# A pentest's weaknesses it proved by exploiting them: a series stays exploited for as long as it stays open
PROVED_QUERY = """query q($op_id: String!, $page_input: PageInput) { weaknesses_page(input: {op_id: $op_id}, page_input: $page_input) {
  weaknesses { vuln_id ip port created_at time_to_finding_s proofs { proof_type created_at command_outputs { command output } } } } }"""
PROVED = {"filter_by_inputs": [{"field_name": "has_proof", "values": ["true"]}]}


def _dt(v):
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00")) if v else None
    except ValueError:
        return None
    return t.replace(tzinfo=timezone.utc) if t is not None and t.tzinfo is None else t   # NodeZero's times are UTC


def group(series: list[dict]) -> dict:
    """(ip, weakness id) -> one finding's worth: a weakness open on several ports of a host is one finding."""
    out: dict[tuple, dict] = {}
    for s in series:
        vid, ip = str(s.get("vuln_id") or "")[:200], s.get("ip")
        if not vid or not ip or s.get("is_open") is False:
            continue
        g = out.setdefault((ip, vid), {"ip": ip, "vuln_id": vid, "ports": set(), "first": None, "last": None, "paths": 0, "s": s})
        if isinstance(s.get("port"), int) and 0 < s["port"] < 65536:
            g["ports"].add(f"{s['port']}/{str(s.get('protocol') or 'tcp').lower()[:4]}")
        f, la = _dt(s.get("first_seen_at")), _dt(s.get("last_seen_at"))
        g["first"] = min(filter(None, [g["first"], f]), default=None)
        g["last"] = max(filter(None, [g["last"], la]), default=None)
        g["paths"] = max(g["paths"], s.get("attack_paths_count") or 0)
    return out


async def apply(db, series: list[dict], proof: dict, find) -> tuple[int, set]:
    """Write the open series as findings. proof: (ip, weakness id) -> how a pentest proved it (truthy).
    Returns (findings written, their source ids), so the caller can close the rest."""
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    now, n, seen, vulns = datetime.now(timezone.utc), 0, set(), {}
    hit_vulns, hit_cves = set(), set()
    for (ip, vid), g in group(series).items():
        d = await find(ip)
        if d is None:
            continue
        s, va = g["s"], g["s"].get("vuln") or {}
        cves = [a for a in (va.get("aliases") or []) if isinstance(a, str) and _CVE.match(a)]
        cve = vid if _CVE.match(vid) else (cves[0] if cves else None)
        v = vulns.get(vid)
        if v is None:
            v = (await db.execute(select(Vulnerability).where(Vulnerability.source == SOURCE, Vulnerability.source_vuln_id == vid))).scalar_one_or_none()
            if v is None:
                v = Vulnerability(source=SOURCE, source_vuln_id=vid, title=str(s.get("vuln_name") or vid)[:512], domain="infra")
                db.add(v)
            v.title, v.cve_id = str(s.get("vuln_name") or v.title)[:512], cve or v.cve_id
            base = va.get("base_score") if isinstance(va.get("base_score"), (int, float)) else s.get("score")
            if isinstance(base, (int, float)) and 0 <= base <= 10:
                v.cvss_base = float(base)
            v.is_kev = bool(va.get("cisa_kev")) or v.is_kev
            await db.flush()
            vulns[vid] = v
        proved = bool(proof.get((ip, vid)))
        v.exploit_available = proved or v.exploit_available
        if proved:
            hit_vulns.add(v.id)
            if cve:
                hit_cves.add(cve)
        sid = f"{d.id}:{vid}"[:256]
        f = (await db.execute(select(Finding).where(Finding.source == SOURCE, Finding.source_id == sid))).scalar_one_or_none()
        if f is None:
            f = Finding(device_id=str(d.id), vuln_id=str(v.id), source=SOURCE, source_id=sid, domain="infra",
                        first_detected=g["first"] or now)
            db.add(f)
        f.status, f.last_seen = FindingStatus.open, g["last"] or now
        f.first_detected = min(filter(None, [f.first_detected, g["first"]]))
        if g["ports"]:
            f.ports, f.exposure = " ".join(sorted(g["ports"]))[:500], "listening"
        # NodeZero reached it from inside the network: reachable, and proved when it exploited it
        f.is_reachable, f.reachability_source, f.reachability_updated_at = True, SOURCE, now
        f.details = {"has_proof": proved, "category": s.get("vuln_category"), "impact_paths": g["paths"],
                     "where": str(s.get("affected_asset_short_name") or "")[:300], "series": str(s.get("uuid") or "")[:64],
                     "ransomware_use": bool(va.get("known_ransomware_campaign_use")), "last_pentest": str(s.get("last_op_id") or "")[:64],
                     "first_seen": g["first"].isoformat() if g["first"] else None, "last_seen": g["last"].isoformat() if g["last"] else None}
        if isinstance(proof.get((ip, vid)), dict):   # what NodeZero ran and what came back (encrypted with the details)
            f.details = {**f.details, "proof": proof[(ip, vid)]}
        seen.add(sid)
        n += 1
        if cve:   # NodeZero reached this CVE on this host: the same CVE from every other source there is reachable too
            for other in (await db.execute(select(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id).where(
                    Finding.device_id == d.id, Vulnerability.cve_id == cve, Finding.source != SOURCE,
                    Finding.status == FindingStatus.open))).scalars():
                other.is_reachable, other.reachability_source, other.reachability_updated_at = True, SOURCE, now
        if n % 500 == 0:
            await db.commit()
    await mark_exploited(db, hit_vulns, hit_cves)
    await db.commit()
    return n, seen


async def mark_exploited(db, vuln_ids: set, cves: set) -> None:
    """Pentest-exploited, on NodeZero's own entry and on that CVE from every source; cleared once nothing is open."""
    from api.models.vuln import Vulnerability
    await db.execute(update(Vulnerability).where(Vulnerability.pentest_exploited.is_(True)).values(pentest_exploited=False))
    ids = list(vuln_ids)
    for i in range(0, len(ids), 500):
        await db.execute(update(Vulnerability).where(Vulnerability.id.in_(ids[i:i + 500])).values(pentest_exploited=True))
    cl = list(cves)
    for i in range(0, len(cl), 500):
        await db.execute(update(Vulnerability).where(Vulnerability.cve_id.in_(cl[i:i + 500])).values(pentest_exploited=True))


async def close_the_rest(db, seen: set) -> int:
    """NodeZero findings whose weakness series is no longer open: fixed, as NodeZero says."""
    from api.models.vuln import Finding, FindingStatus
    n = 0
    for f in (await db.execute(select(Finding).where(Finding.source == SOURCE, Finding.status == FindingStatus.open))).scalars():
        if f.source_id not in seen:
            f.status, n = FindingStatus.remediated, n + 1
    await db.commit()
    return n
