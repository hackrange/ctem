"""Reachable, not scanned: internal addresses another tool reached recently (an autonomous pentest, a cloud inventory,
the shipper's network probe) that no vulnerability scanner covers. A pentest finding something on a host the
scanner has never seen (a PHP server only NodeZero knows) is exactly the gap this lists, worst first."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.grc.checks import SCANNERS, Check, Outcome, Threshold, now, pct, register
from api.models.cloud import CloudAsset
from api.models.device import Device, NON_HOST_TYPES
from api.models.vuln import Finding, FindingStatus
from api.rules.apply import device_scope

MAX_ROWS = 5000
# Tools that reach hosts without managing them, by kind (any of each kind's vendors)
REACHERS = {"pentest": ("horizon3",), "cloud inventory": ("aws", "oci", "azure"), "network probe": ("netprobe",)}
_ALL = tuple(v for vs in REACHERS.values() for v in vs)


def _holds(code: str):
    return func.coalesce(Device.sources, "").contains(f",{code},")


def _reached_since(cut):
    """Some tool reached it since `cut`: a pentest finding seen, a cloud inventory row, or a probe answer."""
    pentest = exists(select(Finding.id).where(Finding.device_id == Device.id, Finding.source.in_(REACHERS["pentest"]),
                                              Finding.last_seen >= cut))
    cloud = exists(select(CloudAsset.id).where(CloudAsset.device_id == Device.id, CloudAsset.seen_at >= cut))
    return or_(pentest, cloud, Device.alive_at >= cut)


def _known_by(d: Device) -> str:
    have = {s for s in (d.sources or "").split(",") if s}
    return ", ".join(k for k, vs in REACHERS.items() if have & set(vs)) or "another tool"


async def _unscanned(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    cut, scan_cut = now() - timedelta(days=t["reached_within_days"]), now() - timedelta(days=t["scan_stale_days"])
    internal = and_(Device.subnet_hash.is_not(None), Device.device_type.not_in(NON_HOST_TYPES), device_scope())
    base = and_(internal, or_(*(_holds(v) for v in _ALL)), _reached_since(cut))
    total = (await db.execute(select(func.count()).select_from(Device).where(base))).scalar_one()
    if not total:
        return Outcome("error", f"no internal host was reached by a pentest, cloud inventory or network probe in the last {t['reached_within_days']} days")
    scanned = or_(*(_holds(v) for v in SCANNERS))
    gap = and_(base, or_(~scanned, Device.last_seen.is_(None), Device.last_seen < scan_cut))
    n = (await db.execute(select(func.count()).select_from(Device).where(gap))).scalar_one()
    risky = (await db.execute(select(func.count()).select_from(Device).where(gap, Device.open_findings > 0))).scalar_one()
    p = pct(n, total)
    result = "pass" if n == 0 else "warning" if p <= t["fail_pct"] and not risky else "fail"
    out = Outcome(result, f"{n:,} of {total:,} reachable internal hosts ({p}%) aren't covered by a vulnerability scanner; "
                          f"{risky:,} of them already have open findings from the tool that reached them",
                  {"reachable": total, "unscanned": n, "unscanned_pct": p, "unscanned_with_findings": risky})
    if detail:
        out.columns = ["ip", "hostname", "device_type", "known_by", "open_findings", "kev_findings", "top_finding", "scanner_last_seen"]
        rows = (await db.execute(select(Device).where(gap).order_by(Device.kev_findings.desc(), Device.open_findings.desc(),
                                                                    Device.hostname).limit(MAX_ROWS))).scalars().all()
        top = {}
        if rows:
            from api.models.vuln import Vulnerability
            q = (select(Finding.device_id, Vulnerability.title, Vulnerability.cvss_base)
                 .join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                 .where(Finding.device_id.in_([d.id for d in rows]), Finding.status.in_((FindingStatus.open, FindingStatus.in_progress))))
            for did, title, score in (await db.execute(q)).all():
                if did not in top or (score or 0) > top[did][1]:
                    top[did] = (title, score or 0)
        out.rows = [{"device_id": str(d.id), "ip": d.ip or "", "hostname": d.hostname, "device_type": d.device_type.value if d.device_type else "",
                     "known_by": _known_by(d), "open_findings": d.open_findings or 0, "kev_findings": d.kev_findings or 0,
                     "top_finding": (top.get(d.id) or ("", 0))[0][:200],
                     "scanner_last_seen": d.last_seen.isoformat() if d.last_seen and any(f",{s}," in (d.sources or "") for s in SCANNERS) else "never"}
                    for d in rows]
    return out


register(Check(
    "ctem_reachable_unscanned", "Reachable, not scanned",
    "Internal hosts a pentest, cloud inventory or the network probe reached recently that no vulnerability scanner covers "
    "(add them to scan scope; fail at once when any of them already has open findings)", 1,
    SCANNERS, ("CIS 1.1", "CIS 7.5", "CIS 7.6", "NIST CSF ID.AM-01", "NIST CSF ID.RA-01", "ISO 27001 A.8.8"),
    {"reached_within_days": Threshold(30, 1, 365, "a pentest, cloud inventory or probe reached it within this many days"),
     "scan_stale_days": Threshold(21, 3, 180, "not scanned for this many days counts as uncovered"),
     "fail_pct": Threshold(2, 0, 100, "fail when more than this % are uncovered (any with open findings fails)")},
    _unscanned, device_scoped=True))
