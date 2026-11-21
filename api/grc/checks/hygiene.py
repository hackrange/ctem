"""Inventory hygiene: records tools keep for machines nobody sees, AD objects no tool knows, machines on the
network whose EDR has gone quiet, and live machines the scanner has missed. Each lists what to fix and where."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.device_match import SOURCE_CODES
from api.grc.checks import DIRECTORY, EDR, SCANNERS, Check, Outcome, Threshold, now, pct, register
from api.grc.checks.endpoint import MAX_ROWS, _count, _row
from api.models.device import Device, DeviceType
from api.rules.apply import device_scope

STALE = 21   # days without a scan, an EDR heartbeat or a directory logon before a record counts as stale
# Tool categories, each any of its vendors (Rapid7, Qualys or Tanium scan; CrowdStrike, SentinelOne or Defender EDR...)
_KINDS = (("scanner", SCANNERS), ("EDR", EDR), ("directory", DIRECTORY))
_ALL = tuple(dict.fromkeys(v for _, vendors in _KINDS for v in vendors))


def _holds(code: str):
    return func.coalesce(Device.sources, "").contains(f",{code},")


def _holds_any(vendors) -> object:
    return or_(*(_holds(v) for v in vendors))


def _still_in(d: Device) -> str:
    """The vendors that still list this device, by their short codes (R7, CS, S1, QL, AD...)."""
    have = [s for s in (d.sources or "").split(",") if s in _ALL]
    return " ".join(SOURCE_CODES.get(s, s) for s in have)


def _iso(v) -> str:
    return v.isoformat() if v else "never"


def _quiet(cut):
    """No sign of life from any tool since `cut` (NULL counts as never)."""
    return and_(*(or_(col.is_(None), col < cut) for col in (Device.last_seen, Device.edr_last_seen, Device.ad_last_logon)))


def _grade(bad: int, total: int, fail_pct: int) -> tuple[str, float]:
    p = pct(bad, total)
    return ("pass" if bad == 0 else "warning" if p <= fail_pct else "fail"), p


async def _stale_records(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    held = and_(_holds_any(_ALL), device_scope())
    total = await _count(db, held)
    if not total:
        return Outcome("error", "no device records from a scanner, EDR or directory in CTEM")
    stale_q = and_(held, _quiet(now() - timedelta(days=t["stale_days"])))
    stale = await _count(db, stale_q)
    per = {label: await _count(db, stale_q, _holds_any(vendors)) for label, vendors in _KINDS}
    result, p = _grade(stale, total, t["fail_pct"])
    where = ", ".join(f"{k} {v:,}" for k, v in per.items() if v) or "none"
    out = Outcome(result, f"{stale:,} of {total:,} device records ({p}%) have had no sign of life in {t['stale_days']} days "
                          f"but are still listed in a tool ({where})",
                  {"records": total, "stale": stale, "stale_pct": p, **{f"stale_in_{k.lower()}": v for k, v in per.items()}})
    if detail:
        out.columns = ["hostname", "os", "device_type", "still_in", "scanner_last_seen", "edr_last_seen", "ad_last_logon"]
        found = await db.execute(select(Device).where(stale_q).order_by(Device.hostname).limit(MAX_ROWS))
        out.rows = [{**_row(d), "still_in": _still_in(d),
                     "scanner_last_seen": _iso(d.last_seen), "edr_last_seen": _iso(d.edr_last_seen),
                     "ad_last_logon": _iso(d.ad_last_logon)} for d in found.scalars()]
    return out


async def _orphan_ad(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    """Directory (AD) computer objects with no logon in N days that no scanner or EDR has ever reported."""
    joined = and_(Device.ad_joined == True, device_scope())  # noqa: E712
    total = await _count(db, joined)
    if not total:
        return Outcome("error", "no directory (AD) computer objects in CTEM")
    cut = now() - timedelta(days=t["stale_days"])
    no_other_tool = ~_holds_any(SCANNERS + EDR)
    orphan_q = and_(joined, no_other_tool, or_(Device.ad_last_logon.is_(None), Device.ad_last_logon < cut))
    n = await _count(db, orphan_q)
    result, p = _grade(n, total, t["fail_pct"])
    out = Outcome(result, f"{n:,} of {total:,} directory computers ({p}%) haven't logged on in {t['stale_days']} days "
                          "and no scanner or EDR has ever reported them", {"ad_computers": total, "orphaned": n, "orphaned_pct": p})
    if detail:
        out.columns = ["hostname", "os", "ad_last_logon", "ad_dn"]
        found = await db.execute(select(Device).where(orphan_q).order_by(Device.hostname).limit(MAX_ROWS))
        out.rows = [{**_row(d), "ad_last_logon": _iso(d.ad_last_logon), "ad_dn": d.ad_dn or ""} for d in found.scalars()]
    return out


async def _edr_silent(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    """Workstations and servers the scanner saw recently whose EDR agent hasn't checked in for N days:
    on the network, but probably not getting EDR policy or protection."""
    seen_cut, edr_cut = now() - timedelta(days=t["scan_within_days"]), now() - timedelta(days=t["edr_silent_days"])
    base = and_(Device.device_type.in_([DeviceType.workstation, DeviceType.server]), Device.last_seen >= seen_cut,
                Device.edr_last_seen.is_not(None), device_scope())
    total = await _count(db, base)
    if not total:
        return Outcome("error", f"no workstations or servers with an EDR record were scanned in the last {t['scan_within_days']} days")
    silent_q = and_(base, Device.edr_last_seen < edr_cut)
    n = await _count(db, silent_q)
    result, p = _grade(n, total, t["fail_pct"])
    out = Outcome(result, f"{n:,} of {total:,} devices scanned in the last {t['scan_within_days']} days ({p}%) have an EDR "
                          f"agent that hasn't checked in for {t['edr_silent_days']} days",
                  {"scanned_with_edr": total, "edr_silent": n, "edr_silent_pct": p})
    if detail:
        out.columns = ["hostname", "os", "device_type", "scanner_last_seen", "edr_last_seen", "edr_hidden", "sources"]
        found = await db.execute(select(Device).where(silent_q).order_by(Device.edr_last_seen).limit(MAX_ROWS))
        out.rows = [{**_row(d), "scanner_last_seen": _iso(d.last_seen), "edr_last_seen": _iso(d.edr_last_seen),
                     "edr_hidden": "yes" if d.edr_hidden else "no"} for d in found.scalars()]
    return out


async def _scan_gap(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    """Workstations and servers that are alive (an EDR heartbeat or a directory logon recently) but the vulnerability
    scanner hasn't seen in N days, or ever: a scanner, agent or credential failure, or a gap in scan coverage."""
    alive_cut, scan_cut = now() - timedelta(days=t["alive_within_days"]), now() - timedelta(days=t["scan_stale_days"])
    base = and_(Device.device_type.in_([DeviceType.workstation, DeviceType.server]),
                or_(Device.edr_last_seen >= alive_cut, Device.ad_last_logon >= alive_cut), device_scope())
    total = await _count(db, base)
    if not total:
        return Outcome("error", f"no workstations or servers checked in with EDR or the directory in the last {t['alive_within_days']} days")
    gap_q = and_(base, or_(Device.last_seen.is_(None), Device.last_seen < scan_cut))
    n = await _count(db, gap_q)
    never = await _count(db, gap_q, Device.last_seen.is_(None))
    result, p = _grade(n, total, t["fail_pct"])
    out = Outcome(result, f"{n:,} of {total:,} active devices ({p}%) haven't been scanned in {t['scan_stale_days']} days "
                          f"({never:,} never)", {"active": total, "scan_gap": n, "never_scanned": never, "scan_gap_pct": p})
    if detail:
        out.columns = ["hostname", "os", "device_type", "scanner_last_seen", "edr_last_seen", "ad_last_logon", "sources"]
        found = await db.execute(select(Device).where(gap_q).order_by(Device.hostname).limit(MAX_ROWS))
        out.rows = [{**_row(d), "scanner_last_seen": _iso(d.last_seen), "edr_last_seen": _iso(d.edr_last_seen),
                     "ad_last_logon": _iso(d.ad_last_logon)} for d in found.scalars()]
    return out


_FAIL = Threshold(2, 0, 100, "fail when more than this % are flagged")

register(Check(
    "ctem_stale_tool_records", "Stale records in security tools",
    "Devices still listed in a scanner, EDR or directory that no tool has seen in N days (retire them there)", 1,
    SCANNERS + EDR + DIRECTORY, ("CIS 1.1", "CIS 1.2", "NIST CSF ID.AM-01", "ISO 27001 A.5.9"),
    {"stale_days": Threshold(STALE, 7, 365, "no scan, EDR heartbeat or directory logon for this many days counts as stale"),
     "fail_pct": _FAIL}, _stale_records, device_scoped=True))

register(Check(
    "ctem_orphan_ad_computers", "Stale directory computers in no other tool",
    "Directory (AD) computer objects with no logon in N days that no scanner or EDR has ever reported (disable or delete them)", 1,
    DIRECTORY, ("CIS 1.1", "CIS 5.3", "NIST CSF ID.AM-01", "ISO 27001 A.5.9"),
    {"stale_days": Threshold(STALE, 7, 365, "no directory logon for this many days counts as stale"), "fail_pct": _FAIL},
    _orphan_ad, device_scoped=True))

register(Check(
    "ctem_edr_silent_on_network", "On the network, EDR silent",
    "Workstations and servers the scanner saw recently whose EDR agent hasn't checked in for N days", 1,
    EDR, ("CIS 10.1", "NIST CSF DE.CM-01", "ISO 27001 A.8.7", "SOC 2 CC6.8"),
    {"scan_within_days": Threshold(7, 1, 30, "the scanner saw it within this many days"),
     "edr_silent_days": Threshold(STALE, 3, 180, "the EDR agent hasn't checked in for this many days"),
     "fail_pct": Threshold(1, 0, 100, "fail when more than this % are silent")}, _edr_silent, device_scoped=True))

register(Check(
    "ctem_scan_gap", "Active, not scanned",
    "Workstations and servers alive in EDR or the directory that the vulnerability scanner hasn't seen in N days, or ever", 1,
    SCANNERS, ("CIS 7.5", "CIS 7.6", "NIST CSF ID.RA-01", "ISO 27001 A.8.8"),
    {"alive_within_days": Threshold(7, 1, 30, "an EDR heartbeat or directory logon within this many days counts as active"),
     "scan_stale_days": Threshold(STALE, 3, 180, "not scanned for this many days counts as a gap"),
     "fail_pct": Threshold(5, 0, 100, "fail when more than this % have a gap")}, _scan_gap, device_scoped=True))
