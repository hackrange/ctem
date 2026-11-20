"""Endpoint controls: EDR coverage, host hardening, asset inventory, stale AD computers."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.grc.checks import (
    DIRECTORY, EDR, HARDENING, Check, Outcome, Threshold, grade_high, now, pct, register,
)
from api.models.device import Device
from api.rules.apply import device_scope

MAX_ROWS = 50000
_ACTIVE = Threshold(30, 1, 365, "a device counts as active if any source saw it within this many days")


def _active(days: int):
    cut = now() - timedelta(days=days)
    return and_(or_(Device.last_seen >= cut, Device.edr_last_seen >= cut, Device.ad_last_logon >= cut), device_scope())


def _row(d: Device) -> dict:
    return {"device_id": str(d.id), "hostname": d.hostname, "os": d.os or "", "device_type": d.device_type.value if d.device_type else "",
            "last_seen": d.last_seen.isoformat() if d.last_seen else "", "sources": (d.sources or "").strip(",")}


async def _count(db: AsyncSession, *where) -> int:
    return (await db.execute(select(func.count()).select_from(Device).where(*where))).scalar_one()


async def _rows(db: AsyncSession, *where) -> list[dict]:
    found = await db.execute(select(Device).where(*where).order_by(Device.hostname).limit(MAX_ROWS))
    return [_row(d) for d in found.scalars()]


async def _edr(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    active = _active(t["active_days"])
    total = await _count(db, active)
    covered = await _count(db, active, Device.edr_active == True)  # noqa: E712
    if not total:
        return Outcome("error", "no active devices in CTEM, so coverage can't be measured")
    p = pct(covered, total)
    out = Outcome(grade_high(p, t["pass_at"], t["warn_at"]),
                  f"{p}% of active devices have healthy EDR ({covered:,} of {total:,})",
                  {"active_devices": total, "with_edr": covered, "without_edr": total - covered, "coverage_pct": p})
    if detail:
        out.columns = ["hostname", "os", "device_type", "last_seen", "sources"]
        out.rows = await _rows(db, active, Device.edr_active == False)  # noqa: E712
    return out


async def _hardening(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    active = _active(t["active_days"])
    fw_known = await _count(db, active, Device.firewall_enabled.isnot(None))
    usb_known = await _count(db, active, Device.usb_storage_blocked.isnot(None))
    if not fw_known and not usb_known:
        return Outcome("error", "no firewall or USB-storage telemetry for active devices")
    fw_on = await _count(db, active, Device.firewall_enabled == True)  # noqa: E712
    usb_on = await _count(db, active, Device.usb_storage_blocked == True)  # noqa: E712
    fw_p, usb_p = pct(fw_on, fw_known), pct(usb_on, usb_known)
    worst = min(p for p, known in ((fw_p, fw_known), (usb_p, usb_known)) if known)
    out = Outcome(grade_high(worst, t["pass_at"], t["warn_at"]),
                  f"host firewall on {fw_p}% of {fw_known:,} devices; USB storage blocked on {usb_p}% of {usb_known:,}",
                  {"firewall_known": fw_known, "firewall_enabled": fw_on, "firewall_pct": fw_p,
                   "usb_known": usb_known, "usb_blocked": usb_on, "usb_pct": usb_p})
    if detail:
        out.columns = ["hostname", "os", "device_type", "last_seen", "sources", "firewall_enabled", "usb_storage_blocked"]
        found = await db.execute(select(Device).where(active, or_(Device.firewall_enabled == False,  # noqa: E712
                                 Device.usb_storage_blocked == False)).order_by(Device.hostname).limit(MAX_ROWS))  # noqa: E712
        out.rows = [{**_row(d), "firewall_enabled": d.firewall_enabled, "usb_storage_blocked": d.usb_storage_blocked}
                    for d in found.scalars()]
    return out


async def _inventory(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    active = _active(t["active_days"])
    total = await _count(db, active)
    if not total:
        return Outcome("error", "no active devices in CTEM")
    owned = await _count(db, active, Device.owner_user_id.isnot(None), Device.criticality.isnot(None))
    # ",ldap," has two commas; anything with three or more was seen by more than one feed
    single = await _count(db, active, or_(Device.sources.is_(None), func.length(Device.sources)
                                          - func.length(func.replace(Device.sources, ",", "")) <= 2))
    p = pct(owned, total)
    out = Outcome(grade_high(p, t["pass_at"], t["warn_at"]),
                  f"{p}% of active devices have an owner and a criticality ({owned:,} of {total:,}); "
                  f"{single:,} seen by only one source",
                  {"active_devices": total, "owned_and_rated": owned, "coverage_pct": p, "single_source": single})
    if detail:
        out.columns = ["hostname", "os", "device_type", "last_seen", "sources", "missing"]
        found = await db.execute(select(Device).where(active, or_(Device.owner_user_id.is_(None),
                                 Device.criticality.is_(None))).order_by(Device.hostname).limit(MAX_ROWS))
        out.rows = [{**_row(d), "missing": ", ".join(m for m, v in (("owner", d.owner_user_id), ("criticality", d.criticality))
                                                     if not v)} for d in found.scalars()]
    return out


async def _stale_ad(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    joined = and_(Device.ad_joined == True, device_scope())  # noqa: E712
    total = await _count(db, joined)
    if not total:
        return Outcome("error", "no AD computer objects in CTEM")
    cut = now() - timedelta(days=t["stale_days"])
    stale_q = and_(joined, or_(Device.ad_last_logon.is_(None), Device.ad_last_logon < cut))
    stale = await _count(db, stale_q)
    p = pct(stale, total)
    result = "pass" if stale == 0 else "warning" if p <= t["fail_pct"] else "fail"
    out = Outcome(result, f"{stale:,} of {total:,} AD computers ({p}%) haven't logged on in {t['stale_days']} days",
                  {"ad_computers": total, "stale": stale, "stale_pct": p})
    if detail:
        out.columns = ["hostname", "os", "device_type", "last_seen", "sources", "ad_last_logon"]
        found = await db.execute(select(Device).where(stale_q).order_by(Device.hostname).limit(MAX_ROWS))
        out.rows = [{**_row(d), "ad_last_logon": d.ad_last_logon.isoformat() if d.ad_last_logon else "never"}
                    for d in found.scalars()]
    return out


register(Check(
    "ctem_edr_coverage", "EDR coverage", "Share of active devices with a healthy EDR agent", 1, EDR,
    ("NIST CSF DE.CM-01", "CIS 10.1", "ISO 27001 A.8.7", "SOC 2 CC6.8"),
    {"pass_at": Threshold(98, 50, 100, "pass at or above this %"), "warn_at": Threshold(90, 0, 100, "warning at or above this %"),
     "active_days": _ACTIVE}, _edr, device_scoped=True))

register(Check(
    "ctem_host_hardening", "Host firewall and USB storage", "Host firewall on and USB mass storage blocked", 1, HARDENING,
    ("CIS 4.4", "CIS 4.5", "CIS 10.3", "ISO 27001 A.8.9"),
    {"pass_at": Threshold(98, 50, 100, "pass at or above this %"), "warn_at": Threshold(90, 0, 100, "warning at or above this %"),
     "active_days": _ACTIVE}, _hardening, device_scoped=True))

register(Check(
    "ctem_asset_inventory", "Asset inventory ownership", "Active devices with an owner and a criticality", 1, DIRECTORY + EDR,
    ("CIS 1.1", "NIST CSF ID.AM-01", "ISO 27001 A.5.9", "SOC 2 CC6.1"),
    {"pass_at": Threshold(95, 50, 100, "pass at or above this %"), "warn_at": Threshold(80, 0, 100, "warning at or above this %"),
     "active_days": _ACTIVE}, _inventory, device_scoped=True))

register(Check(
    "ctem_stale_ad_computers", "Stale AD computer accounts", "AD computer objects with no logon in N days", 1, DIRECTORY,
    ("CIS 1.1", "CIS 5.3", "ISO 27001 A.5.9"),
    {"stale_days": Threshold(90, 30, 365, "no logon for this many days counts as stale"),
     "fail_pct": Threshold(2, 0, 100, "fail when more than this % are stale")}, _stale_ad, device_scoped=True))
