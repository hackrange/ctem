"""Vulnerability controls: KEV deadlines, remediation SLAs, exposed criticals, attack paths, exceptions."""
from __future__ import annotations

from datetime import datetime, time, timedelta, timezone

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.grc.checks import PENTEST, SCANNERS, Check, Outcome, Threshold, aware, grade_low, now, register
from api.models.device import Device
from api.models.risk import AttackPath, RiskException
from api.models.vuln import Finding, FindingStatus, Vulnerability

MAX_ROWS = 50000
OPEN = (FindingStatus.open, FindingStatus.in_progress)


def _iso(dt) -> str:
    return dt.isoformat() if dt else ""


async def _kev(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    rows = (await db.execute(
        select(Finding, Vulnerability, Device.hostname).join(Vulnerability, Finding.vuln_id == Vulnerability.id)
        .join(Device, Finding.device_id == Device.id)
        .where(Finding.status.in_(OPEN), Vulnerability.is_kev == True))).all()  # noqa: E712
    overdue, pending, out_rows = 0, 0, []
    for f, v, host in rows:
        # The clock starts when we found it or when CISA listed it, whichever is later
        start = aware(f.first_detected) or now()
        if v.kev_added_date:
            start = max(start, datetime.combine(v.kev_added_date, time.min, tzinfo=timezone.utc))
        due = start + timedelta(days=t["due_days"])
        late = due < now()
        overdue += late
        pending += not late
        if detail and len(out_rows) < MAX_ROWS:
            out_rows.append({"hostname": host, "cve_id": v.cve_id, "first_detected": _iso(f.first_detected),
                             "kev_added": _iso(v.kev_added_date), "due": due.date().isoformat(), "overdue": late})
    result = "fail" if overdue > t["warn_max"] else "warning" if overdue or pending else "pass"
    out = Outcome(result, f"{overdue:,} open KEV findings past the {t['due_days']}-day deadline; {pending:,} still inside it",
                  {"open_kev_findings": overdue + pending, "overdue": overdue, "within_deadline": pending})
    if detail:
        out.columns, out.rows = ["hostname", "cve_id", "first_detected", "kev_added", "due", "overdue"], out_rows
    return out


def _sla_breach(t: dict):
    crit_cut, high_cut = now() - timedelta(days=t["critical_days"]), now() - timedelta(days=t["high_days"])
    cond = and_(Finding.status.in_(OPEN), or_(
        and_(Vulnerability.cvss_base >= 9.0, Finding.first_detected < crit_cut),
        and_(Vulnerability.cvss_base >= 7.0, Vulnerability.cvss_base < 9.0, Finding.first_detected < high_cut)))
    if t["reachable_only"]:
        cond = and_(cond, Finding.is_reachable == True)  # noqa: E712
    return cond


async def _sla(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    base = select(func.count()).select_from(Finding).join(Vulnerability, Finding.vuln_id == Vulnerability.id)
    breaches = (await db.execute(base.where(_sla_breach(t)))).scalar_one()
    crit = (await db.execute(base.where(_sla_breach(t), Vulnerability.cvss_base >= 9.0))).scalar_one()
    out = Outcome(grade_low(breaches, 0, t["warn_max"]),
                  f"{breaches:,} open findings past SLA ({crit:,} critical over {t['critical_days']} days, "
                  f"{breaches - crit:,} high over {t['high_days']} days)",
                  {"past_sla": breaches, "critical_past_sla": crit, "high_past_sla": breaches - crit,
                   "reachable_only": bool(t["reachable_only"])})
    if detail:
        found = await db.execute(
            select(Finding, Vulnerability, Device.hostname).join(Vulnerability, Finding.vuln_id == Vulnerability.id)
            .join(Device, Finding.device_id == Device.id).where(_sla_breach(t))
            .order_by(Finding.first_detected).limit(MAX_ROWS))
        out.columns = ["hostname", "cve_id", "cvss", "first_detected", "reachable"]
        out.rows = [{"hostname": h, "cve_id": v.cve_id, "cvss": v.cvss_base, "first_detected": _iso(f.first_detected),
                     "reachable": "unknown" if f.is_reachable is None else f.is_reachable} for f, v, h in found.all()]
    return out


def _exposed_cond():
    return and_(Device.is_internet_exposed == True, Finding.status.in_(OPEN),  # noqa: E712
                or_(Vulnerability.cvss_base >= 9.0, Vulnerability.is_kev == True),  # noqa: E712
                or_(Finding.is_reachable.is_(None), Finding.is_reachable == True))  # noqa: E712


async def _exposed(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    q = (select(func.count(func.distinct(Device.id))).select_from(Finding)
         .join(Vulnerability, Finding.vuln_id == Vulnerability.id).join(Device, Finding.device_id == Device.id)
         .where(_exposed_cond()))
    hosts = (await db.execute(q)).scalar_one()
    exposed = (await db.execute(select(func.count()).select_from(Device).where(Device.is_internet_exposed == True))).scalar_one()  # noqa: E712
    if not exposed:
        # Nothing marked internet-facing means we lack exposure data, not that we're safe
        return Outcome("error", "no devices are marked internet-facing, so external exposure can't be judged")
    out = Outcome(grade_low(hosts, 0, t["warn_max"]),
                  f"{hosts:,} of {exposed:,} internet-facing devices have a critical or KEV finding that isn't ruled unreachable",
                  {"internet_exposed_devices": exposed, "with_exposed_criticals": hosts})
    if detail:
        found = await db.execute(
            select(Device.hostname, Vulnerability.cve_id, Vulnerability.cvss_base, Vulnerability.is_kev)
            .select_from(Finding).join(Vulnerability, Finding.vuln_id == Vulnerability.id)
            .join(Device, Finding.device_id == Device.id).where(_exposed_cond()).order_by(Device.hostname).limit(MAX_ROWS))
        out.columns = ["hostname", "cve_id", "cvss", "kev"]
        out.rows = [{"hostname": h, "cve_id": c, "cvss": s, "kev": k} for h, c, s, k in found.all()]
    return out


async def _paths(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    cond = and_(AttackPath.is_active == True, AttackPath.path_score >= t["min_score"])  # noqa: E712
    n = (await db.execute(select(func.count()).select_from(AttackPath).where(cond))).scalar_one()
    out = Outcome(grade_low(n, 0, t["warn_max"]), f"{n:,} validated attack paths are open (score {t['min_score']}+)",
                  {"open_attack_paths": n})
    if detail:
        found = await db.execute(select(AttackPath).where(cond).order_by(AttackPath.path_score.desc()).limit(MAX_ROWS))
        out.columns = ["path", "score", "confirmed_by", "last_seen"]
        out.rows = [{"path": (p.path_description or "")[:500], "score": p.path_score, "confirmed_by": p.confirmed_by or "",
                     "last_seen": _iso(p.last_seen)} for p in found.scalars()]
    return out


async def _exceptions(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    active = (await db.execute(select(RiskException).where(RiskException.is_active == True))).scalars().all()  # noqa: E712
    expired = [e for e in active if not e.is_permanent and e.expires_at and aware(e.expires_at) < now()]
    permanent = [e for e in active if e.is_permanent]
    result = "fail" if expired else "warning" if len(permanent) > t["permanent_max"] else "pass"
    out = Outcome(result, f"{len(active):,} active risk exceptions: {len(expired):,} past expiry, {len(permanent):,} permanent",
                  {"active": len(active), "expired_still_active": len(expired), "permanent": len(permanent)})
    if detail:
        out.columns = ["cve_id", "approved_at", "expires_at", "permanent", "expired"]
        out.rows = [{"cve_id": e.cve_id or "", "approved_at": _iso(e.approved_at), "expires_at": _iso(e.expires_at),
                     "permanent": e.is_permanent, "expired": e in expired} for e in active][:MAX_ROWS]
    return out


register(Check(
    "ctem_kev_remediation", "CISA KEV remediation", "Open known-exploited vulnerabilities past their deadline", 1, SCANNERS,
    ("NIST CSF ID.RA-01", "CIS 7.7", "ISO 27001 A.8.8", "PCI DSS 6.3.3", "CISA BOD 22-01"),
    {"due_days": Threshold(14, 1, 180, "days from detection (or KEV listing) to fix"),
     "warn_max": Threshold(0, 0, 1000, "overdue findings tolerated as a warning instead of a fail")}, _kev))

register(Check(
    "ctem_vuln_sla", "Vulnerability remediation SLA", "Critical and high findings open longer than their SLA", 1, SCANNERS,
    ("ISO 27001 A.8.8", "CIS 7.3", "NIST 800-53 RA-5", "NIST 800-53 SI-2", "PCI DSS 6.3.3"),
    {"critical_days": Threshold(15, 1, 365, "SLA for CVSS 9.0+"), "high_days": Threshold(30, 1, 365, "SLA for CVSS 7.0-8.9"),
     "warn_max": Threshold(5, 0, 100000, "breaches tolerated as a warning"),
     "reachable_only": Threshold(0, 0, 1, "1 = only count findings validated as reachable")}, _sla))

register(Check(
    "ctem_exposed_criticals", "Internet-facing critical exposure", "Internet-facing devices with critical or KEV findings", 1,
    SCANNERS, ("NIST CSF PR.IR-01", "CIS 12", "ISO 27001 A.8.20", "PCI DSS 11.3"),
    {"warn_max": Threshold(0, 0, 10000, "devices tolerated as a warning")}, _exposed))

register(Check(
    "ctem_attack_paths", "Validated attack paths", "Open attack paths confirmed by pentest (Horizon3 NodeZero)", 1, PENTEST,
    ("NIST CSF ID.RA-05", "ISO 27001 A.8.8", "PCI DSS 11.4"),
    {"min_score": Threshold(0, 0, 100, "only count paths at or above this score"),
     "warn_max": Threshold(0, 0, 10000, "paths tolerated as a warning")}, _paths, max_age_hours=24 * 30))

register(Check(
    "ctem_risk_exceptions", "Risk exception hygiene", "Accepted vulnerabilities past expiry, and permanent acceptances", 1, (),
    ("ISO 27001 6.1.3", "NIST CSF GV.RM", "SOC 2 CC3.2"),
    {"permanent_max": Threshold(0, 0, 10000, "permanent exceptions tolerated before a warning")}, _exceptions))
