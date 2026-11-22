"""Vulnerability age: how long open findings have been waiting, for Infrastructure, Code and Web apps.

Age is days from when the source first found a finding until today. By default each finding is held to the
install's SLA for its severity (Vulnerabilities > Change SLAs), so lowering the SLAs tightens this check too; a flat
ceiling (max_age_days) can replace them. The result grades the share of open findings that are too old, and the
evidence keeps the age profile (buckets, oldest, by severity and type) for trends and dashboards."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.device_scope_exempt import in_scope
from api.grc.checks import SCANNERS, Check, Outcome, Threshold, now, register
from api.models.device import Device
from api.models.vuln import Finding, FindingStatus, Vulnerability
from api.rules.apply import device_scope

MAX_ROWS = 50000
OPEN = (FindingStatus.open, FindingStatus.in_progress)
SOURCES = SCANNERS + ("rapid7_appsec", "github_code_review", "snyk")   # hosts, web apps and code
SEVERITIES = ("critical", "high", "medium", "low")
CUT = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.0}
TYPES = {0: None, 1: "infra", 2: "code", 3: "web"}
BUCKETS = ((0, 30, "0-30"), (31, 90, "31-90"), (91, 180, "91-180"), (181, 365, "181-365"), (366, None, "365+"))


def _sev():
    c = func.coalesce(Vulnerability.cvss_base, 0.0)
    return case((c >= 9.0, "critical"), (c >= 7.0, "high"), (c >= 4.0, "medium"), else_="low")


def _included(t: dict) -> list[str]:
    """min_severity: 4 critical only, 3 high and up, 2 medium and up, 1 everything."""
    return list(SEVERITIES[:max(1, min(4, 5 - t["min_severity"]))])


def _limits(t: dict) -> dict[str, int]:
    """Days allowed per included severity: the install's SLAs, or one flat ceiling."""
    from api.core.sla import current
    sla = current()
    return {s: (t["max_age_days"] or sla[s]) for s in _included(t)}


def _base(t: dict) -> list:
    cond = [Finding.status.in_(OPEN), Finding.first_detected.is_not(None), device_scope(), in_scope(),
            func.coalesce(Vulnerability.cvss_base, 0.0) >= CUT[_included(t)[-1]]]
    if TYPES.get(t["type"]):
        cond.append(Finding.domain == TYPES[t["type"]])
    if t["reachable_only"]:
        cond.append(Finding.is_reachable == True)  # noqa: E712
    return cond


def _too_old(limits: dict[str, int]):
    n, sev = now(), _sev()
    return or_(*[and_(sev == s, Finding.first_detected < n - timedelta(days=d)) for s, d in limits.items()])


async def _age(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    limits = _limits(t)
    old, n, sev = _too_old(limits), now(), _sev()
    agg = [func.count(), func.count().filter(old), func.min(Finding.first_detected)]
    agg += [func.count().filter(old, sev == s) for s in limits]
    agg += [func.count().filter(old, Finding.domain == d) for d in ("infra", "code", "web")]
    agg += [func.count().filter(Finding.first_detected <= n - timedelta(days=lo),
                                *([Finding.first_detected > n - timedelta(days=hi + 1)] if hi else []))
            for lo, hi, _ in BUCKETS]
    r = (await db.execute(select(*agg).select_from(Finding).join(Vulnerability, Finding.vuln_id == Vulnerability.id)
                          .join(Device, Finding.device_id == Device.id).where(*_base(t)))).one()
    total, aged, oldest = r[0], r[1], r[2]
    i = 3
    by_sev = {s: r[i + k] for k, s in enumerate(limits)}
    i += len(limits)
    by_type = {d: r[i + k] for k, d in enumerate(("infra", "code", "web"))}
    i += 3
    buckets = {label: r[i + k] for k, (_, _, label) in enumerate(BUCKETS)}
    from api.core.finding_age import days as age_days
    oldest_days = age_days(oldest)
    pct = round(aged * 100.0 / total, 2) if total else 0.0
    result = "pass" if pct <= t["pass_max_pct"] and (aged == 0 or t["pass_max_pct"] > 0) else \
        "warning" if pct <= t["warn_max_pct"] else "fail"
    rule = (f"older than {t['max_age_days']} days" if t["max_age_days"]
            else "older than their SLA (" + ", ".join(f"{s} {d}d" for s, d in limits.items()) + ")")
    summary = (f"{aged:,} of {total:,} open findings ({pct:g}%) are {rule}"
               + (f"; the oldest is {oldest_days:,} days old" if oldest_days is not None else ""))
    out = Outcome(result, summary, {
        "open_findings": total, "too_old": aged, "too_old_pct": pct, "oldest_days": oldest_days,
        "limits_days": limits, "uses_install_sla": not t["max_age_days"], "too_old_by_severity": by_sev,
        "too_old_by_type": by_type, "age_buckets_days": buckets, "type": TYPES.get(t["type"]) or "all",
        "reachable_only": bool(t["reachable_only"])})
    if detail:
        found = (await db.execute(
            select(Finding, Vulnerability, Device.hostname).join(Vulnerability, Finding.vuln_id == Vulnerability.id)
            .join(Device, Finding.device_id == Device.id).where(*_base(t), old)
            .order_by(Finding.first_detected).limit(MAX_ROWS))).all()
        out.columns = ["hostname", "type", "cve_id", "title", "severity", "first_detected", "age_days", "allowed_days"]
        from api.core.finding_age import severity
        out.rows = [{"device_id": str(f.device_id), "hostname": h, "type": f.domain, "cve_id": v.cve_id,
                     "title": (v.title or "")[:200], "severity": severity(v.cvss_base),
                     "first_detected": f.first_detected.isoformat() if f.first_detected else "",
                     "age_days": age_days(f.first_detected), "allowed_days": limits.get(severity(v.cvss_base))}
                    for f, v, h in found]
    return out


register(Check(
    "ctem_vuln_age", "Vulnerability age",
    "Open findings older than allowed, for Infrastructure, Code and Web apps (the install's SLAs by default)", 1,
    SOURCES, ("NIST 800-53 SI-2", "NIST 800-53 RA-5", "ISO 27001 A.8.8", "CIS 7.2", "PCI DSS 6.3.3", "NIST CSF ID.RA-01"),
    {"min_severity": Threshold(2, 1, 4, "lowest severity counted: 4 critical, 3 high, 2 medium, 1 low"),
     "max_age_days": Threshold(0, 0, 3650, "0 = each severity's SLA from Change SLAs; otherwise one ceiling in days"),
     "pass_max_pct": Threshold(0, 0, 100, "percent of open findings allowed too old and still pass"),
     "warn_max_pct": Threshold(5, 0, 100, "percent allowed too old as a warning; above it fails"),
     "type": Threshold(0, 0, 3, "0 all, 1 Infrastructure, 2 Code, 3 Web apps"),
     "reachable_only": Threshold(0, 0, 1, "1 = only count findings validated as reachable")}, _age, device_scoped=True))
