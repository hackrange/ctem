"""Identity controls: dormant and privileged accounts, password policy, ITDR alerts, shadow AI/SaaS."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import and_, func, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from api.grc.checks import DIRECTORY, IDENTITY, SHADOW, Check, Outcome, Threshold, aware, grade_low, now, register
from api.models.identity import IdentityThreat, ItdrAlertStatus, SaasAppRecord
from api.models.user import User

MAX_ROWS = 50000
PRIVILEGED = ("domain admins", "enterprise admins", "schema admins", "administrators", "account operators",
              "backup operators", "server operators", "print operators", "dnsadmins", "group policy creator owners")


def _iso(dt) -> str:
    return dt.isoformat() if dt else ""


def _directory_user():
    return and_(User.is_local == False, User.ad_dn.isnot(None))  # noqa: E712


def _enabled():
    return or_(User.ad_disabled.is_(None), User.ad_disabled == False)  # noqa: E712


def _person():
    return and_(_directory_user(), _enabled(), User.is_service_account == False)  # noqa: E712


async def _count(db, *where) -> int:
    return (await db.execute(select(func.count()).select_from(User).where(*where))).scalar_one()


def _name(u) -> str:
    return u.ad_username or u.username


def _like(pattern: str) -> str:
    """An account glob (* and ?) as a case-insensitive LIKE pattern, with LIKE's own wildcards taken literally."""
    p = pattern.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return p.replace("*", "%").replace("?", "_")


def _groups(t: dict) -> list[tuple[str, object, int]]:
    """(label, which accounts, idle days): each account override in order (first match wins), then everyone else."""
    name = func.lower(func.coalesce(User.ad_username, User.username))
    out, taken = [], []
    for o in t.get("_account_overrides") or []:
        m = or_(*(name.like(_like(p), escape="\\") for p in o["name_patterns"]))
        out.append((", ".join(o["name_patterns"]), and_(m, *[~x for x in taken]), o["thresholds"]["idle_days"]))
        taken.append(m)
    out.append(("other accounts" if taken else "", and_(*[~x for x in taken]) if taken else true(), t["idle_days"]))
    return out


async def _dormant(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    total = await _count(db, _person())
    if not total:
        return Outcome("error", "no enabled directory accounts in CTEM")
    groups, idle, never, parts, by = _groups(t), [], [], [], {}
    for label, who, days in groups:
        cut = now() - timedelta(days=days)
        i = and_(_person(), who, User.ad_last_logon < cut)
        nv = and_(_person(), who, User.ad_last_logon.is_(None), User.created_at < cut.replace(tzinfo=None))
        a, b = await _count(db, i), await _count(db, nv)
        idle.append(i)
        never.append(nv)
        by[label or "all accounts"] = {"idle_days": days, "dormant": a, "never_logged_on": b}
        parts.append(f"{label} over {days} days" if label else f"over {days} days")
    n_idle = sum(g["dormant"] for g in by.values())
    n_never = sum(g["never_logged_on"] for g in by.values())
    n = n_idle + n_never
    rule = parts[0] if len(parts) == 1 else "; ".join(parts)
    out = Outcome(grade_low(n, 0, t["warn_max"]),
                  f"{n:,} of {total:,} enabled accounts idle ({rule}; {n_never:,} never logged on)",
                  {"enabled_accounts": total, "dormant": n_idle, "never_logged_on": n_never,
                   **({"by_account_group": by} if len(groups) > 1 else {})})
    if detail:
        rows = []
        for (label, who, days), i, nv in zip(groups, idle, never):
            found = await db.execute(select(User).where(or_(i, nv)).order_by(User.ad_last_logon).limit(MAX_ROWS))
            rows += [{"account": _name(u), "last_logon": _iso(u.ad_last_logon) or "never",
                      "password_last_set": _iso(u.ad_pwd_last_set), "idle_limit_days": days, "group": label or "all"}
                     for u in found.scalars()]
        out.columns = ["account", "last_logon", "password_last_set", "idle_limit_days", "group"]
        out.rows = rows[:MAX_ROWS]
    return out


async def _password(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    total = await _count(db, _person())
    if not total:
        return Outcome("error", "no enabled directory accounts in CTEM")
    never_q = and_(_person(), User.ad_pwd_never_expires == True)  # noqa: E712
    expired_q = and_(_person(), User.ad_pwd_expired == True)  # noqa: E712
    never, expired = await _count(db, never_q), await _count(db, expired_q)
    out = Outcome(grade_low(never, 0, t["warn_max"]),
                  f"{never:,} of {total:,} enabled people accounts have passwords that never expire; {expired:,} expired",
                  {"enabled_accounts": total, "password_never_expires": never, "password_expired": expired})
    if detail:
        found = await db.execute(select(User).where(or_(never_q, expired_q)).order_by(User.username).limit(MAX_ROWS))
        out.columns = ["account", "never_expires", "expired", "password_last_set"]
        out.rows = [{"account": _name(u), "never_expires": bool(u.ad_pwd_never_expires), "expired": bool(u.ad_pwd_expired),
                     "password_last_set": _iso(u.ad_pwd_last_set)} for u in found.scalars()]
    return out


def _priv_groups(groups) -> list[str]:
    out = []
    for g in groups or []:
        cn = str(g).split(",", 1)[0]
        cn = cn[3:] if cn.lower().startswith("cn=") else cn
        if cn.strip().lower() in PRIVILEGED:
            out.append(cn.strip())
    return out


async def _privileged(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    # Group lists are encrypted at rest, so membership is matched here rather than in SQL
    found = await db.execute(select(User.username, User.ad_username, User.ad_groups, User.ad_disabled,
                                    User.ad_last_logon, User.is_service_account).where(_directory_user()))
    idle_cut = now() - timedelta(days=t["idle_days"])
    members, disabled, idle, rows = 0, 0, 0, []
    for username, ad_name, groups, is_disabled, last, svc in found.all():
        priv = _priv_groups(groups)
        if not priv:
            continue
        stale = not is_disabled and (aware(last) is None or aware(last) < idle_cut)
        members += not is_disabled
        disabled += bool(is_disabled)
        idle += stale
        if detail and len(rows) < MAX_ROWS:
            rows.append({"account": ad_name or username, "groups": "; ".join(sorted(set(priv))), "disabled": bool(is_disabled),
                         "service_account": bool(svc), "last_logon": _iso(last) or "never", "idle": stale})
    if disabled or idle:
        result = "fail"
    else:
        result = "warning" if members > t["max_members"] else "pass"
    out = Outcome(result, f"{members:,} enabled privileged accounts (target {t['max_members']}); "
                          f"{idle:,} idle over {t['idle_days']} days; {disabled:,} disabled but still in privileged groups",
                  {"privileged_enabled": members, "privileged_idle": idle, "privileged_disabled": disabled})
    if detail:
        out.columns = ["account", "groups", "disabled", "service_account", "last_logon", "idle"]
        out.rows = rows
    return out


async def _itdr(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    live = and_(IdentityThreat.status.in_((ItdrAlertStatus.active, ItdrAlertStatus.investigating)),
                IdentityThreat.severity.in_(("critical", "high")))
    old = and_(live, IdentityThreat.detected_at < now() - timedelta(hours=t["max_age_hours"]))
    n_live = (await db.execute(select(func.count()).select_from(IdentityThreat).where(live))).scalar_one()
    n_old = (await db.execute(select(func.count()).select_from(IdentityThreat).where(old))).scalar_one()
    result = "fail" if n_old else "warning" if n_live else "pass"
    out = Outcome(result, f"{n_live:,} open critical/high identity threat alerts; {n_old:,} open longer than {t['max_age_hours']}h",
                  {"open_critical_high": n_live, "over_age": n_old})
    if detail:
        found = await db.execute(select(IdentityThreat).where(live).order_by(IdentityThreat.detected_at).limit(MAX_ROWS))
        out.columns = ["detected_at", "severity", "threat_type", "title", "user", "status"]
        out.rows = [{"detected_at": _iso(a.detected_at), "severity": a.severity, "threat_type": a.threat_type.value,
                     "title": a.title[:200], "user": a.user_display or "", "status": a.status.value} for a in found.scalars()]
    return out


def _app_key(a) -> str:
    """Grip and FairTPRM can both report the same app; match on domain, else name. Agents stay separate."""
    key = (a.vendor or a.app_name or "").strip().lower()
    return f"agent:{a.app_name.lower()}" if a.source == "grip_ai_agent" else key


def _shadow(ai: bool):
    async def run(db: AsyncSession, t: dict, detail: bool) -> Outcome:
        cond = and_(SaasAppRecord.source.in_(("grip", "grip_ai_agent", "fairtprm")), SaasAppRecord.is_shadow_ai == ai,
                    SaasAppRecord.is_sanctioned == False, SaasAppRecord.user_count > 0)  # noqa: E712
        apps: dict[str, SaasAppRecord] = {}
        for a in (await db.execute(select(SaasAppRecord).where(cond))).scalars():
            k = _app_key(a)
            if k not in apps or a.user_count > apps[k].user_count:
                apps[k] = a
        n, people = len(apps), sum(a.user_count for a in apps.values())
        kind = "AI" if ai else "SaaS"
        out = Outcome(grade_low(n, t["pass_max"], t["warn_max"]),
                      f"{n:,} unsanctioned {kind} apps in use by {int(people):,} user accounts",
                      {"unsanctioned_apps": n, "user_accounts": int(people)})
        if detail:
            out.columns = ["app", "vendor", "category", "risk_level", "users", "last_seen", "source"]
            out.rows = [{"app": a.app_name, "vendor": a.vendor or "", "category": a.app_category or "", "risk_level": a.risk_level,
                         "users": a.user_count, "last_seen": _iso(a.last_seen), "source": a.source}
                        for a in sorted(apps.values(), key=lambda x: -x.user_count)[:MAX_ROWS]]
        return out
    return run


_IDLE = Threshold(90, 30, 365, "no logon for this many days counts as idle")

register(Check(
    "ctem_dormant_accounts", "Dormant accounts", "Enabled people accounts with no logon in N days", 1, DIRECTORY,
    ("NIST 800-53 AC-2(3)", "CIS 5.3", "ISO 27001 A.5.18", "SOC 2 CC6.2"),
    {"idle_days": _IDLE, "warn_max": Threshold(10, 0, 100000, "dormant accounts tolerated as a warning")}, _dormant,
    account_scoped=True))

register(Check(
    "ctem_password_policy", "Password expiry policy", "People accounts whose passwords never expire", 1, DIRECTORY,
    ("CIS 5.2", "ISO 27001 A.5.17", "NIST 800-53 IA-5"),
    {"warn_max": Threshold(0, 0, 100000, "accounts tolerated as a warning")}, _password))

register(Check(
    "ctem_privileged_accounts", "Privileged access review", "Members of AD admin groups: count, idle, and disabled leftovers",
    1, DIRECTORY, ("CIS 5.4", "ISO 27001 A.8.2", "NIST 800-53 AC-6", "SOC 2 CC6.3", "SOX ITGC"),
    {"max_members": Threshold(10, 0, 10000, "privileged accounts above this are a warning"), "idle_days": _IDLE},
    _privileged))

register(Check(
    "ctem_itdr_alerts", "Identity threat response", "Open critical/high ITDR alerts and how long they've been open", 1,
    IDENTITY, ("NIST CSF DE.AE-02", "NIST CSF RS.MA-01", "ISO 27001 A.5.25", "ISO 27001 A.5.26"),
    {"max_age_hours": Threshold(24, 1, 720, "alerts open longer than this fail")}, _itdr))

register(Check(
    "ctem_shadow_ai", "Shadow AI", "Unsanctioned AI apps in use", 2, SHADOW,
    ("ISO/IEC 42001", "NIST AI RMF GOVERN 1.6", "ISO 27001 A.5.23"),
    {"pass_max": Threshold(0, 0, 10000, "apps tolerated as a pass"), "warn_max": Threshold(3, 0, 10000, "apps tolerated as a warning")},
    _shadow(True)))

register(Check(
    "ctem_shadow_saas", "Shadow SaaS", "Unsanctioned SaaS apps in use", 2, SHADOW,
    ("ISO 27001 A.5.23", "CIS 2.3", "SOC 2 CC9.2"),
    {"pass_max": Threshold(0, 0, 100000, "apps tolerated as a pass"), "warn_max": Threshold(25, 0, 100000, "apps tolerated as a warning")},
    _shadow(False)))
