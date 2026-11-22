"""Account deprovisioning: evidence that leaver triggers actually remove access, from the directory (AD/LDAP).

Three signs a deprovisioning trigger didn't finish the job:
  disabled accounts still in groups   access left behind after the account was disabled
  enabled accounts in a leaver OU     the account was moved to a Disabled/Terminated OU but never disabled
  enabled accounts idle past a limit  a person who left whose account nothing ever disabled
Suited to controls like "Automated deprovision of account triggers" (map it to them with a FairTPRM monitor)."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.grc.checks import DIRECTORY, Check, Outcome, Threshold, aware, grade_low, now, register
from api.models.user import User

MAX_ROWS = 50000
DEFAULT_GROUPS = {"domain users", "domain guests", "users", "domain computers"}   # every account has these
LEAVER_OU = ("disabled", "terminated", "termed", "leavers", "deprovision", "offboard", "former", "separated")


def _cn(dn: str) -> str:
    first = str(dn).split(",", 1)[0].strip()
    return first[3:].strip() if first.lower().startswith("cn=") else first


def _ous(dn: str | None) -> list[str]:
    return [p.strip()[3:] for p in str(dn or "").split(",") if p.strip().lower().startswith("ou=")]


def leaver_ou(dn: str | None) -> str | None:
    """The OU that marks a leaver (Disabled Users, Terminated, Leavers...), if the account sits in one."""
    for ou in _ous(dn):
        low = ou.lower()
        if any(k in low for k in LEAVER_OU):
            return ou
    return None


async def _deprov(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    rows = (await db.execute(select(User.username, User.ad_username, User.ad_dn, User.ad_groups, User.ad_disabled,
                                    User.ad_last_logon, User.created_at, User.is_service_account)
                             .where(User.is_local == False, User.ad_dn.is_not(None)))).all()  # noqa: E712
    if not rows:
        return Outcome("error", "no directory accounts in CTEM")
    cut = now() - timedelta(days=t["idle_days"])
    kept, in_leaver_ou, idle, enabled, out_rows = 0, 0, 0, 0, []
    for username, ad_name, dn, groups, disabled, last, created, svc in rows:   # DNs and groups are encrypted at rest
        issues = []
        if disabled:
            left = [g for g in sorted({_cn(g) for g in groups or []} - {""}, key=str.lower) if g.lower() not in DEFAULT_GROUPS]
            if left:
                kept += 1
                issues.append(("disabled, still in groups", "; ".join(left)[:400]))
        else:
            enabled += 1
            ou = leaver_ou(dn)
            if ou:
                in_leaver_ou += 1
                issues.append(("enabled in a leaver OU", ou))
            seen = aware(last) or (aware(created) if last is None else None)
            if t["include_idle"] and not svc and (seen is None or seen < cut):
                idle += 1
                issues.append((f"enabled, no logon in {t['idle_days']} days", aware(last).date().isoformat() if last else "never"))
        if detail:
            for kind, what in issues:
                if len(out_rows) < MAX_ROWS:
                    out_rows.append({"account": ad_name or username, "issue": kind, "detail": what,
                                     "last_logon": aware(last).isoformat() if last else "never"})
    n = kept + in_leaver_ou + idle
    out = Outcome(grade_low(n, 0, t["warn_max"]),
                  f"{kept:,} disabled accounts still in groups; {in_leaver_ou:,} enabled accounts in a leaver OU"
                  + (f"; {idle:,} enabled accounts with no logon in {t['idle_days']} days" if t["include_idle"] else ""),
                  {"directory_accounts": len(rows), "enabled_accounts": enabled, "disabled_still_in_groups": kept,
                   "enabled_in_leaver_ou": in_leaver_ou, "enabled_idle": idle if t["include_idle"] else None,
                   "leaver_ou_words": list(LEAVER_OU)})
    if detail:
        out.columns = ["account", "issue", "detail", "last_logon"]
        out.rows = sorted(out_rows, key=lambda r: (r["issue"], r["account"].lower()))[:MAX_ROWS]
    return out


register(Check(
    "ctem_deprovisioning", "Account deprovisioning",
    "Leaver access left behind: disabled accounts still in groups, enabled accounts in a leaver OU, long-idle enabled accounts",
    1, DIRECTORY, ("NIST 800-53 AC-2(3)", "NIST 800-53 PS-4", "ISO 27001 A.5.18", "SOC 2 CC6.2", "CIS 5.3", "CIS 6.2"),
    {"idle_days": Threshold(90, 14, 365, "an enabled account with no logon this long counts as a missed deprovision"),
     "include_idle": Threshold(1, 0, 1, "1 = count long-idle enabled people accounts too; 0 = only the two direct signs"),
     "warn_max": Threshold(0, 0, 100000, "accounts tolerated as a warning instead of a fail")}, _deprov))
