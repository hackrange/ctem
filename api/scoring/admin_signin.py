"""An admin signing in interactively raises a host's risk: their credentials sit in memory there, so a flaw on that host
is a path to whatever they administer. Admins should use runas or sudo instead, so on a workstation any admin sign-in
counts in full; on a server, where admins do sign in to maintain it, a privileged-group account counts in full and an
admin-named one less, and servers left out by the admin sign-in check's curated rules (jump servers) don't count.

Admin: an account in a privileged AD group (Domain Admins and the like), or one named like an admin account (the admin
sign-in check's patterns, its curated rules' account_patterns, and the built-in Administrator and root). Signed in:
the last interactive sign-in the EDR saw, or one of the recent ones (cached credentials). Cached per process for a few
minutes, so a rescoring round reads the directory once."""
from __future__ import annotations

import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

BUILT_IN = ("administrator", "root")
CHECK = "ctem_admin_local_logons"
TTL = 300
# (privileged group, admin-named, recent sign-in only) by device type
FACTORS = {"workstation": (1.4, 1.4, 1.25), "server": (1.4, 1.25, 1.1)}
_cache: dict = {}


async def context(db: AsyncSession) -> dict:
    """{privileged: names, patterns: globs, exempt: server ids}, cached for TTL seconds."""
    if _cache.get("at", 0) > time.monotonic() - TTL:
        return _cache["ctx"]
    from api.grc.checks.admin_logons import DEFAULT_PATTERNS, bare
    from api.grc.checks.identity import PRIVILEGED
    from api.models.device import Device, DeviceType
    from api.models.user import User
    from api.rules.apply import active_rules, combine
    privileged = set()
    for u in (await db.execute(select(User).where(User.is_local == False, User.ad_groups.is_not(None)))).scalars():  # noqa: E712
        cns = {str(g).split(",", 1)[0].split("=", 1)[-1].strip().lower() for g in (u.ad_groups or [])}
        if cns & set(PRIVILEGED):
            privileged |= {bare(n) for n in (u.ad_username, u.username) if n}
    rules = await active_rules(db, CHECK)
    patterns = list(DEFAULT_PATTERNS) + list(BUILT_IN)
    for _row, doc in rules:
        if doc is not None and doc.account_patterns:
            patterns += [str(p) for p in doc.account_patterns]
    clause, _t, _applied, problem = combine(rules)
    exempt: set[str] = set()
    if clause is not None and problem is None:   # servers the check's rules leave out: where admin sign-ins are expected
        servers = select(Device.id).where(Device.device_type == DeviceType.server)
        kept = {str(i) for (i,) in (await db.execute(servers.where(clause))).all()}
        exempt = {str(i) for (i,) in (await db.execute(servers)).all()} - kept
    ctx = {"privileged": privileged, "patterns": tuple(dict.fromkeys(patterns)), "exempt": exempt}
    _cache.update(at=time.monotonic(), ctx=ctx)
    return ctx


def factor(device, ctx: dict) -> tuple[float, str] | None:
    """(multiplier, reason) for this host, or None: not a workstation or server, no admin sign-in, or a server where
    admin sign-ins are expected."""
    from api.grc.checks.admin_logons import bare, matches
    kind = getattr(getattr(device, "device_type", None), "value", None)
    if kind not in FACTORS or (kind == "server" and str(device.id) in ctx["exempt"]):
        return None
    full, named, recent_f = FACTORS[kind]
    where = "this workstation" if kind == "workstation" else "this server"
    last = bare(device.last_login_user or "")
    if last and last in ctx["privileged"]:
        return full, f"A privileged account (domain admin level) signs in interactively to {where} (+{round((full - 1) * 100)}%)"
    if last and matches(last, ctx["patterns"]):
        return named, f"An admin account signs in interactively to {where}; use runas or sudo instead (+{round((named - 1) * 100)}%)"
    recent = [n for n in device.recent_logins or [] if isinstance(n, str)]
    if any(bare(n) in ctx["privileged"] or matches(n, ctx["patterns"]) for n in recent):
        return recent_f, f"An admin account signed in to {where} recently; its credentials may still be cached (+{round((recent_f - 1) * 100)}%)"
    return None


def forget() -> None:
    _cache.clear()
