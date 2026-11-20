"""open-ctem's own data, exposed to the hunt as allowlisted, read-only lookups.

The AI never writes SQL. It names a table, a few filters, and a limit; this
module decides what that means. Secrets and contact PII are simply not listed.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.core.encryption import search_hash
from api.models.device import Device
from api.models.identity import IdentityThreat
from api.models.risk import AttackPath
from api.models.settings import AppSetting
from api.models.user import User
from api.models.vuln import Finding, Vulnerability

MAX_ROWS = 100

# table -> (what it holds, {field: meaning}, {filterable field: how})
# "eq" exact (case-insensitive), "like" accepts * wildcards, "hash" matches an
# encrypted column through its search hash, "bool" true/false.
TABLES: dict[str, tuple[str, dict[str, str], dict[str, str]]] = {
    "devices": (
        "Every computer and server open-ctem knows about (from AD, EDR, scanners)",
        {"hostname": "computer name", "ip": "current IP", "os": "operating system",
         "device_type": "workstation/server/...", "last_login_user": "last person signed in",
         "ad_joined": "joined to Active Directory", "edr_active": "endpoint protection running",
         "edr_vendor": "which EDR", "is_internet_exposed": "reachable from the internet",
         "risk_grade": "A (good) to F (bad)", "risk_score": "0-100", "last_seen": "last check-in"},
        {"hostname": "like", "ip": "hash", "os": "like", "device_type": "eq",
         "risk_grade": "eq", "is_internet_exposed": "bool", "edr_active": "bool"},
    ),
    "users": (
        "Directory accounts (AD/LDAP), not app logins",
        {"username": "account name", "ad_groups": "groups it belongs to",
         "is_service_account": "used by software, not a person", "is_active": "enabled",
         "is_locked": "locked out", "last_login": "last sign-in seen"},
        {"username": "like", "is_service_account": "bool", "is_locked": "bool"},
    ),
    "findings": (
        "Open vulnerabilities on devices, from scanners",
        {"hostname": "device", "cve_id": "CVE", "title": "vulnerability name",
         "cvss": "severity 0-10", "epss": "chance of exploitation 0-1", "is_kev": "known exploited",
         "status": "open/accepted/...", "is_reachable": "attacker can reach it",
         "score": "open-ctem risk 0-100", "first_detected": "first seen"},
        {"hostname": "like", "cve_id": "eq", "is_kev": "bool", "status": "eq"},
    ),
    "alerts": (
        "Latest alerts pulled from every connected security tool (EDR, firewall, segmentation)",
        {"source": "which tool", "severity": "tool's severity", "hostname": "computer involved",
         "description": "what the tool said", "details": "other fields the tool sent",
         "last_seen": "when open-ctem last pulled it"},
        {"source": "eq", "hostname": "like", "text": "like"},
    ),
    "identity_threats": (
        "Identity alerts from SaaS/identity tools (risky sign-ins, token theft)",
        {"source": "tool", "threat_type": "kind", "severity": "severity", "status": "open/closed",
         "user": "who", "app_name": "app", "title": "alert", "source_ip": "from IP",
         "country": "from country", "detected_at": "when"},
        {"user": "like", "source_ip": "eq", "severity": "eq"},
    ),
    "attack_paths": (
        "Proven or modeled routes an attacker could take between machines",
        {"from_host": "start", "to_host": "target", "path": "how", "impact": "what it reaches",
         "score": "0-100", "confirmed_by": "who proved it"},
        {"from_host": "like", "to_host": "like"},
    ),
}


def describe(counts: dict[str, int]) -> str:
    """Plain description of the tables for the AI, with how full each one is."""
    out = []
    for name, (what, fields, filters) in TABLES.items():
        out.append(f'- {name} ({counts.get(name, 0)} rows): {what}\n'
                   f'    fields: {", ".join(f"{k} = {v}" for k, v in fields.items())}\n'
                   f'    filter on: {", ".join(f"{k} ({v})" for k, v in filters.items())}')
    return "\n".join(out)


async def row_counts(db: AsyncSession) -> dict[str, int]:
    q = {
        "devices": select(func.count()).select_from(Device),
        "users": select(func.count()).select_from(User).where(User.is_local == False),  # noqa: E712
        "findings": select(func.count()).select_from(Finding),
        "alerts": select(func.count()).select_from(AppSetting).where(AppSetting.key.like("threat_alert_%")),
        "identity_threats": select(func.count()).select_from(IdentityThreat),
        "attack_paths": select(func.count()).select_from(AttackPath),
    }
    return {k: (await db.execute(v)).scalar() or 0 for k, v in q.items()}


def validate(table: str, filters: dict) -> dict[str, Any]:
    if table not in TABLES:
        raise ValueError(f"unknown table {table!r}")
    allowed = TABLES[table][2]
    clean = {}
    for k, v in (filters or {}).items():
        if k not in allowed:
            raise ValueError(f"{table} cannot be filtered on {k!r}")
        if allowed[k] == "bool":
            clean[k] = str(v).lower() in ("true", "1", "yes")
        else:
            clean[k] = str(v)[:200]
    return clean


def _match(col, value: str, how: str):
    text = cast(col, String)  # enum columns refuse lower() on Postgres
    if how == "like" and "*" in value:
        return text.ilike(value.replace("%", r"\%").replace("*", "%"))
    return func.lower(text) == value.lower()


def _iso(v):
    return v.strftime("%Y-%m-%d %H:%M:%S") if isinstance(v, datetime) else v


async def lookup(db: AsyncSession, table: str, filters: dict, limit: int = 25) -> list[dict]:
    f = validate(table, filters)
    limit = max(1, min(int(limit or 25), MAX_ROWS))
    how = TABLES[table][2]

    if table == "devices":
        stmt = select(Device)
        for k, v in f.items():
            if k == "ip":
                stmt = stmt.where(Device.ip_hash == search_hash(v))
            elif how[k] == "bool":
                stmt = stmt.where(getattr(Device, k) == v)
            else:
                stmt = stmt.where(_match(getattr(Device, k), v, how[k]))
        rows = (await db.execute(stmt.order_by(Device.risk_score.desc().nullslast()).limit(limit))).scalars()
        return [{"hostname": d.hostname, "ip": d.ip, "os": d.os,
                 "device_type": d.device_type.value if d.device_type else None,
                 "last_login_user": d.last_login_user, "ad_joined": d.ad_joined,
                 "edr_active": d.edr_active, "edr_vendor": d.edr_vendor,
                 "is_internet_exposed": d.is_internet_exposed,
                 "risk_grade": d.risk_grade.value if d.risk_grade else None,
                 "risk_score": d.risk_score, "last_seen": _iso(d.last_seen)} for d in rows]

    if table == "users":
        stmt = select(User).where(User.is_local == False)  # noqa: E712
        for k, v in f.items():
            stmt = stmt.where(getattr(User, k) == v) if how[k] == "bool" else stmt.where(_match(User.username, v, how[k]))
        rows = (await db.execute(stmt.limit(limit))).scalars()
        return [{"username": u.username, "ad_groups": [g.split(",")[0].removeprefix("CN=") for g in (u.ad_groups or [])],
                 "is_service_account": u.is_service_account, "is_active": u.is_active,
                 "is_locked": u.is_locked, "last_login": _iso(u.last_login)} for u in rows]

    if table == "findings":
        stmt = select(Finding).join(Device).join(Vulnerability).options(
            selectinload(Finding.device), selectinload(Finding.vuln))
        for k, v in f.items():
            col = {"hostname": Device.hostname, "cve_id": Vulnerability.cve_id,
                   "is_kev": Vulnerability.is_kev, "status": Finding.status}[k]
            stmt = stmt.where(col == v) if how[k] == "bool" else stmt.where(_match(col, v, how[k]))
        rows = (await db.execute(stmt.order_by(Finding.composite_score.desc().nullslast()).limit(limit))).scalars()
        return [{"hostname": x.device.hostname, "cve_id": x.vuln.cve_id, "title": x.vuln.title,
                 "cvss": x.vuln.cvss_base, "epss": x.vuln.epss_score, "is_kev": x.vuln.is_kev,
                 "status": x.status.value, "is_reachable": x.is_reachable,
                 "score": x.composite_score, "first_detected": _iso(x.first_detected)} for x in rows]

    if table == "alerts":
        return await _alerts(db, f, limit)

    if table == "identity_threats":
        stmt = select(IdentityThreat)
        for k, v in f.items():
            col = {"user": IdentityThreat.user_display, "source_ip": IdentityThreat.source_ip,
                   "severity": IdentityThreat.severity}[k]
            stmt = stmt.where(_match(col, v, how[k]))
        rows = (await db.execute(stmt.order_by(IdentityThreat.detected_at.desc()).limit(limit))).scalars()
        return [{"source": t.source, "threat_type": t.threat_type.value, "severity": t.severity,
                 "status": t.status.value, "user": t.user_display, "app_name": t.app_name,
                 "title": t.title, "source_ip": t.source_ip, "country": t.country,
                 "detected_at": _iso(t.detected_at)} for t in rows]

    stmt = select(AttackPath).where(AttackPath.is_active == True).limit(limit)  # noqa: E712
    paths = (await db.execute(stmt)).scalars().all()
    names = {d.id: d.hostname for d in (await db.execute(select(Device).where(
        Device.id.in_({p.source_device_id for p in paths} | {p.target_device_id for p in paths})))).scalars()}
    out = [{"from_host": names.get(p.source_device_id), "to_host": names.get(p.target_device_id),
            "path": p.path_description, "impact": p.impact_description,
            "score": p.path_score, "confirmed_by": p.confirmed_by} for p in paths]
    for k, v in f.items():
        out = [r for r in out if r.get(k) and str(v).lower().strip("*") in r[k].lower()]
    return out


async def _alerts(db: AsyncSession, f: dict, limit: int) -> list[dict]:
    stmt = select(AppSetting).where(AppSetting.key.like("threat_alert_%"))
    if "source" in f:
        stmt = stmt.where(AppSetting.value.ilike(f'%"source": "{f["source"].replace("%", "")}"%'))
    rows = (await db.execute(stmt.order_by(AppSetting.updated_at.desc()).limit(2000))).scalars()
    out = []
    for row in rows:
        try:
            a = json.loads(row.value or "{}")
        except ValueError:
            continue
        if not isinstance(a, dict):
            continue
        host = a.get("hostname") or a.get("source_asset") or ", ".join(a.get("hosts") or [])
        blob = json.dumps(a).lower()
        if "hostname" in f and f["hostname"].lower().strip("*") not in str(host).lower():
            continue
        if "text" in f and f["text"].lower().strip("*") not in blob:
            continue
        details = {k: v for k, v in a.items() if k not in ("source", "severity", "hostname", "description", "raw", "id")}
        out.append({"source": a.get("source"), "severity": a.get("severity"), "hostname": host,
                    "description": a.get("description"), "details": json.dumps(details)[:400],
                    "last_seen": _iso(row.updated_at)})
        if len(out) >= limit:
            break
    return out
