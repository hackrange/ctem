"""Every AI agent, app, browser extension and installed AI tool in one inventory (the AI page, api/routes/ai_inventory.py),
from what CTEM already holds:

  agents      AI agents people built (Grip: custom Copilot agents and the like), with their owner, whether they're
              shared or reach the internet, and Grip's review state
  apps        AI apps people use (Grip and FairTPRM shadow AI), with users and whether they're sanctioned
  extensions  AI browser extensions (Grip)
  software    AI software installed on assets (the software inventory: InsightVM, Tanium, CrowdStrike Discover)

The concerns that make an agent worth a look (concerns()) are shared with the AI agents control check."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

AGENT_SOURCE = "grip_ai_agent"
APP_SOURCES = ("grip", "fairtprm")
EXT_SOURCE = "grip_extension"
SANCTIONED = ("sanctioned", "approved")
UNSANCTIONED = ("unsanctioned", "blocked", "denied", "rejected")
MAX_ROWS = 2000


def state(rec) -> str:
    """sanctioned | unsanctioned | unreviewed, from Grip's review state (or the sanctioned flag)."""
    s = str((rec.data_access_scopes or {}).get("sanction_state") or "").lower() if isinstance(rec.data_access_scopes, dict) else ""
    if rec.is_sanctioned or s in SANCTIONED:
        return "sanctioned"
    return "unsanctioned" if s in UNSANCTIONED else "unreviewed"


def concerns(rec) -> list[str]:
    """What spreads an agent's risk beyond one person who answers for it."""
    d = rec.data_access_scopes if isinstance(rec.data_access_scopes, dict) else {}
    out = []
    if state(rec) == "unsanctioned":
        out.append("marked unsanctioned")
    if str(d.get("sharing") or "").lower() not in ("", "personal", "private", "none"):
        out.append("shared with others")
    if d.get("is_connected_to_internet"):
        out.append("connected to the internet")
    if not d.get("owner_email_hash"):
        out.append("no owner")
    return out


def _when(v):
    return v.isoformat() if v else None


async def agents(db: AsyncSession) -> list[dict]:
    from api.models.identity import IdentityRiskScore, SaasAppRecord
    rows = (await db.execute(select(SaasAppRecord).where(SaasAppRecord.source == AGENT_SOURCE)
                             .order_by(SaasAppRecord.app_name).limit(MAX_ROWS))).scalars().all()
    owners = {(r.data_access_scopes or {}).get("owner_email_hash") for r in rows if isinstance(r.data_access_scopes, dict)} - {None}
    ids = dict((await db.execute(select(IdentityRiskScore.user_email_hash, IdentityRiskScore.id)
                                 .where(IdentityRiskScore.user_email_hash.in_(owners or {""})))).all())
    out = []
    for r in rows:
        d = r.data_access_scopes if isinstance(r.data_access_scopes, dict) else {}
        h = d.get("owner_email_hash")
        out.append({"id": str(r.id), "name": r.app_name, "platform": d.get("platform"), "owner": d.get("owner_display"),
                    "owner_identity_id": str(ids[h]) if h in ids else None, "sharing": d.get("sharing"),
                    "internet": bool(d.get("is_connected_to_internet")), "state": state(r), "concerns": concerns(r),
                    "last_seen": _when(r.last_seen), "first_seen": _when(getattr(r, "created_at", None))})
    return out


async def apps(db: AsyncSession) -> list[dict]:
    from api.models.identity import SaasAppRecord
    rows = (await db.execute(select(SaasAppRecord).where(SaasAppRecord.source.in_(APP_SOURCES), SaasAppRecord.is_shadow_ai == True)  # noqa: E712
                             .order_by(SaasAppRecord.user_count.desc(), SaasAppRecord.app_name).limit(MAX_ROWS))).scalars().all()
    return [{"id": str(r.id), "name": r.app_name, "vendor": r.vendor, "users": r.user_count, "state": state(r),
             "risk": r.risk_level, "source": r.source, "last_seen": _when(r.last_seen)} for r in rows]


async def extensions(db: AsyncSession) -> list[dict]:
    from api.grc.checks.software import AI_NAMES
    from api.models.identity import SaasAppRecord
    rows = (await db.execute(select(SaasAppRecord).where(SaasAppRecord.source == EXT_SOURCE)
                             .order_by(SaasAppRecord.user_count.desc()))).scalars().all()
    return [{"id": str(r.id), "name": r.app_name, "users": r.user_count, "state": state(r), "risk": r.risk_level,
             "last_seen": _when(r.last_seen)} for r in rows if r.is_shadow_ai or AI_NAMES.search(r.app_name or "")][:MAX_ROWS]


async def software(db: AsyncSession) -> list[dict]:
    from datetime import datetime, timedelta, timezone

    from api.core.software_ingest import STALE_DAYS
    from api.grc.checks.software import _ai_titles
    from api.models.software import SoftwareInstall, SoftwareTitle
    ai = list(await _ai_titles(db))
    if not ai:
        return []
    live = SoftwareInstall.last_seen >= datetime.now(timezone.utc) - timedelta(days=STALE_DAYS)
    rows = (await db.execute(select(SoftwareTitle.id, SoftwareTitle.title, SoftwareTitle.vendor, SoftwareTitle.status,
                                    func.count(func.distinct(SoftwareInstall.device_id)), func.max(SoftwareInstall.last_seen))
                             .join(SoftwareInstall, SoftwareInstall.title_id == SoftwareTitle.id)
                             .where(SoftwareTitle.id.in_(ai), live).group_by(SoftwareTitle.id, SoftwareTitle.title, SoftwareTitle.vendor,
                                                                              SoftwareTitle.status)
                             .order_by(func.count(func.distinct(SoftwareInstall.device_id)).desc()))).all()
    return [{"id": str(i), "name": t, "vendor": v, "state": {"approved": "sanctioned", "unauthorized": "unsanctioned"}.get(st, "unreviewed"),
             "assets": n, "last_seen": _when(ls)} for i, t, v, st, n, ls in rows][:MAX_ROWS]


def summary(sec: list[dict], key: str = "state") -> dict:
    out = {"total": len(sec), "sanctioned": 0, "unsanctioned": 0, "unreviewed": 0}
    for r in sec:
        out[r.get(key, "unreviewed")] = out.get(r.get(key, "unreviewed"), 0) + 1
    return out


async def inventory(db: AsyncSession) -> dict:
    sections = {"agents": await agents(db), "apps": await apps(db), "extensions": await extensions(db), "software": await software(db)}
    return {"sections": sections, "summary": {k: summary(v) for k, v in sections.items()},
            "agents_with_concerns": sum(1 for a in sections["agents"] if a["concerns"])}
