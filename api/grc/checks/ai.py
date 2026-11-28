"""AI agents: agents people built (Grip sees custom Copilot agents and the like) that nobody has reviewed and approved.

An agent is a concern when its risk reaches beyond one person who answers for it: shared with others, connected to
the internet, with no owner, or marked unsanctioned. Grip doesn't report what an agent can access (its scopes), so
the check works from those facts. With no AI agent data at all it is an error, never a pass."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.grc.checks import Check, Outcome, Threshold, register

MAX_ROWS = 50000


async def _ai_agents(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    from api.core.ai_inventory import AGENT_SOURCE, agents
    from api.models.identity import SaasAppRecord
    known = (await db.execute(select(SaasAppRecord.id).where(SaasAppRecord.source == AGENT_SOURCE).limit(1))).first()
    rows = await agents(db) if known else []
    if not rows:
        return Outcome("error", "No AI agent data yet: Grip hasn't reported any AI agents")
    unsanctioned = [a for a in rows if a["state"] == "unsanctioned"]
    risky = [a for a in rows if a["state"] != "sanctioned" and a["concerns"]]
    unreviewed = [a for a in rows if a["state"] == "unreviewed"]
    fail = len({a["id"] for a in unsanctioned + risky})
    result = "fail" if fail > t["warn_max"] else "warning" if fail or unreviewed else "pass"
    out = Outcome(result, f"{fail:,} of {len(rows):,} AI agents are unsanctioned or unreviewed and shared, internet-connected or "
                          f"ownerless; {len(unreviewed):,} not reviewed yet",
                  {"ai_agents": len(rows), "agents_failing": fail, "unsanctioned": len(unsanctioned),
                   "unreviewed": len(unreviewed), "shared": sum("shared with others" in a["concerns"] for a in rows),
                   "internet_connected": sum(a["internet"] for a in rows), "no_owner": sum("no owner" in a["concerns"] for a in rows)})
    if detail:
        out.columns = ["agent", "platform", "owner", "review", "concerns", "last_seen"]
        order = {"unsanctioned": 0, "unreviewed": 1, "sanctioned": 2}
        out.rows = [{"agent": a["name"], "platform": a["platform"] or "", "owner": a["owner"] or "(none)", "review": a["state"],
                     "concerns": ", ".join(a["concerns"]), "last_seen": a["last_seen"] or ""}
                    for a in sorted(rows, key=lambda a: (order.get(a["state"], 1), not a["concerns"], a["name"] or ""))
                    if a["state"] != "sanctioned"][:MAX_ROWS]
    return out


register(Check(
    "ctem_ai_agents", "AI agents not reviewed",
    "AI agents people built that aren't sanctioned: unsanctioned, or unreviewed and shared, internet-connected or with "
    "no owner, fail; other unreviewed agents warn", 1, ("grip",),
    ("NIST AI RMF GOVERN 1.6", "NIST 800-53 CM-8", "ISO 27001 A.5.9", "CIS 2.1", "NIST CSF ID.AM-02"),
    {"warn_max": Threshold(0, 0, 100000, "agents with concerns tolerated as a warning instead of a fail")}, _ai_agents))
