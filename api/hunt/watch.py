"""Standing hunt for the dashboard: only the issues worth interrupting someone for."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.settings import AppSetting

WATCH_KEY = "hunt_watch"
WATCH_RANGE = "7d"
WATCH_QUESTION = ("What is probably really happening that a security team must act on? Look for "
                  "corroborated attacks across sources, impossible travel, credential theft, persistence, "
                  "new admin rights, data leaving, and exploitable vulnerabilities on reachable machines "
                  "without compensating controls. Ignore isolated signals with innocent explanations.")
MAX_SHOWN = 5
# Read on every run, whatever searches are reused: a check that never looks at the alerts can't say nothing is wrong
ALWAYS = [{"source": "ctem", "table": "alerts", "filters": {}, "limit": 100, "title": "Recent alerts from every connected tool",
           "why": "The newest alerts from the EDR and other tools, so the check always weighs what they raised"}]


def worth_showing(issue: dict) -> bool:
    """Only probable, corroborated problems reach the dashboard. Low never does."""
    sources = len({t.get("source", "").lower() for t in issue.get("timeline", []) if t.get("source")})
    sev, conf = issue["severity"], issue["confidence"]
    if sev == "critical":
        return conf != "low"
    if sev == "high":
        return conf == "high" or sources >= 2
    return sev == "medium" and conf == "high" and sources >= 2


def _key(issue: dict) -> str:
    who = sorted(h.lower() for h in (issue.get("involved") or {}).get("hosts", []))
    return hashlib.sha256(f"{issue['title'].lower()}|{who}".encode()).hexdigest()[:16]


async def load_watch(db: AsyncSession) -> dict | None:
    row = (await db.execute(select(AppSetting).where(AppSetting.key == WATCH_KEY))).scalar_one_or_none()
    try:
        return json.loads(row.value) if row and row.value else None
    except ValueError:
        return None


async def run_watch(db: AsyncSession) -> dict:
    from api.hunt.engine import investigate
    result = await investigate(db, WATCH_QUESTION, WATCH_RANGE, always=ALWAYS)
    now = datetime.now(timezone.utc).isoformat()
    seen = {i["key"]: i.get("first_noticed") for i in ((await load_watch(db)) or {}).get("result", {}).get("issues", [])}
    if result.get("mode") != "ai":   # without the AI only the curated rules speak, and they're high fidelity already
        keep = [i for i in result.get("issues", []) if i.get("from_rule") and worth_showing(i)][:MAX_SHOWN]
        for i in keep:
            i["key"] = _key(i)
            i["first_noticed"] = seen.get(i["key"]) or now
        result.update(issues=keep, summary="")
        note = "" if keep else "AI is off, so only the Threat Curated Rules were checked, and none matched."
    else:
        keep = [i for i in result["issues"] if worth_showing(i)][:MAX_SHOWN]
        for i in keep:
            i["key"] = _key(i)
            i["first_noticed"] = seen.get(i["key"]) or now
        result["issues"] = keep
        note = ""
    used = {n for i in result["issues"] for n in i.get("lookups", [])}
    # Only keep the evidence the shown issues point at; renumber so the links still line up
    order = sorted(used)
    remap = {old: new for new, old in enumerate(order, 1)}
    result["lookups"] = [result["lookups"][n - 1] for n in order]
    for i in result["issues"]:
        i["lookups"] = [remap[n] for n in i.get("lookups", [])]
        for step in i.get("timeline", []):
            step["lookup"] = remap.get(step.get("lookup"))
    watch = {"ran_at": now, "note": note, "result": result}
    row = (await db.execute(select(AppSetting).where(AppSetting.key == WATCH_KEY))).scalar_one_or_none()
    row = row or AppSetting(key=WATCH_KEY, is_sensitive=False)
    row.value = json.dumps(watch)
    db.add(row)
    await db.commit()
    return watch
