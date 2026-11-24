"""Run a hunt end to end: map the data, plan, search, follow leads, write it up."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.hunt import ai as hunt_ai
from api.hunt import ctem_data, fallback, memory, window
from api.hunt.results import ctem_table, evidence_brief, for_ui, splunk_table
from api.hunt.schema import describe, load_schema, refresh_schema
from api.hunt.spl_guard import TIME_RANGES, vet_spl
from api.models.integration import IntegrationConfig, Vendor

log = logging.getLogger("open-ctem.hunt")

TIME_LABELS = {"24h": "the last 24 hours", "7d": "the last 7 days", "30d": "the last 30 days", "all": "all time"}
ALERT_VENDORS = ("crowdstrike", "sentinelone", "msdefender", "cortex_xdr", "guardicore", "fortinet", "paloalto_ngfw")
_STALE = timedelta(minutes=15)
_LABELS = {"crowdstrike": "CrowdStrike", "sentinelone": "SentinelOne", "msdefender": "Microsoft Defender",
           "cortex_xdr": "Cortex XDR", "guardicore": "Guardicore", "fortinet": "Fortinet",
           "paloalto_ngfw": "Palo Alto firewall"}


async def _enabled(db: AsyncSession, vendors, live: bool = False) -> list[IntegrationConfig]:
    rows = (await db.execute(select(IntegrationConfig).where(
        IntegrationConfig.is_enabled == True,  # noqa: E712
        IntegrationConfig.vendor.in_([Vendor(v) for v in vendors])))).scalars().all()
    # live=True means we'll query it directly, which a push-only collector can't answer
    return [c for c in rows if (c.config or {}).get("mode") != "collector"] if live else rows


async def _refresh_alert_tools(db: AsyncSession, tools: list[IntegrationConfig]) -> None:
    """Pull fresh alerts from any tool whose copy is older than 15 minutes."""
    from api.core import db as core_db
    from api.integrations.base import sync_by_id
    now = datetime.now(timezone.utc)
    for t in tools:
        last = t.last_sync_at if not t.last_sync_at or t.last_sync_at.tzinfo else t.last_sync_at.replace(tzinfo=timezone.utc)
        if last and now - last < _STALE:
            continue
        try:
            async with core_db._session_factory() as s:
                await asyncio.wait_for(sync_by_id(s, str(t.id)), timeout=45)
        except Exception:
            log.warning("hunt: could not refresh %s alerts", t.vendor.value, exc_info=True)


def _vet(lookups: list, notes: list[str]) -> list[dict]:
    ok = []
    for lk in lookups[:8]:
        if not isinstance(lk, dict):
            continue
        title = str(lk.get("title") or "Lookup")[:120]
        try:
            if lk.get("source") == "splunk":
                entry = {"source": "splunk", "title": title, "why": str(lk.get("why", ""))[:300],
                         "spl": vet_spl(str(lk.get("spl", "")))}
                span = lk.get("around") if isinstance(lk.get("around"), dict) else {}
                win = window.around([span.get("first"), span.get("last")]) if span else None
                if win:
                    entry["around"] = {"first": str(span.get("first"))[:25], "last": str(span.get("last"))[:25]}
                    entry["window"] = list(win)
                    entry["window_label"] = window.label(win)
                ok.append(entry)
            elif lk.get("source") == "ctem":
                filters = ctem_data.validate(str(lk.get("table")), lk.get("filters") or {})
                ok.append({"source": "ctem", "title": title, "why": str(lk.get("why", ""))[:300],
                           "table": lk["table"], "filters": filters, "limit": min(int(lk.get("limit") or 25), 100)})
        except (ValueError, TypeError, KeyError) as exc:
            notes.append(f"Skipped '{title}': {exc}")
    return ok


async def _run(db: AsyncSession, splunk, lookups: list[dict], earliest: str) -> list[dict]:
    async def one_splunk(lk):
        try:
            if lk.get("window"):
                rows = await splunk.run_search(lk["spl"], earliest=str(lk["window"][0]), latest=str(lk["window"][1]))
            else:
                rows = await splunk.run_search(lk["spl"], earliest=earliest)
            cols, table = splunk_table(rows)
            return {**lk, "source_label": "Splunk", "columns": cols, "rows": table, "count": len(table)}
        except Exception:
            log.warning("hunt search failed: %s", lk["spl"], exc_info=True)
            return {**lk, "source_label": "Splunk", "columns": [], "rows": [], "count": 0,
                    "error": "Splunk could not run this search"}

    jobs = [one_splunk(lk) for lk in lookups if lk["source"] == "splunk" and splunk]
    done = dict(zip([id(lk) for lk in lookups if lk["source"] == "splunk" and splunk], await asyncio.gather(*jobs)))
    out = []
    for lk in lookups:
        if lk["source"] == "splunk":
            if id(lk) in done:
                out.append(done[id(lk)])
            continue
        try:
            cols, table = ctem_table(await ctem_data.lookup(db, lk["table"], lk["filters"], lk["limit"]))
            out.append({**lk, "source_label": "open-ctem", "columns": cols, "rows": table, "count": len(table)})
        except Exception:
            await db.rollback()  # one bad lookup must not poison the rest of the session
            log.warning("hunt lookup failed: %s", lk, exc_info=True)
            out.append({**lk, "source_label": "open-ctem", "columns": [], "rows": [], "count": 0,
                        "error": "open-ctem could not run this lookup"})
    return out


async def investigate(db: AsyncSession, question: str, time_range: str = "7d",
                      progress: Callable[[str], None] = lambda s: None, always: list[dict] | None = None) -> dict:
    """always: lookups that run every time, whatever plan is reused (the dashboard watch always reads the alerts)."""
    time_range = time_range if time_range in TIME_RANGES else "7d"
    earliest, label = TIME_RANGES[time_range], TIME_LABELS[time_range]
    notes: list[str] = []

    progress("Checking which tools are connected")
    splunk_cfg = (await _enabled(db, ["splunk"], live=True) or [None])[0]
    from api.integrations.base import get_connector
    splunk = get_connector("splunk", splunk_cfg.config) if splunk_cfg else None
    tools = await _enabled(db, ALERT_VENDORS)
    await _refresh_alert_tools(db, tools)
    sources = (["Splunk (live search)"] if splunk else []) + \
              [f"{_LABELS.get(t.vendor.value, t.vendor.value)} alerts" for t in tools] + \
              ["open-ctem devices, users, vulnerabilities and alerts"]

    schema = await load_schema(db)
    if splunk and schema is None:
        progress("Mapping what is in Splunk (first time only)")
        await refresh_schema(splunk, db)
        schema = await load_schema(db)
    splunk_map = describe(schema) if splunk else "(Splunk is not connected.)"
    ctem_map = ctem_data.describe(await ctem_data.row_counts(db))
    fp = memory.schema_print(schema)
    ai = await hunt_ai.get_ai(db)
    if ai is not None:
        from api.core.ai_usage import AIBudgetExceeded, guard
        try:
            await guard()
        except AIBudgetExceeded as exc:
            notes.append(str(exc) + " Keyword searches were used instead.")
            ai = None

    base = {"question": question, "time_range": time_range, "sources": sources, "notes": notes}
    if ai is None:
        progress("Searching (AI is off, using keywords and the curated rules)")
        results = await _run(db, splunk, _vet(fallback.plan(question, schema if splunk else None), notes), earliest)
        from api.hunt import curated
        rule_issues, rule_lookups, _ = await curated.run(db, splunk, time_range, first_lookup=len(results) + 1)
        if rule_issues:
            notes.append(f"{len(rule_issues)} Threat Curated Rule{'s' if len(rule_issues) != 1 else ''} matched.")
        return {**base, "mode": "keyword", "summary": "", "issues": rule_issues,
                "lookups": for_ui(results + rule_lookups)}

    saved = await memory.load_plan(db, question, fp)
    if saved:
        skipped = []
        lookups = _vet(saved, skipped)
        if skipped or not lookups:
            saved = None  # a saved plan that no longer passes the rules gets re-planned
        else:
            notes.append("Reused saved searches for this question, so no AI planning was needed.")
    from_ai = False
    if not saved:
        progress("Deciding where to look")
        lookups = _vet(await hunt_ai.plan(ai, question, splunk_map, ctem_map, label), notes)
        from_ai = bool(lookups)
        if not lookups:
            notes.append("The AI could not plan searches, so keyword searches were used.")
            lookups = _vet(fallback.plan(question, schema if splunk else None), notes)

    if always:   # never part of the saved plan, so a reused plan can't drop them
        have = {(lk.get("table"), str(lk.get("filters"))) for lk in lookups}
        lookups = lookups + [lk for lk in _vet(always, notes) if (lk.get("table"), str(lk.get("filters"))) not in have]
    progress("Searching every connected source")
    results = await _run(db, splunk, lookups, earliest)
    # Curated rules first: what they explain is already an issue, for free, and the AI isn't paid to see it again
    from api.hunt import curated
    progress("Running the Threat Curated Rules")
    rule_issues, rule_lookups, explained = await curated.run(db, splunk, time_range, first_lookup=len(results) + 1)
    if explained:
        for r in results:
            if r.get("table") == "alerts" and r.get("rows"):
                r["rows"] = [row for row in r["rows"] if row.get("alert_key") not in explained]
                r["count"] = len(r["rows"])
    if rule_issues:
        notes.append(f"{len(rule_issues)} Threat Curated Rule{'s' if len(rule_issues) != 1 else ''} matched, with no AI tokens spent on them.")

    if not saved:
        progress("Following the leads")
        more = _vet(await hunt_ai.follow_leads(ai, question, splunk_map, ctem_map, evidence_brief(results)), notes)
        if more:
            results += await _run(db, splunk, more, earliest)
        if from_ai:  # keyword fallbacks are never saved as if the AI had chosen them; the "always" lookups aren't plan
            fixed = {(lk.get("table"), str(lk.get("filters"))) for lk in _vet(always or [], [])}
            await memory.save_plan(db, question, fp, [r for r in results if not r.get("error")
                                                      and (r.get("table"), str(r.get("filters"))) not in fixed])

    evidence = evidence_brief(results)
    key = memory.answer_key(question, time_range, evidence)
    answer = memory.cached_answer(key)
    left = sum(r.get("count") or 0 for r in results if not r.get("error"))
    if answer:
        notes.append("Same evidence as a recent hunt, so the earlier write-up was reused.")
    elif rule_issues and not left:
        notes.append("The curated rules explained everything found, so the AI wasn't needed.")
        answer = {"summary": f"{len(rule_issues)} curated detection{'s' if len(rule_issues) != 1 else ''} matched; "
                             "nothing else needed a closer look.", "issues": []}
    else:
        progress("Writing up what happened")
        raw = await hunt_ai.write_up(ai, question, evidence, label)
        answer = hunt_ai.clean_write_up(raw, len(results)) if raw else None
        if answer:
            memory.store_answer(key, answer)
    if not answer:
        notes.append("The AI write-up failed, so only the raw results are shown.")
        answer = {"summary": "", "issues": []}
    answer = {**answer, "issues": [dict(i) for i in answer["issues"]]}   # a cached answer stays as it was
    learned = await curated.learn(db, answer["issues"], question)
    if learned:
        notes.append(f"Saved {learned} new Threat Curated Rule{'s' if learned != 1 else ''}, so this is caught for free next time.")
    for i in answer["issues"]:
        i.pop("rule_draft", None)
    results += rule_lookups
    answer["issues"] = rule_issues + answer["issues"]

    for issue in answer["issues"]:
        win = window.around(t["time"] for t in issue["timeline"])
        spls = [results[n - 1]["spl"] for n in issue["lookups"] if results[n - 1].get("spl")]
        issue["splunk"] = [window.for_splunk(s, win) for s in spls] if win else spls
        issue["window"] = list(win) if win else None
        issue["window_label"] = window.label(win) if win else ""
    return {**base, "mode": "ai", **answer, "lookups": for_ui(results)}
