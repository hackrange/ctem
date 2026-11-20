"""What lives in Splunk, mapped at sync time and explained once by AI."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.settings import AppSetting

log = logging.getLogger("open-ctem.hunt")

SCHEMA_KEY = "splunk_hunt_schema"
_NOISE = {"punct", "linecount", "splunk_server", "timestartpos", "timeendpos", "eventtype",
          "tag", "index", "splunk_server_group", "date_hour", "date_mday", "date_minute",
          "date_month", "date_second", "date_wday", "date_year", "date_zone", "timestamp"}


async def load_schema(db: AsyncSession) -> dict | None:
    row = (await db.execute(select(AppSetting).where(AppSetting.key == SCHEMA_KEY))).scalar_one_or_none()
    try:
        return json.loads(row.value) if row and row.value else None
    except ValueError:
        return None


async def _save(db: AsyncSession, schema: dict) -> None:
    row = (await db.execute(select(AppSetting).where(AppSetting.key == SCHEMA_KEY))).scalar_one_or_none()
    row = row or AppSetting(key=SCHEMA_KEY, is_sensitive=False)
    row.value = json.dumps(schema)
    db.add(row)
    await db.commit()


_TYPE_FIELDS = ("event_simpleName", "EventCode", "event_type", "eventtype_name", "action", "sourcetype")
_HEXISH = re.compile(r"^[0-9a-fA-F]{16,}$|^[0-9a-z]{28,}$")


async def _summarize(conn, spl: str) -> dict:
    fields = {}
    for r in await conn.run_search(spl, earliest="0", max_rows=150):
        field = r.get("field", "")
        if not field or field.startswith("_") or field in _NOISE or field.startswith("date_"):
            continue
        try:
            vals = [str(v.get("value"))[:40] for v in json.loads(r.get("values") or "[]")]
        except (ValueError, AttributeError):
            vals = []
        distinct = int(float(r.get("distinct_count") or 0))
        if distinct > 25:  # ids and hashes teach the AI nothing and cost tokens
            vals = [v for v in vals if not _HEXISH.match(v)][:2]
        fields[field] = {"distinct": distinct, "samples": vals[:10]}
    return fields


async def _map_index(conn, name: str) -> dict:
    """Sample a few events of every event type across all time, not just the newest.

    The newest few thousand events are routine noise; the detection or lockout
    the analyst cares about is rare, and so are the fields that only it carries.
    """
    fs = "| fieldsummary maxvals=10 | fields field count distinct_count values"
    fields = await _summarize(conn, f"search index={name} | head 3000 {fs}")
    type_field = next((t for t in _TYPE_FIELDS if t in fields), None)
    types = {}
    if type_field:
        fields.update(await _summarize(conn, f"search index={name} | dedup 20 {type_field} {fs}"))
        for r in await conn.run_search(f"search index={name} | stats count by {type_field} | sort -count",
                                       earliest="0", max_rows=40):
            types[str(r.get(type_field))[:60]] = int(float(r.get("count") or 0))
    top = dict(sorted(fields.items(), key=lambda kv: kv[1]["distinct"] > 25)[:60])
    fp = hashlib.sha256(json.dumps({"t": sorted(types), "f": sorted(top)}).encode()).hexdigest()[:16]
    return {"fields": top, "type_field": type_field, "types": types, "fingerprint": fp}


async def refresh_schema(conn, db: AsyncSession) -> None:
    """Re-map Splunk; only indexes whose shape changed go to the AI for notes."""
    try:
        indexes = [i for i in await conn.list_indexes()
                   if i.get("name") and not i["name"].startswith("_") and int(i.get("totalEventCount") or 0) > 0]
        old = (await load_schema(db) or {}).get("indexes", {})
        new = {}
        for i in indexes:
            mapped = await _map_index(conn, i["name"])
            mapped.update(events=int(i.get("totalEventCount") or 0),
                          first=i.get("minTime"), last=i.get("maxTime"))
            prev = old.get(i["name"], {})
            if prev.get("fingerprint") == mapped["fingerprint"] and prev.get("notes"):
                mapped["notes"] = prev["notes"]
            new[i["name"]] = mapped
        await _annotate(db, new)
        await _save(db, {"built_at": datetime.now(timezone.utc).isoformat(), "indexes": new})
        log.info("hunt schema mapped: %d indexes", len(new))
    except Exception:
        log.exception("hunt schema refresh failed")


async def _annotate(db: AsyncSession, indexes: dict) -> None:
    from api.hunt.ai import ask_json, get_ai
    todo = {k: v for k, v in indexes.items() if not v.get("notes")}
    if not todo:
        return
    ai = await get_ai(db)
    if ai is None:
        return
    # One small call per changed index: a single giant reply gets cut off mid-JSON
    for name, idx in todo.items():
        brief = {"index": name, "event_type_field": idx.get("type_field"),
                 "event_types": idx.get("types"),
                 "fields": {f: v["samples"][:4] for f, v in idx["fields"].items()}}
        prompt = (
            "Explain this Splunk index for a security analyst in plain words. Return JSON: "
            '{"summary": "one sentence", "event_types": {"<value>": "what it means, under 10 words"}, '
            '"key_fields": {"<field>": "what it holds, under 8 words"}}. '
            "Describe every event type listed and only the 15 most useful fields.\n\n"
            + json.dumps(brief)[:9000]
        )
        note = await ask_json(ai, prompt, max_tokens=3000)
        if isinstance(note, dict):
            idx["notes"] = {
                "summary": str(note.get("summary", ""))[:300],
                "event_types": {str(k)[:60]: str(v)[:120] for k, v in list((note.get("event_types") or {}).items())[:40]},
                "key_fields": {str(k)[:60]: str(v)[:100] for k, v in list((note.get("key_fields") or {}).items())[:20]},
            }


def describe(schema: dict | None) -> str:
    """The compact Splunk map the planner reads."""
    if not schema:
        return "(Splunk is not connected or has not been mapped yet.)"
    out = []
    for name, idx in schema.get("indexes", {}).items():
        notes = idx.get("notes") or {}
        out.append(f"- index={name} ({idx.get('events', 0)} events, {idx.get('first')} to {idx.get('last')})"
                   + (f": {notes['summary']}" if notes.get("summary") else ""))
        meaning = notes.get("event_types") or {}
        if idx.get("types"):
            out.append(f"    event types ({idx.get('type_field')}=value: count, meaning):")
            for value, count in idx["types"].items():
                out.append(f"      {value}: {count}" + (f", {meaning[value]}" if meaning.get(value) else ""))
        fields = []
        for f, meta in idx.get("fields", {}).items():
            hint = (notes.get("key_fields") or {}).get(f)
            sample = ", ".join(meta["samples"][:3])
            fields.append(f"{f}" + (f" ({hint})" if hint else "") + (f" e.g. {sample}" if sample else ""))
        out.append("    fields: " + "; ".join(fields)[:3000])
    return "\n".join(out)
