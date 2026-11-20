"""Click a user, computer, or IP: everything known about it, in one place."""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.encryption import search_hash
from api.hunt import ctem_data, memory, window
from api.hunt.fallback import entity_filter
from api.hunt.results import splunk_table
from api.hunt.scope import notable_clause, scoped
from api.hunt.spl_guard import vet_spl
from api.models.device import Device
from api.models.risk import RiskScoreHistory

_VALUE = re.compile(r"^[A-Za-z0-9._@\\ -]{1,128}$")
_LABELS = {
    "4624": "Signed in", "4625": "Failed sign-in", "4634": "Signed out", "4648": "Signed in as someone else",
    "4672": "Used admin rights", "4688": "Started a program", "4698": "Scheduled task created",
    "4720": "Account created", "4728": "Added to admin group", "4732": "Added to local admins",
    "4740": "Account locked out", "4756": "Added to universal group", "4768": "Asked for a sign-in ticket",
    "4769": "Asked for a service ticket", "4771": "Sign-in ticket failed", "7045": "New service installed",
    "ProcessRollup2": "Program ran", "NetworkConnectIP4": "Network connection", "DnsRequest": "Website lookup",
    "DetectionSummaryEvent": "EDR detection", "network_flow": "Network traffic",
    "incident": "Segmentation incident", "policy_violation": "Broke a network rule",
}
_EVENT_COLS = "_time index host EventCode event_simpleName event_type TargetUserName IpAddress WorkstationName " \
              "ComputerName UserName FileName CommandLine Technique source_asset destination_asset " \
              "destination_port description"


def check(kind: str, value: str) -> str:
    value = (value or "").strip()
    if kind not in ("user", "host", "ip"):
        raise ValueError("kind must be user, host, or ip")
    if kind == "ip":
        return str(ipaddress.ip_address(value))
    if not _VALUE.match(value):
        raise ValueError("that name has characters we don't search on")
    return value


def _label(kind: str, schema: dict | None) -> str:
    """Short built-in label first; the AI's description only for types we don't know."""
    if kind in _LABELS:
        return _LABELS[kind]
    for idx in ((schema or {}).get("indexes") or {}).values():
        note = ((idx.get("notes") or {}).get("event_types") or {}).get(kind)
        if note:
            note = note.rstrip(".")
            return note if len(note) <= 32 else note[:32].rsplit(" ", 1)[0] + "..."
    return kind


async def _splunk(splunk, schema, kind, value, earliest, win) -> dict:
    fields, filt = entity_filter(kind, value)
    notable = notable_clause(schema)
    q = {
        "trend": scoped(schema, fields, f"{filt} | eval kind=coalesce(event_simpleName, event_type, EventCode, sourcetype) "
                                        "| bin _time span=1d | stats count by _time kind"),
        "events": scoped(schema, fields, f"{filt} {notable} | sort - _time | table {_EVENT_COLS}"),
        "related": scoped(schema, fields, f"{filt} | eval h=coalesce(ComputerName, WorkstationName, source_asset, host), "
                                          "i=coalesce(IpAddress, aip, source_ip), u=coalesce(TargetUserName, UserName, SubjectUserName) "
                                          "| stats count by h i u | sort -count"),
    }
    out = {"spl": {}}
    for name, spl in q.items():
        if not spl:
            continue
        spl = vet_spl(spl, max_rows=500 if name != "events" else 100)
        span = win if (name == "events" and win) else None
        rows = await splunk.run_search(spl, earliest=str(span[0]) if span else earliest,
                                       latest=str(span[1]) if span else "now", max_rows=500)
        out[name] = rows
        out["spl"][name] = window.for_splunk(spl, span) if span else spl
    return out


def _trend(rows: list[dict], schema) -> dict:
    days, series = set(), defaultdict(Counter)
    for r in rows:
        day = str(r.get("_time", ""))[:10]
        days.add(day)
        series[_label(str(r.get("kind")), schema)][day] += int(float(r.get("count") or 0))
    days = sorted(days)
    totals = {k: sum(v.values()) for k, v in series.items()}
    top = sorted(totals, key=totals.get, reverse=True)[:6]
    return {"days": days, "series": {k: [series[k][d] for d in days] for k in top}, "totals": totals}


def _loopback(v: str) -> bool:
    try:
        return ipaddress.ip_address(v).is_loopback
    except ValueError:
        return v == "-"


def _related(rows: list[dict], kind: str, value: str) -> dict:
    hosts, ips, users = Counter(), Counter(), Counter()
    for r in rows:
        n = int(float(r.get("count") or 0))
        if r.get("h"):
            hosts[r["h"]] += n
        if r.get("i") and not _loopback(r["i"]):
            ips[r["i"]] += n
        if r.get("u") and r["u"] not in ("-", "SYSTEM"):
            users[str(r["u"]).split("\\")[-1]] += n
    me = value.lower().split("\\")[-1]
    pick = lambda c: [{"value": k, "count": v} for k, v in c.most_common(12) if k.lower() != me]
    return {"hosts": pick(hosts), "ips": pick(ips), "users": pick(users)}


async def _records(db: AsyncSession, kind: str, value: str) -> dict:
    out: dict = {}
    if kind == "user":
        bare = value.split("\\")[-1]
        out["record"] = (await ctem_data.lookup(db, "users", {"username": bare}, 1) or [None])[0]
        out["identity"] = await ctem_data.lookup(db, "identity_threats", {"user": f"*{bare}*"}, 25)
        devs = (await db.execute(select(Device.hostname).where(Device.last_login_user_hash == search_hash(bare)).limit(20))).scalars()
        out["computers"] = list(devs)
    elif kind == "host":
        out["record"] = (await ctem_data.lookup(db, "devices", {"hostname": value}, 1) or [None])[0]
        out["vulns"] = await ctem_data.lookup(db, "findings", {"hostname": value}, 25)
        out["paths"] = (await ctem_data.lookup(db, "attack_paths", {"from_host": value}, 25)
                        + await ctem_data.lookup(db, "attack_paths", {"to_host": value}, 25))
        out["alerts"] = await ctem_data.lookup(db, "alerts", {"hostname": value}, 25)
        dev = (await db.execute(select(Device.id).where(Device.hostname.ilike(value)))).scalar_one_or_none()
        if dev:
            hist = (await db.execute(select(RiskScoreHistory).where(
                RiskScoreHistory.entity_type == "device", RiskScoreHistory.entity_id == dev)
                .order_by(RiskScoreHistory.recorded_at).limit(90))).scalars()
            out["risk_history"] = [{"day": h.recorded_at.strftime("%Y-%m-%d"), "score": h.score, "grade": h.grade} for h in hist]
    else:
        out["record"] = (await ctem_data.lookup(db, "devices", {"ip": value}, 1) or [None])[0]
        out["alerts"] = await ctem_data.lookup(db, "alerts", {"text": value}, 25)
    return out


async def build(db: AsyncSession, kind: str, value: str, earliest: str, around: dict | None,
                splunk, schema, ai) -> dict:
    value = check(kind, value)
    win = window.around([(around or {}).get("first"), (around or {}).get("last")]) if around else None
    prof = {"kind": kind, "value": value, "window_label": window.label(win) if win else "", **await _records(db, kind, value)}
    if splunk and schema:
        sp = await _splunk(splunk, schema, kind, value, earliest, win)
        prof["trend"] = _trend(sp.get("trend", []), schema)
        cols, rows = splunk_table(sp.get("events", []))
        prof["events"] = {"columns": cols, "rows": rows[:100], "count": len(rows)}
        prof["related"] = _related(sp.get("related", []), kind, value)
        prof["spl"] = sp["spl"]
    prof["summary"] = await _summary(ai, prof) if ai else ""
    return prof


async def _summary(ai, prof: dict) -> str:
    from api.hunt.ai import ask_json
    brief = {k: prof.get(k) for k in ("kind", "value", "record", "computers", "related", "risk_history")}
    brief["activity_totals"] = (prof.get("trend") or {}).get("totals")
    brief["notable_events"] = (prof.get("events") or {}).get("rows", [])[:15]
    brief["vulns"] = (prof.get("vulns") or [])[:10]
    brief["paths"] = (prof.get("paths") or [])[:5]
    brief["alerts"] = (prof.get("alerts") or [])[:10]
    brief["identity"] = (prof.get("identity") or [])[:10]
    text = json.dumps(brief, default=str)[:14000]
    key = memory.answer_key("profile", prof["kind"] + prof["value"], text)
    cached = memory.cached_answer(key)
    if cached:
        return cached.get("summary", "")
    out = await ask_json(ai, "In plain words a 5th grader can follow, sum up what this data says about this "
                             f"{prof['kind']} in 3-4 short sentences: who or what it is, anything unusual, and "
                             'how worried to be. Return {"summary": "..."}\n\n' + text, max_tokens=2500)
    summary = str((out or {}).get("summary", ""))[:1200] if isinstance(out, dict) else ""
    if summary:
        memory.store_answer(key, {"summary": summary})
    return summary
