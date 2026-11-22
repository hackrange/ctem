"""Store hunting data from the shipper: threat intel indicators, EDR stream events and fleet stacks (FDR).

Each stack's domain, IP and hash are checked against the stored indicators; a match marks the stack and raises a
high-fidelity "intel_match" alert for the SIEM feed (api/core/alert_feed.py). So does a remote response session
opened on a host from the EDR's console ("rtr_session"). Everything is kept RETENTION_DAYS (prune())."""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

RETENTION_DAYS = int(os.environ.get("HUNT_RETENTION_DAYS", "30"))
_INTEL_FOR = {"dns": ("domain",), "network": ("ip_address",), "process": ("hash_sha256",)}
RTR = ("RemoteResponseSessionStartEvent",)


def _dt(v):
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")) if v else None
    except ValueError:
        return None


async def intel(db: AsyncSession, rows: list[dict], source: str = "crowdstrike") -> int:
    from api.models.hunt_data import IntelIndicator
    if not rows:
        return 0
    have = {(i.type, i.value): i for i in (await db.execute(select(IntelIndicator).where(
        IntelIndicator.source == source, IntelIndicator.value.in_([r["value"] for r in rows])))).scalars()}
    for r in rows:
        i = have.get((r["type"], r["value"]))
        if i is None:
            i = IntelIndicator(source=source, type=r["type"], value=r["value"])
            db.add(i)
            have[(r["type"], r["value"])] = i
        i.confidence, i.actors, i.malware, i.labels = r.get("confidence"), r.get("actors"), r.get("malware"), r.get("labels")
        i.published, i.updated = _dt(r.get("published")), _dt(r.get("updated"))
    await db.flush()
    return len(rows)


async def stream_events(db: AsyncSession, rows: list[dict], source: str = "crowdstrike") -> int:
    from api.core.alert_feed import _add, existing
    from api.models.hunt_data import EdrEvent
    if not rows:
        return 0
    seen = {(e.partition, e.offset) for e in (await db.execute(select(EdrEvent).where(
        EdrEvent.source == source, EdrEvent.offset.in_([r["offset"] for r in rows])))).scalars()}
    now, n = datetime.now(timezone.utc), 0
    have = await existing(db, [f"rtr_session:{source}:{r['partition']}:{r['offset']}" for r in rows if r["type"] in RTR])
    for r in rows:
        if (r["partition"], r["offset"]) in seen:
            continue
        seen.add((r["partition"], r["offset"]))
        db.add(EdrEvent(source=source, partition=r["partition"], offset=r["offset"], type=r["type"], at=_dt(r.get("at")) or now,
                        hostname=r.get("hostname"), user=r.get("user"), summary=r.get("summary"), severity=r.get("severity"),
                        event=r.get("event")))
        n += 1
        if r["type"] in RTR:
            await _add(db, have, f"rtr_session:{source}:{r['partition']}:{r['offset']}", "rtr_session", "medium",
                       f"Remote response session opened on {r.get('hostname') or 'a host'} by {r.get('user') or 'someone'}",
                       {"hostname": r.get("hostname"), "user": r.get("user"), "at": r.get("at"), "source": source})
    await db.flush()
    return n


async def stacks(db: AsyncSession, rows: list[dict]) -> int:
    from api.core.alert_feed import _add, existing
    from api.models.hunt_data import HOSTS_CAP, HuntStack, IntelIndicator
    if not rows:
        return 0
    keys = [(date.fromisoformat(r["day"]), r["key"]) for r in rows]
    have = {(s.day, s.key): s for s in (await db.execute(select(HuntStack).where(
        HuntStack.key.in_([k for _, k in keys]), HuntStack.day.in_({d for d, _ in keys})))).scalars()}
    # What to check against the indicators: domains as they are, an IP without its port, a file by its hash
    probe = {}
    for r in rows:
        v = r["sha256"] if r["kind"] == "process" else r["value"].rsplit(":", 1)[0] if r["kind"] == "network" else r["value"]
        if v and r["kind"] in _INTEL_FOR:
            probe.setdefault(v.lower(), set()).update(_INTEL_FOR[r["kind"]])
    hits = {}
    if probe:
        for i in (await db.execute(select(IntelIndicator).where(IntelIndicator.value.in_(list(probe))))).scalars():
            if i.type in probe.get(i.value, ()):
                hits[i.value] = i
    alerted = await existing(db, [f"intel_match:{r['day']}:{r['key']}" for r in rows]) if hits else set()
    for r in rows:
        day = date.fromisoformat(r["day"])
        s = have.get((day, r["key"]))
        if s is None:
            s = HuntStack(day=day, kind=r["kind"], key=r["key"], value=r["value"][:512], sha256=r.get("sha256"),
                          fields=r.get("fields") or None, hosts=[], host_count=0, events=0)
            db.add(s)
            have[(day, r["key"])] = s
        hosts = list(dict.fromkeys([*(s.hosts or []), *r.get("hosts", [])]))
        s.hosts = hosts[:HOSTS_CAP]
        s.host_count = max(s.host_count or 0, len(hosts))
        s.events = (s.events or 0) + int(r.get("events") or 0)
        utc = lambda t: t.replace(tzinfo=timezone.utc) if t is not None and t.tzinfo is None else t  # noqa: E731
        fs, ls = _dt(r.get("first_seen")), _dt(r.get("last_seen"))
        s.first_seen = min(filter(None, [utc(s.first_seen), utc(fs)]), default=None)
        s.last_seen = max(filter(None, [utc(s.last_seen), utc(ls)]), default=None)
        v = (r.get("sha256") if r["kind"] == "process" else r["value"].rsplit(":", 1)[0] if r["kind"] == "network" else r["value"]) or ""
        ind = hits.get(v.lower())
        if ind is not None:
            s.intel_hit = True
            await _add(db, alerted, f"intel_match:{day.isoformat()}:{r['key']}", "intel_match", "high",
                       f"Threat intel match: {r['kind']} {r['value'][:200]} on {len(hosts)} host(s)",
                       {"kind": r["kind"], "value": r["value"][:512], "indicator": ind.value, "indicator_type": ind.type,
                        "confidence": ind.confidence, "actors": ind.actors, "malware": ind.malware, "day": day.isoformat(),
                        "edr_host_ids": hosts[:20], "host_count": len(hosts)})
    await db.flush()
    return len(rows)


async def prune(db: AsyncSession) -> int:
    from api.models.hunt_data import EdrEvent, HuntStack, IntelIndicator
    cut = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    n = (await db.execute(delete(HuntStack).where(HuntStack.day < cut.date()))).rowcount or 0
    n += (await db.execute(delete(EdrEvent).where(EdrEvent.at < cut))).rowcount or 0
    n += (await db.execute(delete(IntelIndicator).where(IntelIndicator.updated < cut - timedelta(days=60)))).rowcount or 0
    await db.commit()
    return n
