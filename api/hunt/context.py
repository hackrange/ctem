"""Weigh a Threat Curated Rule hit against what CTEM already knows before it becomes a finding.

A rule says "this pattern can be an attack"; context says whether this time looks like one:
- the tool's own severity: alerts it rates informational are never high confidence, low ones at most medium
- new or established: a detection seen steadily for two weeks or more, without spreading to new hosts faster, is
  routine; one first seen inside the hunt's range is new and says so
- what people decided: most of the detection's earlier alerts closed in the tool means they were looked at
- how it spread: one account on several hosts is how intrusions move, and so is a detection new here reaching
  several new hosts within two days; either keeps confidence high whatever else says. An established detection
  where each person is on their own machine is people using a tool, and lowers it, even if a few joined at once

Each step down lowers confidence by one (high, medium, low); the reasons go into the finding so nothing is hidden,
and anything that drops below the watch's bar still shows in on-demand hunts. Only stored alerts are read."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

LADDER = ("low", "medium", "high")
RANK = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ESTABLISHED_DAYS = 14
BURST_HOURS, BURST_HOSTS = 48, 3
CLOSED_SHARE, CLOSED_MIN = 0.5, 5


def _at(s) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _key(a: dict) -> tuple:
    return ((a.get("title") or "").strip().lower(), a.get("source") or "")


def _plural(n: int, word: str) -> str:
    return f"{n} {word if n == 1 else {'person': 'people'}.get(word, word + 's')}"


def weigh(hits: list[dict], history: list[dict], since: datetime, now: datetime | None = None) -> dict:
    """hits: the rule's alerts in the hunt's range; history: every stored alert. Returns {"confidence", "notes"}."""
    now = now or datetime.now(timezone.utc)
    keys = {_key(h) for h in hits}
    past = [a for a in history if _key(a) in keys]
    times = [t for t in (_at(a.get("detected_at")) for a in past) if t]
    first = min(times) if times else None
    hosts_before = {(a.get("hostname") or "").lower() for a in past
                    if (t := _at(a.get("detected_at"))) and t < since and a.get("hostname")}
    hit_hosts = {(h.get("hostname") or "").lower() for h in hits if h.get("hostname")}
    new_hosts = hit_hosts - hosts_before
    down, notes, escalate = 0, [], []

    ranks = [RANK[s] for s in (str(h.get("severity") or "").lower() for h in hits) if s in RANK]
    cap = 2
    if ranks and max(ranks) == 0:
        cap = 0
        notes.append(f"{_vendor(hits)} rates {'it' if len(hits) == 1 else 'all of them'} informational")
    elif ranks and max(ranks) == 1:
        cap = 1
        notes.append(f"{_vendor(hits)} rates {'it' if len(hits) == 1 else 'them'} low at most")

    established = bool(first and first <= now - timedelta(days=ESTABLISHED_DAYS))
    if established and len(new_hosts) <= 1:
        down += 1
        notes.append(f"seen steadily since {first:%b %d} on {_plural(len(hosts_before | hit_hosts), 'host')}, "
                     f"{'no new host' if not new_hosts else 'one new host'} in this range")
    elif first and first >= since:
        notes.append(f"first seen {first:%b %d}: new here")

    closed = sum(1 for a in past if str(a.get("status") or "").lower() == "closed")
    if len(past) >= CLOSED_MIN and closed / len(past) >= CLOSED_SHARE:
        down += 1
        notes.append(f"{closed} of {len(past)} already closed in {_vendor(hits)}")

    by_person: dict[str, set] = {}
    for h in hits:
        if h.get("user_key") and h.get("hostname"):
            by_person.setdefault(h["user_key"], set()).add(h["hostname"].lower())
    spread = max((len(v) for v in by_person.values()), default=0)
    recent = [t for t in (_at(h.get("detected_at")) for h in hits if (h.get("hostname") or "").lower() in new_hosts) if t]
    burst = bool(len(new_hosts) >= BURST_HOSTS and recent and max(recent) - min(recent) <= timedelta(hours=BURST_HOURS))
    own_machines = len(by_person) >= 2 and spread == 1
    if spread >= 3:
        escalate.append(f"one account on {spread} hosts")
    if burst and not (established and own_machines):
        escalate.append(f"reached {_plural(len(new_hosts), 'new host')} within {BURST_HOURS} hours")
    if own_machines and not escalate:
        down += 1
        notes.append(f"{_plural(len(by_person), 'person')}, each on their own machine"
                     + (f" ({_plural(len(new_hosts), 'new host')} this range)" if new_hosts else ""))

    conf = "high" if escalate else LADDER[max(0, min(cap, 2 - down))]
    return {"confidence": conf, "notes": escalate + notes, "escalated": bool(escalate)}


def _vendor(hits: list[dict]) -> str:
    srcs = {h.get("source") for h in hits if h.get("source")}
    return {"crowdstrike": "CrowdStrike", "sentinelone": "SentinelOne", "msdefender": "Defender"}.get(
        next(iter(srcs)) if len(srcs) == 1 else "", "the tool")


def explain(ctx: dict) -> str:
    """One sentence for the finding."""
    if not ctx["notes"]:
        return ""
    lead = "Raised" if ctx["escalated"] else ("Kept" if ctx["confidence"] == "high" else "Lowered to " + ctx["confidence"] + " confidence")
    return f" {lead}: " + "; ".join(ctx["notes"]) + "."
