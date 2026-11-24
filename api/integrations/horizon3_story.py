"""How NodeZero got in, and what it got to: the proof behind each exploited weakness, and each attack path as the
ordered chain NodeZero walked (launch, host, service, weakness, impact). Field names were confirmed against the live
API, which allows no introspection. Read only: queries, never mutations (api/integrations/horizon3.py refuses those).

Proofs are kept on the finding (its details are encrypted at rest); attack paths in attack_paths, one row per path
per asset it runs through, with the chain in an encrypted column. Only what's real now is kept: a path through a
weakness while NodeZero still has that weakness open, a path through credentials alone while its pentest is recent.
Anything else is deleted, and so is an asset only NodeZero knew once nothing of NodeZero's is left on it."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from sqlalchemy import select

log = logging.getLogger("open-ctem.horizon3")
SOURCE = "horizon3"
KEEP_PATHS = 25            # per asset, newest first
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# Long secret-looking runs NodeZero didn't already mask, and header values that carry credentials
_TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
_HEADER = re.compile(r"(?im)^((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*)(.+)$")

PATHS_QUERY = """query q($op_id: String!, $page_input: PageInput) { attack_paths_page(input: {op_id: $op_id}, page_input: $page_input) {
  attack_paths { uuid attack_path_title score severity impact_type impact_title impact_description affected_asset_text
  time_to_finding_s created_at hosts { ip host_name } weaknesses { uuid vuln_id ip port }
  attack_vector { attack_graph { nodes { uuid label description created_at } edges { source target } } } } } }"""


def redact(text: str | None, limit: int) -> str | None:
    if not text:
        return None
    out = _HEADER.sub(lambda m: m.group(1) + "[redacted]", str(text))
    out = _TOKEN.sub(lambda m: m.group(0)[:4] + "…[redacted]", out)
    return out[:limit] + ("…" if len(out) > limit else "")


def proof_of(w: dict, op: dict) -> dict | None:
    """What NodeZero ran to prove a weakness and what came back, from one pentest."""
    shown = []
    for p in w.get("proofs") or []:
        for co in p.get("command_outputs") or []:
            if co.get("command") or co.get("output"):
                shown.append({"command": redact(co.get("command"), 1000), "output": redact(co.get("output"), 4000)})
    proofs = w.get("proofs") or [{}]
    return {"pentest": str(op.get("name") or "")[:200], "pentest_id": str(op.get("op_id") or "")[:64],
            "at": proofs[0].get("created_at") or w.get("created_at"), "kind": str(proofs[0].get("proof_type") or "")[:64] or None,
            "found_after_s": w.get("time_to_finding_s") if isinstance(w.get("time_to_finding_s"), (int, float)) else None,
            "port": w.get("port") if isinstance(w.get("port"), int) else None, "steps": shown[:3]}


def steps_of(graph: dict | None) -> list[dict]:
    """The chain in the order NodeZero walked it: from its launch node along the edges, impacts last."""
    nodes = {n.get("uuid"): n for n in (graph or {}).get("nodes") or [] if n.get("uuid")}
    nxt: dict = {}
    for e in (graph or {}).get("edges") or []:
        nxt.setdefault(e.get("source"), []).append(e.get("target"))
    targets = {t for ts in nxt.values() for t in ts}
    roots = [u for u, n in nodes.items() if n.get("label") == "NodeZero"] or [u for u in nodes if u not in targets]
    order, seen, queue = [], set(), list(roots)
    while queue:   # breadth first: every hop after the one it came from
        u = queue.pop(0)
        if u in seen or u not in nodes:
            continue
        seen.add(u)
        order.append(u)
        queue += sorted(nxt.get(u, []), key=lambda t: str(nodes.get(t, {}).get("created_at") or "~"))
    order += [u for u in nodes if u not in seen]   # anything the edges didn't reach still shows
    out = []
    for u in order:
        n = nodes[u]
        label = "Impact" if n.get("label") == "ImpactEdge" else str(n.get("label") or "")[:32]
        out.append({"kind": label, "text": redact(n.get("description"), 400), "at": n.get("created_at"),
                    "ips": _IP.findall(str(n.get("description") or ""))[:4]})
    return out[:40]


def is_active(pairs, completed, still_open: set | None, recent) -> bool:
    """Real now: one of its weaknesses is still open in NodeZero; with no weakness (credentials only), its pentest is recent."""
    if still_open is None:
        return True
    if pairs:
        return any((ip, v) in still_open for ip, v in pairs)
    return bool(completed) and _when(completed) >= recent


async def save_paths(db, op: dict, paths: list[dict], find, still_open: set | None, recent=None) -> int:
    """Each path that's real now, on every asset it runs through. find(ip, name) -> the CTEM asset or None (never
    creates one). still_open: (ip, weakness id) NodeZero has open, or None when the API gave no series."""
    from api.models.risk import AttackPath
    when = _when(op.get("completed_at"))
    n = 0
    for p in paths:
        steps = steps_of((p.get("attack_vector") or {}).get("attack_graph"))
        assets = {}
        for h in p.get("hosts") or []:
            d = await find(h.get("ip"), h.get("host_name"))
            if d is not None:
                assets[str(d.id)] = d
        for w in p.get("weaknesses") or []:
            d = await find(w.get("ip"), None)
            if d is not None:
                assets.setdefault(str(d.id), d)
        for s in steps:   # link each host on the chain to its asset page
            for ip in s["ips"]:
                d = await find(ip, None)
                if d is not None:
                    s.setdefault("assets", {})[ip] = str(d.id)
        weak = {(w.get("ip"), str(w.get("vuln_id") or "")[:200]) for w in p.get("weaknesses") or []}
        pairs = [(ip, v) for ip, v in weak if ip and v]
        if not is_active(pairs, op.get("completed_at"), still_open, recent or datetime.min.replace(tzinfo=timezone.utc)):
            continue   # fixed since, or an old credential path: not shown, not kept
        ext = f"{op.get('op_id')}:{p.get('uuid')}"[:256]
        graph = {"pentest": str(op.get("name") or "")[:200], "pentest_id": str(op.get("op_id") or "")[:64],
                 "impact_type": str(p.get("impact_type") or "")[:64] or None, "impact": str(p.get("impact_title") or "")[:120] or None,
                 "severity": str(p.get("severity") or "")[:16] or None, "where": redact(p.get("affected_asset_text"), 300),
                 "minutes_to_find": round(p["time_to_finding_s"] / 60) if isinstance(p.get("time_to_finding_s"), (int, float)) else None,
                 "weaknesses": sorted({v for _, v in weak if v})[:20], "pairs": sorted([ip, v] for ip, v in weak if ip and v)[:40],
                 "completed_at": op.get("completed_at"), "steps": steps}
        for did in assets:
            row = (await db.execute(select(AttackPath).where(AttackPath.confirmed_by == SOURCE, AttackPath.external_id == ext,
                                                             AttackPath.target_device_id == did))).scalar_one_or_none()
            if row is None:
                row = AttackPath(confirmed_by=SOURCE, external_id=ext, target_device_id=did, path_score=0.0)
                db.add(row)
            row.path_description = str(p.get("attack_path_title") or "")[:2048] or None
            row.impact_description = redact(p.get("impact_description"), 1000)
            row.path_score = float(p["score"]) if isinstance(p.get("score"), (int, float)) else 0.0
            row.is_active, row.last_seen, row.graph = True, when, graph
            n += 1
    await db.commit()
    return n


async def prune(db, still_open: set | None, recent) -> dict:
    """Keep only what's real now: delete paths that aren't, then assets only NodeZero knew with nothing of its left."""
    from sqlalchemy import delete

    from api.models.device import Device
    from api.models.risk import AttackPath
    from api.models.vuln import Finding
    if still_open is None:   # no series from the API: nothing to judge by, so nothing is removed
        return {"paths": 0, "assets": 0}
    gone = [row.id for row in (await db.execute(select(AttackPath).where(AttackPath.confirmed_by == SOURCE))).scalars()
            if not is_active([tuple(x) for x in (row.graph or {}).get("pairs") or []], (row.graph or {}).get("completed_at")
                             or row.last_seen, still_open, recent)]
    for i in range(0, len(gone), 500):
        await db.execute(delete(AttackPath).where(AttackPath.id.in_(gone[i:i + 500])))
    has_finding = select(Finding.device_id).where(Finding.source == SOURCE)
    has_path = select(AttackPath.target_device_id).where(AttackPath.confirmed_by == SOURCE, AttackPath.target_device_id.is_not(None))
    # Only NodeZero ever knew it and nothing of NodeZero's is left: it isn't an asset any more
    stale = (await db.execute(select(Device.id).where(Device.sources == f",{SOURCE},", Device.id.not_in(has_finding),
                                                     Device.id.not_in(has_path)))).scalars().all()
    for i in range(0, len(stale), 500):
        await db.execute(delete(Device).where(Device.id.in_(stale[i:i + 500])))
    await db.commit()
    return {"paths": len(gone), "assets": len(stale)}


def _when(v):
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00")) if v else None
    except ValueError:
        t = None
    t = t or datetime.now(timezone.utc)
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)   # NodeZero's times are UTC
