"""NodeZero attack paths through an asset as attack maps (api/core/attack_map.py, drawn by attack_map.js on the Pentest
tab): every path merged into one map (a host or weakness several paths share appears once), and each path alone.
Steps run left to right in the order NodeZero took them, ending at the impact."""
from __future__ import annotations

import hashlib
import re

from api.core.attack_map import layout

KIND = {"NodeZero": "launch", "Address": "host", "Service": "service", "Application": "service", "Weakness": "weakness",
        "Credential": "credential", "Impact": "impact"}
_SHORT = [
    (re.compile(r"launched from host (\S+)"), r"Launched from \1"),
    (re.compile(r"discovered weakness (CVE-\d{4}-\d+|[^:]+):"), r"\1"),
    (re.compile(r"discovered host (\S+)"), r"\1"),
    (re.compile(r"discovered the (.+?) service at (\S+)"), r"\1 at \2"),
    (re.compile(r"discovered (.+?) application at (\S+)"), r"\1 at \2"),
    (re.compile(r"discovered credential (?:for )?(\S+)"), r"Credential \1"),
    (re.compile(r"^.*\((CVE-\d{4}-\d+)\) affecting (.+)$"), r"\1 on \2"),
]


def short(text: str) -> str:
    """A box label from NodeZero's sentence: the host, the service, the CVE; the whole sentence stays in the details."""
    for rx, rep in _SHORT:
        m = rx.search(text)
        if m:
            return m.expand(rep)[:80]
    return re.sub(r"^NodeZero (module \S+ )?", "", text)[:80]


VERB = {"host": "reached", "service": "found", "weakness": "exploited", "credential": "obtained", "impact": "led to"}


def _graph(chains: list[dict]) -> dict:
    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}
    for c in chains:
        prev = None
        for i, s in enumerate((c.get("steps") or [])[:30]):
            if not isinstance(s, dict):
                continue
            kind = KIND.get(s.get("kind"), "event")
            text = " ".join(str(s.get("text") or s.get("kind") or "Step").split())
            nid = hashlib.sha256(f"{kind}|{text}".encode()).hexdigest()[:12]
            n = nodes.get(nid)
            if n is None:
                facts = [["Step", str(s.get("kind") or kind)], ["What", text]]
                if s.get("at"):
                    facts.append(["When", str(s["at"])])
                facts += [["Asset", f"{ip} (its asset page is linked in the paths list)"] for ip in (s.get("assets") or {})][:3]
                n = nodes[nid] = {"id": nid, "kind": kind, "label": short(text), "col": i, "hit": kind == "impact", "facts": facts,
                                  "sub": str(c.get("impact") or "")[:60] if kind == "impact" else None}
            n["col"] = max(n["col"], i)
            if prev and prev != nid:
                edges[(prev, nid)] = {"from": prev, "to": nid, "label": VERB.get(kind, "then"),
                                      "hot": kind in ("weakness", "credential", "impact")}
            prev = nid
    for _ in range(len(nodes)):   # merged paths can disagree on order: push each box right of whatever leads to it
        moved = False
        for e in edges.values():
            if nodes[e["to"]]["col"] <= nodes[e["from"]]["col"]:
                nodes[e["to"]]["col"] = nodes[e["from"]]["col"] + 1
                moved = True
        if not moved:
            break
    return layout({"nodes": list(nodes.values()), "edges": list(edges.values())})


def graphs(chains: list[dict]) -> dict | None:
    """{"all": every path in one map, "each": one map per path}, or None when no path has steps."""
    with_steps = [c for c in chains if c.get("steps")]
    if not with_steps:
        return None
    return {"all": _graph(with_steps), "each": [_graph([c]) if c.get("steps") else None for c in chains]}
