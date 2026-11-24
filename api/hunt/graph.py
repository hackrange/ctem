"""A Threat Hunt finding as an attack map (api/core/attack_map.py): the people and addresses on the left, the computers
next, then each step of how it unfolded in order, four to a column. Each step is tied to the computers, accounts and
addresses its own words name, so clicking a step or a box shows its path."""
from __future__ import annotations

from api.core.attack_map import layout

PER_COL = 4
MAX_STEPS = 24
MAX_EACH = 6
_KIND = {"crowdstrike": "alert", "sentinelone": "alert", "msdefender": "alert", "cortex_xdr": "alert", "splunk": "log",
         "open-ctem": "event", "ctem": "event"}


def _short(s: str, n: int) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 3].rsplit(" ", 1)[0] + "..."


def build(issue: dict) -> dict:
    who = issue.get("involved") or {}
    hosts = [str(h) for h in (who.get("hosts") or [])][:MAX_EACH]
    users = [str(u) for u in (who.get("users") or [])][:MAX_EACH]
    ips = [str(i) for i in (who.get("ips") or [])][:MAX_EACH]
    timeline = [t for t in (issue.get("timeline") or []) if isinstance(t, dict)][:MAX_STEPS]
    nodes, edges, steps = [], [], []
    for i, u in enumerate(users):
        nodes.append({"id": f"u{i}", "kind": "user", "label": u, "col": 0, "hit": False, "facts": [["Account", u]]})
    for i, ip in enumerate(ips):
        nodes.append({"id": f"a{i}", "kind": "ip", "label": ip, "col": 0, "hit": False, "facts": [["Address", ip]]})
    hcol = 1 if users or ips else 0
    for i, h in enumerate(hosts):
        nodes.append({"id": f"h{i}", "kind": "host", "label": h, "col": hcol, "hit": False, "facts": [["Computer", h]]})
    first = hcol + (1 if hosts else 0)
    sev = (issue.get("severity") or "").lower()
    for n, t in enumerate(timeline):
        sid = f"s{n}"
        what = str(t.get("what") or "")
        src = str(t.get("source") or "")
        facts = [["When", str(t.get("time") or "unknown")], ["Source", src], ["What happened", what]]
        if t.get("lookup"):
            facts.append(["Evidence", f"#{t['lookup']}"])
        nodes.append({"id": sid, "kind": _KIND.get(src.lower(), "event"), "label": _short(what, 60) or f"Step {n + 1}",
                      "sub": " · ".join(x for x in (str(t.get("time") or ""), src) if x)[:60], "col": first + n // PER_COL,
                      "row": n % PER_COL, "hit": n == len(timeline) - 1 and sev in ("critical", "high"), "facts": facts})
        steps.append({"id": sid, "n": n + 1, "time": t.get("time"), "source": src, "what": what, "lookup": t.get("lookup")})
        low = what.lower()
        named = [f"h{i}" for i, h in enumerate(hosts) if h.lower() in low]
        for i, u in enumerate(users):
            if u.lower() in low:
                edges.append({"from": f"u{i}", "to": sid, "label": "by", "hot": False})
        for i, ip in enumerate(ips):
            if ip.lower() in low:
                edges.append({"from": f"a{i}", "to": sid, "label": "involved", "hot": False})
        if n == 0 and not named and hosts:
            named = ["h0"]
        for h in named:
            edges.append({"from": h, "to": sid, "label": "on", "hot": n == 0})
        if n:
            edges.append({"from": f"s{n - 1}", "to": sid, "label": "then", "hot": True})
    # People and addresses no step names still belong to the story: tie them to the first computer
    tied = {e["from"] for e in edges}
    for nd in nodes:
        if nd["kind"] in ("user", "ip") and nd["id"] not in tied and hosts:
            edges.append({"from": nd["id"], "to": "h0", "label": "signed in" if nd["kind"] == "user" else "seen with", "hot": False})
    return {**layout({"nodes": nodes, "edges": edges, "rowh": 124}), "steps": steps}
