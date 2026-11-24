"""An alert as an attack map: the host and user, the process chain that ran, and what the last process did (files,
connections, lookups) and what the EDR did about it. Columns run left to right in the order things happened; the
page (threat_graph.js) draws it and highlights the path to whatever is clicked. Built only from the stored, already
cleaned detail (api/core/cs_alert.py), so nothing here is fetched or trusted beyond that."""
from __future__ import annotations

import re

from api.core.attack_map import layout
from api.core.threat_timeline import _name, actions_text

MAX_PER_KIND = 6


_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def origin(detail: dict) -> dict:
    """Where a logon or identity alert came from and what it touched, from the fields Falcon gave it (context):
    {"ips", "hosts", "accounts", "targets"}, each a short list."""
    out: dict[str, list[str]] = {"ips": [], "hosts": [], "accounts": [], "targets": []}

    def add(kind, v):
        if v and v not in out[kind] and len(out[kind]) < 8:
            out[kind].append(v)
    for k, v in detail.get("context") or []:
        for part in (p.strip() for p in str(v).split(",")):
            if any(x in k for x in ("ip", "address", "addr")) and (_IPV4.match(part) or ":" in part and len(part) <= 45):
                add("ips", part)
            elif any(x in k for x in ("host", "workstation", "computer", "endpoint")) and "name" in k or k.endswith(("host", "hostname")):
                add("hosts", part)
            elif any(x in k for x in ("account", "user", "upn")):
                add("targets" if "target" in k or "dest" in k else "accounts", part)
    return out


def _facts(*pairs) -> list[list[str]]:
    return [[k, str(v)] for k, v in pairs if v not in (None, "", [], {})][:16]


def build(alert: dict, detail: dict) -> dict:
    nodes: list[dict] = []
    edges: list[dict] = []

    def node(nid, kind, label, col, sub=None, hit=False, facts=None):
        nodes.append({"id": nid, "kind": kind, "label": (label or kind)[:80], "sub": (sub or "")[:120] or None,
                      "col": col, "hit": hit, "facts": facts or []})
        return nid

    def edge(a, b, label, hot=False):
        edges.append({"from": a, "to": b, "label": label, "hot": hot})

    h, u = detail.get("host") or {}, detail.get("user") or {}
    host = node("host", "host", alert.get("hostname") or "Host", 0, " / ".join(x for x in (h.get("platform"), h.get("os_version")) if x),
                facts=_facts(("OS", h.get("os_version")), ("Internal IP", h.get("local_ip")), ("External IP", h.get("external_ip")),
                             ("Domain", h.get("domain")), ("Site", h.get("site")), ("Falcon containment", h.get("containment"))))
    src = origin(detail)
    for i, ip in enumerate(src["ips"][:4]):   # where the logon attempts or connections came from
        node(f"from{i}", "ip", ip, -1, "source address", facts=_facts(("Source address", ip), ("Accounts", ", ".join(src["accounts"])),
                                                                        ("Targeted", ", ".join(src["targets"]))))
        edge(f"from{i}", host, "from", hot=True)
    for i, h in enumerate([x for x in src["hosts"] if x.lower() != (alert.get("hostname") or "").lower()][:4]):
        node(f"fromh{i}", "host", h, -1, "source host", facts=_facts(("Source host", h)))
        edge(f"fromh{i}", host, "from", hot=True)
    for i, t in enumerate(src["targets"][:4]):
        node(f"tgt{i}", "user", t, 1, "account targeted", facts=_facts(("Account targeted", t)))
        edge(host, f"tgt{i}", "targeted", hot=True)
    at, col = host, 1 + bool(src["targets"])
    if u.get("name"):
        at = node("user", "user", f"{u['domain']}\\{u['name']}" if u.get("domain") else u["name"], 1, "signed-in user",
                  facts=_facts(("User", u.get("name")), ("Domain", u.get("domain")), ("Principal", u.get("principal")), ("SID", u.get("sid"))))
        edge(host, at, "Session")
        col = 2
    chain = [(k, detail.get(k)) for k in ("grandparent", "parent", "process") if detail.get(k)]
    mitre = " / ".join(x for x in (alert.get("tactic"), alert.get("technique")) if x)
    if not chain:   # only the summary reached CTEM: the detection is the one step
        hit = node("alert", "detection", alert.get("title") or "Alert", col, mitre, hit=True,
                   facts=_facts(("Description", alert.get("description")), ("MITRE", mitre), ("Technique", alert.get("technique_id")),
                                ("Severity", alert.get("severity")), ("Status", alert.get("status"))))
        edge(at, hit, "Detected", hot=True)
        return layout({"nodes": nodes, "edges": edges})
    for i, (k, p) in enumerate(chain):
        last = i == len(chain) - 1
        pid = node(k, "process", _name(p) or "process", col + i, f"PID {p['pid']}" if p.get("pid") is not None else None, hit=last,
                   facts=_facts(("Role", "Process that triggered the alert" if last else k.capitalize()), ("Path", p.get("filepath")),
                                ("Command line", p.get("cmdline")), ("User", p.get("user")), ("PID", p.get("pid")),
                                ("Started", p.get("start")), ("Ended", p.get("end")), ("SHA256", p.get("sha256")), ("SHA1", p.get("sha1")),
                                ("MD5", p.get("md5")),
                                *((("Detected", alert.get("title")), ("MITRE", mitre)) if last else ())))
        edge(at, pid, "Ran" if i == 0 else "Started", hot=last or i == len(chain) - 2)
        at = pid
    out = col + len(chain)
    acts = actions_text(detail)
    disp = detail.get("disposition") or {}
    if acts or disp.get("summary"):
        a = node("edr", "action", "Falcon: " + (", ".join(acts) if acts else "detected"), out, disp.get("summary"),
                 facts=_facts(("What Falcon did", ", ".join(acts)), ("Summary", disp.get("summary"))))
        edge(at, a, "Prevented" if acts else "Detected", hot=True)
    for i, f in enumerate((detail.get("quarantined") or [])[:MAX_PER_KIND]):
        node(f"q{i}", "quarantine", f.get("filename") or "file", out, f.get("state"), hit=True,
             facts=_facts(("File", f.get("filename")), ("SHA256", f.get("sha256")), ("State", f.get("state"))))
        edge(at, f"q{i}", "Quarantined", hot=True)
    if detail.get("ioc"):
        ioc = detail["ioc"]
        node("ioc", "indicator", ioc.get("value") or "indicator", out, ioc.get("type"), hit=True,
             facts=_facts(("Type", ioc.get("type")), ("Value", ioc.get("value")), ("From", ioc.get("source")), ("About", ioc.get("description"))))
        edge(at, "ioc", "Matched", hot=True)
    _group(node, edge, at, out, "w", "file", "Wrote", detail.get("files_written"), lambda f: f.get("filename") or f.get("filepath"),
           lambda f: _facts(("Path", f.get("filepath")), ("SHA256", f.get("sha256")), ("When", f.get("at"))), "files written")
    _group(node, edge, at, out, "d", "file", "Opened", detail.get("documents"), lambda f: f.get("filename") or f.get("filepath"),
           lambda f: _facts(("Path", f.get("filepath")), ("When", f.get("at"))), "documents opened")
    _group(node, edge, at, out, "t", "file", "Went after", detail.get("files_accessed"),
           lambda f: (f.get("filepath") or f.get("filename") or "").replace("\\", "/").rsplit("/", 1)[-1] or f.get("filepath"),
           lambda f: _facts(("Path", f.get("filepath")), ("When", f.get("at"))), "files accessed")
    conns: dict[str, list[dict]] = {}
    for n in detail.get("network") or []:
        conns.setdefault(f"{n.get('remote')}{':' + str(n['remote_port']) if n.get('remote_port') is not None else ''}", []).append(n)
    _group(node, edge, at, out, "n", "network", "Connected", list(conns.items()), lambda kv: kv[0],
           lambda kv: _facts(("Remote", kv[0]), ("Connections", len(kv[1])), ("Direction", kv[1][0].get("direction")),
                             ("Protocol", kv[1][0].get("protocol")), ("First", kv[1][0].get("at"))), "connections")
    _group(node, edge, at, out, "s", "dns", "Resolved", detail.get("dns"), lambda d: d.get("domain"),
           lambda d: _facts(("Domain", d.get("domain")), ("Type", d.get("type")), ("When", d.get("at"))), "DNS lookups")
    return layout({"nodes": nodes, "edges": edges})


def _group(node, edge, src, col, prefix, kind, verb, items, label, facts, plural) -> None:
    """Up to MAX_PER_KIND of one kind as their own boxes; the rest as one '+N more' box listing them."""
    items = list(items or [])
    for i, it in enumerate(items[:MAX_PER_KIND]):
        node(f"{prefix}{i}", kind, str(label(it) or kind), col, facts=facts(it))
        edge(src, f"{prefix}{i}", verb)
    rest = items[MAX_PER_KIND:]
    if rest:
        node(f"{prefix}more", kind, f"+{len(rest)} more {plural}", col,
             facts=[["Also", str(label(it))] for it in rest[:12]])
        edge(src, f"{prefix}more", verb)


def steps(alert: dict, related: list[dict], links: dict | None = None) -> list[dict]:
    """The story in order, one step per distinct detection: this alert and the ones tied to it (same host, same
    user, same process tree). The same detection on the same host again and again is one step with how many times and
    when it started and stopped, so the story reads instead of repeating one title."""
    keep = ("title", "severity", "tactic", "technique", "technique_id", "hostname", "source")
    groups: dict[tuple, dict] = {}
    for r in [{**alert, "why": "this alert"}, *related]:
        k = ((r.get("title") or "").lower(), r.get("severity"), (r.get("hostname") or "").lower())
        g = groups.get(k)
        if g is None:
            g = groups[k] = {**{f: r.get(f) for f in keep}, "id": r["id"], "count": 0, "first": r.get("detected_at"),
                             "last": r.get("detected_at"), "why": set(), "statuses": set(), "current": False}
        g["count"] += 1
        g["why"].add(r.get("why"))
        g["statuses"].add(r.get("status") or "new")
        if r["id"] == alert["id"]:
            g["current"], g["id"] = True, r["id"]   # clicking this step shows the alert being read
        t = r.get("detected_at")
        if t and (not g["first"] or t < g["first"]):
            g["first"] = t
            if not g["current"]:
                g["id"] = r["id"]
        if t and (not g["last"] or t > g["last"]):
            g["last"] = t
    out = []
    for g in groups.values():
        why = g.pop("why") - {None}
        g["why"] = "this alert" if g["current"] else ", ".join(sorted(why))
        g["status"] = "open" if g["statuses"] & {"new", "in_progress", "reopened"} else "closed"
        g["link"] = (links or {}).get(g["id"])
        g.pop("statuses")
        out.append(g)
    return sorted(out, key=lambda g: g.get("first") or "")[:60]
