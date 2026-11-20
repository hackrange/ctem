"""An alert's story from its stored detail: a plain-English summary and a timeline of what took place."""
from __future__ import annotations

from api.core.cs_alert import csa

MAX_EVENTS = 200


def _name(p: dict | None) -> str | None:
    return (p or {}).get("filename") or ((p or {}).get("filepath") or "").replace("\\", "/").rsplit("/", 1)[-1] or None


def actions_text(detail: dict) -> list[str]:
    disp = detail.get("disposition") or {}
    # "detected it" / "matched an indicator" add nothing next to the real actions
    real = [a for a in disp.get("actions", []) if a not in ("detect", "indicator")]
    return [csa.ACTIONS[a] for a in real if a in csa.ACTIONS]


def story(alert: dict, detail: dict) -> str | None:
    """One or two sentences a person can read without opening Falcon."""
    proc, parent, grand = detail.get("process"), detail.get("parent"), detail.get("grandparent")
    user = (detail.get("user") or {}).get("name") or (proc or {}).get("user")
    host = alert.get("hostname") or "the host"
    parts = []
    if _name(proc):
        s = f"{_name(proc)} ran on {host}"
        if user:
            s += f" as {user}"
        if _name(parent):
            s += f", started by {_name(parent)}"
            if _name(grand):
                s += f" (itself started by {_name(grand)})"
        parts.append(s + ".")
    what = alert.get("title") or "suspicious activity"
    mitre = " / ".join(x for x in (alert.get("tactic"), alert.get("technique")) if x)
    s = f"Falcon flagged it as {what}" + (f" ({mitre})" if mitre else "")
    acts = actions_text(detail)
    if acts:
        s += " and " + ", ".join(acts[:-1]) + (" and " if len(acts) > 1 else "") + acts[-1]
    elif (detail.get("disposition") or {}).get("summary"):
        s += f". {detail['disposition']['summary'].rstrip('.')}"
    parts.append(s + ".")
    return " ".join(parts) if parts else None


def timeline(alert: dict, detail: dict, related: list[dict]) -> list[dict]:
    """Every timestamped step, oldest first: process starts, file / network / DNS activity, detection,
    what Falcon did, other alerts on the host, and the latest status change."""
    ev: list[dict] = []

    def add(at, kind, title, text=None, ref=None):
        if at:
            ev.append({k: v for k, v in {"at": at, "kind": kind, "title": title, "text": text, "ref": ref}.items()
                       if v is not None})

    for label, p in (("Grandparent process", detail.get("grandparent")), ("Parent process", detail.get("parent")),
                     ("Process", detail.get("process"))):
        if p:
            add(p.get("start"), "process", f"{label} started: {_name(p) or 'unknown'}", p.get("cmdline"))
    for f in detail.get("files_written", []):
        add(f.get("at"), "file", f"Wrote {f.get('filename') or f.get('filepath')}", f.get("filepath"))
    for f in detail.get("documents", []):
        add(f.get("at"), "file", f"Opened {f.get('filename') or f.get('filepath')}", f.get("filepath"))
    for n in detail.get("network", []):
        port = f":{n['remote_port']}" if n.get("remote_port") is not None else ""
        add(n.get("at"), "network", f"{(n.get('direction') or 'network').capitalize()} connection to {n['remote']}{port}",
            n.get("protocol"))
    for d in detail.get("dns", []):
        add(d.get("at"), "dns", f"DNS lookup: {d['domain']}", d.get("type"))
    detected = detail.get("event_time") or alert.get("detected_at")
    mitre = " / ".join(x for x in (alert.get("technique_id"), alert.get("technique")) if x)
    add(detected, "detection", f"Falcon detected: {alert.get('title') or 'alert'}",
        " · ".join(x for x in (mitre, alert.get("description")) if x) or None)
    acts = actions_text(detail)
    q = [x.get("filename") or x.get("sha256") for x in detail.get("quarantined", [])]
    if acts or q:
        add(detected, "action", "Falcon " + ", ".join(acts or ["quarantined files"]),
            ("Quarantined: " + ", ".join(q)) if q else None)
    if detail.get("created") and detail.get("created") != detected:
        add(detail["created"], "alert", "Alert raised in Falcon")
    if (detail.get("process") or {}).get("end"):
        add(detail["process"]["end"], "process", f"Process ended: {_name(detail['process']) or 'unknown'}")
    for r in related:
        add(r.get("detected_at"), "related", f"Other alert on this host: {r.get('title') or 'alert'}",
            r.get("severity"), r.get("id"))
    if detail.get("updated"):
        bits = [f"status {alert.get('status').replace('_', ' ')}" if alert.get("status") else None,
                f"assigned to {detail['assigned_to']}" if detail.get("assigned_to") else None,
                f"resolution {detail['resolution']}" if detail.get("resolution") else None]
        add(detail["updated"], "status", "Last update in Falcon", ", ".join(b for b in bits if b) or None)
    ev.sort(key=lambda e: e["at"])
    return ev[:MAX_EVENTS]
