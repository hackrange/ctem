"""What an analyst needs from an EDR alert in a hunt's evidence: the process, its command line and parent, the file it
went after (a DLL it loaded, a file it wrote or opened, the indicator it matched), the hash and the user. Opened from
the alert's encrypted detail for the evidence people read in CTEM and the report; never put in an AI prompt (the AI's
write-up is done before this runs, and curated rules don't use the AI)."""
from __future__ import annotations

MAX_ROWS = 50
COLUMNS = ("process", "command_line", "parent", "file", "sha256", "user", "crowdstrike")


def _name(p: dict | None) -> str | None:
    p = p or {}
    return p.get("filename") or (p.get("filepath") or "").replace("\\", "/").rsplit("/", 1)[-1] or None


def summarize(detail: dict) -> dict:
    """{process, command_line, parent, file, sha256, user} from an alert's detail; only what it has."""
    proc, ioc = detail.get("process") or {}, detail.get("ioc") or {}
    file = None
    if ioc.get("value") and str(ioc.get("type") or "").lower() in ("filename", "file", "filepath", "file_path", "module", "dll"):
        file = ioc["value"]
    for key in ("files_accessed", "files_written", "documents"):
        if not file and detail.get(key):
            file = detail[key][0].get("filepath") or detail[key][0].get("filename")
    if not file and detail.get("quarantined"):
        file = detail["quarantined"][0].get("filename")
    if not file and ioc.get("value"):
        file = f"{ioc.get('type') or 'indicator'}: {ioc['value']}"
    u = detail.get("user") or {}
    out = {"process": proc.get("filepath") or _name(proc), "command_line": (proc.get("cmdline") or "")[:400] or None,
           "parent": _name(detail.get("parent")), "file": (str(file)[:400] if file else None), "sha256": proc.get("sha256"),
           "user": f"{u['domain']}\\{u['name']}" if u.get("domain") and u.get("name") else u.get("name") or proc.get("user")}
    return {k: v for k, v in out.items() if v}


async def console_links(db, alerts: list[dict], known: list[str] | None = None) -> dict:
    """{alert id: its CrowdStrike console link} for CrowdStrike alerts, made like the others' when one was saved without
    (`known`: links to copy the form of; looked up once when not given)."""
    from api.core.cs_alert_actions import composite_id, console_link
    from api.routes.threat import _alerts
    cs = [a for a in alerts if a.get("source") == "crowdstrike"]
    if not cs:
        return {}
    known = known or [a["link"] for a in cs if a.get("link")][:3]
    if not known and any(not a.get("link") for a in cs):
        known = [a["link"] for a in await _alerts(db) if a.get("link") and a.get("source") == "crowdstrike"][:3]
    out = {}
    for a in cs:
        cid = composite_id(a["id"].partition("#")[0])
        link = a.get("link") or (console_link(cid, known) if cid else None)
        if link:
            out[a["id"]] = link
    return out


async def enrich(db, lookups: list[dict]) -> None:
    """Add those columns to every evidence table of alerts (rows with an alert_key), the first MAX_ROWS rows each."""
    from api.routes.threat import _alerts, _detail
    cache: dict[str, dict] = {}
    known: list[str] | None = None
    for lk in lookups:
        cols = list(lk.get("columns") or [])
        if "alert_key" not in cols or not lk.get("rows"):
            continue
        added = set()
        for row in lk["rows"][:MAX_ROWS]:
            key = str(row.get("alert_key") or "").partition("#")[0]
            if not key.startswith("threat_alert_"):
                continue
            if key not in cache:
                alert = next(iter(await _alerts(db, key)), None)
                cache[key] = summarize(await _detail(db, key)) if alert and alert.get("has_detail") else {}
                if alert and alert.get("source") == "crowdstrike":
                    if known is None and not alert.get("link"):   # one look for a link to copy the form of, per hunt
                        known = [a["link"] for a in await _alerts(db) if a.get("link") and a.get("source") == "crowdstrike"][:3]
                    link = (await console_links(db, [alert], known)).get(alert["id"])
                    if link:
                        cache[key]["crowdstrike"] = link
            for k, v in cache[key].items():
                if not row.get(k):
                    row[k] = v
                    added.add(k)
        if added:   # after the alert's own columns, before its key
            keep = [c for c in cols if c != "alert_key"]
            lk["columns"] = keep + [c for c in COLUMNS if c in added and c not in keep] + ["alert_key"]


def _words(s) -> set[str]:
    return {w for w in "".join(c.lower() if c.isalnum() else " " for c in str(s or "")).split() if len(w) > 3}


def annotate(issues: list[dict], lookups: list[dict]) -> None:
    """Put the results into the story: each step that points at alert evidence names the process and the file of the
    alert it describes (the row on the same host whose words best match the step)."""
    for issue in issues:
        hosts = {h.lower() for h in (issue.get("involved") or {}).get("hosts") or []}
        for step in issue.get("timeline") or []:
            n, what = step.get("lookup"), str(step.get("what") or "")
            if not isinstance(n, int) or not 0 < n <= len(lookups) or "Process: " in what:
                continue
            want = _words(what)
            best, score = None, 0
            for row in lookups[n - 1].get("rows") or []:
                if not (row.get("process") or row.get("file")):
                    continue
                host = str(row.get("hostname") or row.get("host") or "").lower()
                same = len(want & _words(f"{row.get('description') or ''} {row.get('alert') or ''} {row.get('title') or ''}"))
                if same < 2:   # the step must describe this alert, not only share its host
                    continue
                s = same + (3 if host and (host in what.lower() or host in hosts) else 0)
                if s > score:
                    best, score = row, s
            if best:
                proc = str(best.get("process") or "").replace("\\", "/").rsplit("/", 1)[-1]
                bits = [f"Process: {proc}" + (f" (started by {best['parent']})" if best.get("parent") else "") if proc else "",
                        f"File: {best['file']}" if best.get("file") else ""]
                step["what"] = (what.rstrip(". ") + ". " + "; ".join(b for b in bits if b) + ".")[:600]
