"""Falcon Spotlight vulnerabilities and Discover applications for the CrowdStrike source.

Both are optional ("off" in the source's settings skips them). A tenant without the module, or an API client
without the scope, gets a note for CTEM's integration card and that part is skipped; the run carries on.
Formats follow CrowdStrike's gofalcon models (domain.BaseAPIVulnerabilityV2, domain.DiscoverAPIApplication)."""
import re
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

import collector_common as cc

_ID = re.compile(r"^[0-9a-fA-F]{32}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_HASH = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{64}$")
SPOTLIGHT_FULL_DAYS = 7      # a full pass (open findings only) this often; incremental (anything updated) in between
DISCOVER_HOURS = 24
PAGE = 1000                  # one upload: CTEM takes up to 1000 per batch (Spotlight allows 5000)
SCOPE = {"spotlight": "Vulnerabilities: Read", "discover": "Assets: Read"}


def _txt(v, cap):
    v = v.strip() if isinstance(v, str) else ""
    return v[:cap] if v and not any(ord(ch) < 32 and ch not in "\n\t" for ch in v) else None


def _num(v, lo, hi):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) and lo <= v <= hi else None


def on(s, key):
    return str(s.get(key, "on")).lower() != "off"


def refused(kind, e, notes):
    cc.say(f"  CrowdStrike: {kind} refused (HTTP {e.status}); skipped")
    notes.append(f"Falcon refused {kind} (HTTP {e.status}), so it was skipped; if it's licensed, give the API client "
                 f"the {SCOPE[kind]} scope")


def _iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def spotlight(api, s, state, notes):
    """Yields batches: {"spotlight_cves": [...], "spotlight": [...], "spotlight_mode": "full"|"incremental"}."""
    if not on(s, "spotlight"):
        return
    key, now = f"cs_spotlight:{s.get('client_id', '')[:8]}", datetime.now(timezone.utc)
    last = state.get(key) or {}
    full = not last.get("full_at") or time.time() - last["full_at"] >= SPOTLIGHT_FULL_DAYS * 86400
    if full:
        flt = "status:['open','reopen']"
    else:
        since = datetime.fromtimestamp(last.get("at", 0), timezone.utc) - timedelta(hours=1)
        flt = f"updated_timestamp:>'{_iso(since)}'"
    after, sent_cves, seen = None, set(), 0
    for _ in range(100_000):  # runaway guard
        q = {"filter": flt, "limit": PAGE, "facet": ["cve", "host_info", "remediation"]}
        if after:
            q["after"] = after
        try:
            data = api.call("GET", "/spotlight/combined/vulnerabilities/v1?" + urllib.parse.urlencode(q, doseq=True))
        except cc.HttpError as e:
            if 400 <= e.status < 500 and e.status != 429:
                refused("spotlight", e, notes)
                return
            raise
        rows = data.get("resources") or []
        cves, vulns = [], []
        for r in rows:
            v = _vuln(r)
            if v is None:
                continue
            vulns.append(v)
            c = (r.get("cve") or {})
            if v["cve_id"] not in sent_cves:
                sent_cves.add(v["cve_id"])
                cves.append(_cve(c))
        seen += len(vulns)
        if vulns:
            yield {"spotlight_cves": cves, "spotlight": vulns, "spotlight_mode": "full" if full else "incremental"}
        after = ((data.get("meta") or {}).get("pagination") or {}).get("after")
        if not rows or not after:
            break
    cc.say(f"  CrowdStrike: Spotlight {'full' if full else 'incremental'} pass, {seen} findings")
    state[key] = {"at": now.timestamp(), "full_at": now.timestamp() if full else last.get("full_at")}


def _vuln(r):
    aid, cve = r.get("aid"), (r.get("cve") or {}).get("id")
    if not (isinstance(aid, str) and _ID.match(aid) and isinstance(cve, str) and _CVE.match(cve)):
        return None
    host = r.get("host_info") or {}
    rem = [{"title": _txt(x.get("title"), 256), "action": _txt(x.get("action"), 1000), "link": _txt(x.get("link"), 500)}
           for x in ((r.get("remediation") or {}).get("entities") or [])[:3] if isinstance(x, dict)]
    apps = [_txt(a.get("product_name_version"), 200) for a in (r.get("apps") or [])[:5] if isinstance(a, dict)]
    return {"id": _txt(r.get("id"), 128), "aid": aid, "hostname": _txt(host.get("hostname"), 253),
            "status": _txt(r.get("status"), 16), "cve_id": cve, "created": _txt(r.get("created_timestamp"), 40),
            "updated": _txt(r.get("updated_timestamp"), 40), "closed": _txt(r.get("closed_timestamp"), 40),
            "apps": [a for a in apps if a], "remediation": [x for x in rem if x["title"] or x["action"]]}


def _cve(c):
    cisa = c.get("cisa_info") or {}
    return {"id": c.get("id"), "name": _txt(c.get("name"), 512), "description": _txt(c.get("description"), 4000),
            "base_score": _num(c.get("base_score"), 0, 10), "severity": _txt(c.get("severity"), 16),
            "vector": _txt(c.get("vector"), 256), "exprt_rating": _txt(c.get("exprt_rating"), 16),
            "exploit_status": _num(c.get("exploit_status"), 0, 1000), "is_kev": cisa.get("is_cisa_kev") is True,
            "published": _txt(c.get("published_date"), 40),
            "actors": [a for a in (_txt(x, 128) for x in (c.get("actors") or [])[:20]) if a],
            "cwes": [a for a in (_txt(x, 32) for x in (c.get("cwes") or [])[:10]) if a]}


def discover(api, s, state, notes):
    """Installed applications once a day: {"software": [...]} in the shape CTEM's software inventory takes."""
    if not on(s, "discover"):
        return
    key = f"cs_discover_at:{s.get('client_id', '')[:8]}"
    if time.time() - float(state.get(key, 0)) < DISCOVER_HOURS * 3600:
        return
    after, n = None, 0
    for _ in range(100_000):
        q = {"limit": 1000, "facet": ["host_info"]}
        if after:
            q["after"] = after
        try:
            data = api.call("GET", "/discover/combined/applications/v1?" + urllib.parse.urlencode(q, doseq=True))
        except cc.HttpError as e:
            if 400 <= e.status < 500 and e.status != 429:
                refused("discover", e, notes)
                return
            raise
        rows = data.get("resources") or []
        items = [x for x in map(_app, rows) if x]
        n += len(items)
        if items:
            yield {"software": items}
        after = ((data.get("meta") or {}).get("pagination") or {}).get("after")
        if not rows or not after:
            break
    cc.say(f"  CrowdStrike: Discover, {n} installed applications")
    state[key] = time.time()


def _app(a):
    host = a.get("host") or {}
    name, hn = _txt(a.get("name"), 256), _txt(host.get("hostname"), 253)
    if not name or not hn:
        return None
    h = str(a.get("last_used_file_hash") or "").strip().lower()
    paths = [p for p in (_txt(x, 512) for x in (a.get("installation_paths") or [])[:1]) if p]
    out = {"vendor": _txt(a.get("vendor"), 256), "product": name, "version": _txt(a.get("version"), 128) or "",
           "type": _txt(a.get("software_type"), 64), "hosts": [hn]}
    if paths:
        out["install_path"] = paths[0]
    if _HASH.match(h):
        out["sha256" if len(h) == 64 else "md5"] = h
    return out
