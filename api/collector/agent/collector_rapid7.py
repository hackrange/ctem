"""Rapid7 InsightVM Security Console module (v3 API): assets every run, vuln catalog once a day."""
import base64
import re
import socket
import time

import collector_common as cc

KIND = "rapid7_console"
LABEL = "Rapid7 InsightVM Security Console"
SECRETS = {"password": "Rapid7 console password"}  # nosec B105 - prompt label
# Each size divides the one before, so shrinking mid-list keeps the row position exact
SIZES = (200, 100, 50, 25)
TIMEOUT = 300
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_TAG_TYPES = {"custom", "location", "owner", "criticality"}


def _auth(s, secret):
    raw = f"{s['username']}:{secret['password']}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


def _get(s, secret, path):
    return cc.pinned_json("GET", s["host"], s["port"], path, headers=_auth(s, secret),
                          pin=s.get("pin"), cafile=s.get("ca_file"), timeout=TIMEOUT)


def test(s, secret):
    _get(s, secret, "/api/3/assets?size=1&page=0")


def ask_settings():
    cc.say(f"\n== {LABEL} ==")
    host, port = cc.host_port(cc.ask("Console host (host or host:port)", validate=cc.check_host_port), 3780)
    return {"host": host, "port": port, "username": cc.ask("Console username"), "vuln_catalog_hours": 24}


def probe(settings):
    return {}, cc.tls_probe(settings["host"], settings["port"], "Rapid7 console")


def _pages(s, secret, path):
    """Page through a v3 list; a slow console gets smaller pages instead of a failed run."""
    offset, i = 0, 0
    for _ in range(200_000):  # runaway guard
        size = SIZES[i]
        try:
            data = _get(s, secret, f"{path}?size={size}&page={offset // size}") or {}
        except (TimeoutError, socket.timeout) as e:
            if i + 1 < len(SIZES):
                i += 1
                cc.say(f"  Rapid7 console slow on {path}; retrying with {SIZES[i]} per page")
                continue
            raise RuntimeError(f"Rapid7 console took over {TIMEOUT}s for {size} rows of {path}; "
                               "check console load or any proxy in front of it") from e
        rows = data.get("resources") or []
        yield rows
        offset += size
        info = data.get("page") or {}
        total = info.get("totalResources")
        if not rows or (total is not None and offset >= total) or \
                (total is None and offset // size >= info.get("totalPages", 1)):
            return


def _asset(a, tags=None):
    os_val = a.get("os")
    if isinstance(os_val, dict):
        os_val = os_val.get("name")
    out = {"hostName": (a.get("hostName") or "")[:253] or None, "ip": (a.get("ip") or "")[:45] or None,
           "os": str(os_val)[:256] if os_val else None}
    if tags is not None:  # None = couldn't read tags, so CTEM keeps what it has
        out["tags"] = tags.get(a.get("id"), [])[:100]
    return out if out["hostName"] or out["ip"] else None


def _tag_map(s, secret):
    """asset id -> [{type, name}] for every console tag (custom, location, owner, criticality)."""
    out = {}
    try:
        for rows in _pages(s, secret, "/api/3/tags"):
            for t in rows:
                tid, name, kind = t.get("id"), t.get("name"), str(t.get("type") or "custom").lower()
                if not isinstance(tid, int) or not isinstance(name, str) or kind not in _TAG_TYPES:
                    continue
                for aid in (_get(s, secret, f"/api/3/tags/{tid}/assets") or {}).get("resources") or []:
                    if isinstance(aid, int):
                        out.setdefault(aid, []).append({"type": kind, "name": name[:256]})
    except cc.HttpError as e:
        if e.status in (401, 403):
            cc.say("  Rapid7: this account can't read tags; asset tags are skipped")
            return None
        raise
    return out


def _score(block):
    try:
        val = float((block or {}).get("score"))
        return {"score": val} if 0 <= val <= 10 else None
    except (TypeError, ValueError):
        return None


def _vuln(v):
    cves = [c for c in (v.get("cves") or []) if isinstance(c, str) and _CVE.match(c)][:200]
    if not cves:
        return None
    cvss = v.get("cvss") or {}
    desc = v.get("description")
    text = desc.get("text") if isinstance(desc, dict) else desc
    return {"id": str(v.get("id") or "")[:256] or None, "title": (v.get("title") or "")[:512] or None, "cves": cves,
            "cvss": {"v2": _score(cvss.get("v2")), "v3": _score(cvss.get("v3"))},
            "description": {"text": str(text)[:20000]} if text else None}


def collect(s, secret, state):
    tags = _tag_map(s, secret)
    for rows in _pages(s, secret, "/api/3/assets"):
        yield {"assets": [a for a in (_asset(r, tags) for r in rows) if a]}
    # The vuln catalog is huge and barely changes; once a day is plenty
    key = f"rapid7_vulns_at:{s['host']}"
    if time.time() - float(state.get(key, 0)) < float(s.get("vuln_catalog_hours", 24)) * 3600:
        return
    for rows in _pages(s, secret, "/api/3/vulnerabilities"):
        yield {"vulnerabilities": [v for v in map(_vuln, rows) if v]}
    state[key] = time.time()
