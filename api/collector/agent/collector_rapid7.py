"""Rapid7 InsightVM Security Console module (v3 API): assets every run, vuln catalog once a day."""
import base64
import re
import time

import collector_common as cc

KIND = "rapid7_console"
LABEL = "Rapid7 InsightVM Security Console"
SECRETS = {"password": "Rapid7 console password"}  # nosec B105 - prompt label
PAGE = 500
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _auth(s, secret):
    raw = f"{s['username']}:{secret['password']}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


def _get(s, secret, path):
    return cc.pinned_json("GET", s["host"], s["port"], path, headers=_auth(s, secret),
                          pin=s.get("pin"), cafile=s.get("ca_file"), timeout=120)


def test(s, secret):
    _get(s, secret, "/api/3/assets?size=1&page=0")


def ask_settings():
    cc.say(f"\n== {LABEL} ==")
    host, port = cc.host_port(cc.ask("Console host (host or host:port)", validate=cc.check_host_port), 3780)
    return {"host": host, "port": port, "username": cc.ask("Console username"), "vuln_catalog_hours": 24}


def probe(settings):
    return {}, cc.tls_probe(settings["host"], settings["port"], "Rapid7 console")


def _pages(s, secret, path):
    page = 0
    while page < 5000:  # 2.5M rows; anything past that is a runaway loop
        data = _get(s, secret, f"{path}?size={PAGE}&page={page}") or {}
        yield data.get("resources") or []
        if page >= (data.get("page") or {}).get("totalPages", 1) - 1:
            return
        page += 1


def _asset(a):
    os_val = a.get("os")
    if isinstance(os_val, dict):
        os_val = os_val.get("name")
    out = {"hostName": (a.get("hostName") or "")[:253] or None, "ip": (a.get("ip") or "")[:45] or None,
           "os": str(os_val)[:256] if os_val else None}
    return out if out["hostName"] or out["ip"] else None


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
    for rows in _pages(s, secret, "/api/3/assets"):
        yield {"assets": [a for a in map(_asset, rows) if a]}
    # The vuln catalog is huge and barely changes; once a day is plenty
    key = f"rapid7_vulns_at:{s['host']}"
    if time.time() - float(state.get(key, 0)) < float(s.get("vuln_catalog_hours", 24)) * 3600:
        return
    for rows in _pages(s, secret, "/api/3/vulnerabilities"):
        yield {"vulnerabilities": [v for v in map(_vuln, rows) if v]}
    state[key] = time.time()
