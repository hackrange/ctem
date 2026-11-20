"""Local Splunk module: notable events on a rolling window, plus the index list for the SPL catalog."""
import base64
import re

import collector_common as cc

KIND = "splunk"
LABEL = "Splunk (local search head)"
SECRETS = {"password": "Splunk password"}  # nosec B105 - prompt label
DEFAULT_SPL = "search index=wineventlog OR index=crowdstrike OR index=guardicore | table _time, host, source, _raw"
_KEY = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_INDEX = re.compile(r"^[A-Za-z0-9_-]{1,80}$")


def _req(s, secret, method, path, form=None):
    raw = f"{s['username']}:{secret['password']}".encode()
    headers = {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    return cc.pinned_json(method, s["host"], s["port"], path, headers=headers, form=form,
                          pin=s.get("pin"), cafile=s.get("ca_file"), timeout=300) or {}


def test(s, secret):
    _req(s, secret, "GET", "/services/server/info?output_mode=json")


def ask_settings():
    cc.say(f"\n== {LABEL} ==")
    host, port = cc.host_port(cc.ask("Splunk management host (host or host:port)", validate=cc.check_host_port), 8089)
    s = {"host": host, "port": port, "username": cc.ask("Splunk username"), "max_events": 5000}
    s["query"] = cc.ask("SPL for notable events", default=DEFAULT_SPL)
    return s


def probe(settings):
    return {}, cc.tls_probe(settings["host"], settings["port"], "Splunk")


def _event(row):
    out = {}
    for k, v in row.items():
        if not isinstance(k, str) or not _KEY.match(k) or len(out) >= 100:
            continue
        if isinstance(v, list):
            v = " ".join(str(x) for x in v)
        out[k] = str(v)[:8192]
    return out


def _indexes(s, secret):
    data = _req(s, secret, "GET", "/services/data/indexes?output_mode=json&count=1000")
    out = []
    for e in data.get("entry") or []:
        name, c = e.get("name") or "", e.get("content") or {}
        if not _INDEX.match(name):
            continue
        out.append({"name": name, "totalEventCount": max(int(c.get("totalEventCount") or 0), 0),
                    "currentDBSizeMB": max(float(c.get("currentDBSizeMB") or 0), 0.0),
                    "minTime": str(c.get("minTime") or "")[:40] or None, "maxTime": str(c.get("maxTime") or "")[:40] or None})
    return out


def collect(s, secret, state):
    # Window covers the gap since the last run plus five minutes of overlap; CTEM dedupes by event hash
    lookback = int(s.get("lookback_minutes") or 65)
    query = s["query"] if s["query"].lstrip().lower().startswith(("search", "|")) else f"search {s['query']}"
    form = {"search": query, "output_mode": "json", "exec_mode": "oneshot",
            "count": int(s.get("max_events", 5000))}
    if "earliest=" not in query:
        form.update({"earliest_time": f"-{lookback}m@m", "latest_time": "now"})
    rows = _req(s, secret, "POST", "/services/search/jobs", form=form).get("results") or []
    events = [e for e in map(_event, rows) if e]
    for i in range(0, len(events), 1000):
        yield {"events": events[i:i + 1000]}
    yield {"indexes": _indexes(s, secret)}
