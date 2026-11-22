"""Local Splunk module: notable events on a rolling window, plus the index list for the SPL catalog."""
import base64
import json
import os
import re
import time

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


FILE_MAX = 50 * 1024 * 1024   # the forwarder file rolls over at this size (one previous file kept)


def deliver(api, m, s, secret, state, alerts_dir):
    """CTEM's alert feed, on the box: to the local HEC, to a file a Universal Forwarder monitors, or both."""
    mode = s.get("forward_alerts", "off")
    if mode == "off":
        return 0
    if mode in ("hec", "both") and not secret.get("hec_token"):
        cc.say("  Splunk: no HEC token set in CTEM yet; alerts go to the file only" if mode == "both" else
               "  Splunk: no HEC token set in CTEM yet; alerts are not sent")
        mode = "file" if mode == "both" else "off"
        if mode == "off":
            return 0
    key = f"ctem_alert_seq:{m['integration_id']}"
    seq, sent = state.get(key, -1), 0   # -1: start from now, don't replay history
    for _ in range(200):
        page = api.call("GET", f"/api/v1/collector/alerts/{m['integration_id']}?after={int(seq)}", retries=2) or {}
        events = page.get("alerts") or []
        if events and mode in ("hec", "both"):
            for e in events:
                body = {"time": time.time(), "source": "open-ctem", "sourcetype": "ctem:alert", "event": e}
                if s.get("hec_index"):
                    body["index"] = s["hec_index"]
                cc.pinned_json("POST", s.get("hec_host") or s["host"], int(s.get("hec_port") or 8088), "/services/collector/event",
                               headers={"Authorization": f"Splunk {secret['hec_token']}"}, body=body,
                               pin=s.get("hec_pin"), cafile=s.get("ca_file"), timeout=60)
        if events and mode in ("file", "both"):
            _append(alerts_dir, events)
        sent += len(events)
        seq = page.get("next", seq)
        state[key] = seq   # what's delivered stays delivered, even if a later page fails
        if not page.get("more"):
            break
    if sent:
        cc.say(f"  Splunk: delivered {sent} CTEM alerts ({mode})")
    return sent


def _append(alerts_dir, events):
    os.makedirs(alerts_dir, mode=0o750, exist_ok=True)
    path = os.path.join(alerts_dir, "ctem-alerts.json")
    if os.path.exists(path) and os.path.getsize(path) > FILE_MAX:
        os.replace(path, path + ".1")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, separators=(",", ":"), sort_keys=True) + "\n")
