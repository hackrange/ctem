"""Threat hunting data for the CrowdStrike source: Falcon Intel indicators, the real-time event stream, and Falcon
Data Replicator (FDR) telemetry summarized into fleet stacks. Each is optional ("off" in the source's settings, or
no license or scope: a note for CTEM's card and the run carries on).

Formats follow CrowdStrike's own code: the event stream as their integration gateway reads it (GET dataFeedURL with
"Authorization: Token", "&offset=" to resume, one JSON event per line), FDR as their replicator does (an SQS message
names the S3 bucket and files)."""
import gzip
import hashlib
import io
import json
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import collector_common as cc

INTEL_DAYS = 30            # high-confidence indicators updated this recently
STREAM_SECONDS = 90        # how long one run reads the event stream
STREAM_MAX = 20000
FDR_SECONDS = 240          # how long one run reads FDR
APP_ID = "openctem"
_SAFE = re.compile(r"[\x00-\x08\x0b-\x1f]")


def _txt(v, cap):
    return _SAFE.sub(" ", v.strip())[:cap] or None if isinstance(v, str) and v.strip() else None


def _on(s, key, default="on"):
    return str(s.get(key, default)).lower() != "off"


def intel(api, s, state, notes):
    """Falcon Intel high-confidence indicators: the last INTEL_DAYS days first, then what changed since."""
    if not _on(s, "intel"):
        return
    key = f"cs_intel_at:{s.get('client_id', '')[:8]}"
    since = int(state.get(key) or time.time() - INTEL_DAYS * 86400) - 3600
    started, offset = int(time.time()), 0
    for _ in range(1000):
        q = {"filter": f"malicious_confidence:'high'+last_updated:>{since}", "limit": 5000, "offset": offset,
             "sort": "last_updated|asc"}
        try:
            data = api.call("GET", "/intel/combined/indicators/v1?" + urllib.parse.urlencode(q))
        except cc.HttpError as e:
            if 400 <= e.status < 500 and e.status != 429:
                cc.say(f"  CrowdStrike: Intel refused (HTTP {e.status}); skipped")
                notes.append(f"Falcon refused Intel indicators (HTTP {e.status}), so they were skipped; if Falcon "
                             "Intelligence is licensed, give the API client the Indicators (Falcon Intelligence): Read scope")
                return
            raise
        rows = [x for x in map(_indicator, data.get("resources") or []) if x]
        if rows:
            yield {"intel": rows}
        got = len(data.get("resources") or [])
        offset += got
        if got < 5000 or offset >= 50000:   # the offset window: the next run picks up from last_updated
            break
    state[key] = started


def _indicator(r):
    v, t = _txt(r.get("indicator"), 512), _txt(r.get("type"), 32)
    if not v or not t:
        return None
    ts = lambda x: datetime.fromtimestamp(x, timezone.utc).isoformat() if isinstance(x, int) and x > 0 else None  # noqa: E731
    return {"value": v.lower(), "type": t, "confidence": _txt(r.get("malicious_confidence"), 16),
            "actors": [a for a in (_txt(x, 128) for x in (r.get("actors") or [])[:10]) if a],
            "malware": [a for a in (_txt(x, 128) for x in (r.get("malware_families") or [])[:10]) if a],
            "labels": [a for a in (_txt((x or {}).get("name") if isinstance(x, dict) else x, 64) for x in (r.get("labels") or [])[:10]) if a],
            "published": ts(r.get("published_date")), "updated": ts(r.get("last_updated"))}


def stream(api, s, state, notes, cafile=None):
    """The real-time event stream: read for STREAM_SECONDS from where the last run stopped."""
    if not _on(s, "event_stream"):
        return
    try:
        feeds = api.call("GET", f"/sensors/entities/datafeed/v2?appId={APP_ID}&format=json").get("resources") or []
    except cc.HttpError as e:
        if 400 <= e.status < 500 and e.status != 429:
            cc.say(f"  CrowdStrike: event stream refused (HTTP {e.status}); skipped")
            notes.append(f"Falcon refused the event stream (HTTP {e.status}), so it was skipped; give the API client the "
                         "Event streams: Read scope")
            return
        raise
    for f in feeds:
        url, token = f.get("dataFeedURL"), ((f.get("sessionToken") or {}).get("token"))
        m = re.search(r"/sensors/entities/datafeed/v1/([0-9a-zA-Z]+)\?", url or "")
        if not (url and token and m and url.startswith("https://")):
            continue
        part = m.group(1)[:16]
        key = f"cs_stream_offset:{part}"
        last = state.get(key)
        full = url + (f"&offset={int(last) + 1}" if last is not None else "&whence=2")   # first time: from now
        batch, deadline = [], time.time() + STREAM_SECONDS
        req = urllib.request.Request(full, headers={"Authorization": f"Token {token}", "Connection": "Keep-Alive"})
        try:
            with urllib.request.urlopen(req, timeout=30, context=cc.tls_context(cafile)) as resp:  # nosec B310 - https only, checked above
                while time.time() < deadline and len(batch) < STREAM_MAX:
                    line = resp.readline()
                    if not line:
                        break
                    if not line.strip():
                        continue
                    ev = _stream_event(line, part)
                    if ev:
                        batch.append(ev)
                        state[key] = ev["offset"]
                    if len(batch) >= 1000:
                        yield {"stream_events": batch}
                        batch = []
        except (TimeoutError, OSError):
            pass   # a quiet stream times out the read: normal; the offset is kept
        if batch:
            yield {"stream_events": batch}


def _stream_event(line, part):
    try:
        e = json.loads(line.decode("utf-8", "replace"))
    except ValueError:
        return None
    md, ev = e.get("metadata") or {}, e.get("event") or {}
    if not isinstance(md.get("offset"), int):
        return None
    created = md.get("eventCreationTime")
    at = datetime.fromtimestamp(created / 1000, timezone.utc).isoformat() if isinstance(created, (int, float)) else None
    keep = {k: _txt(str(v), 500) for k, v in ev.items() if isinstance(v, (str, int, float, bool)) and k[:1].isalpha()}
    return {"partition": part, "offset": md["offset"], "type": _txt(md.get("eventType"), 64) or "unknown", "at": at,
            "hostname": _txt(ev.get("ComputerName") or ev.get("Hostname"), 253), "user": _txt(ev.get("UserName") or ev.get("UserId"), 256),
            "severity": _txt(ev.get("SeverityName") or (str(ev.get("Severity")) if ev.get("Severity") is not None else None), 16),
            "summary": _txt(ev.get("DetectName") or ev.get("Name") or ev.get("OperationName") or ev.get("DetectDescription"), 500),
            "event": dict(list(keep.items())[:60])}


# FDR events kept for hunting, and what makes each one distinct
_KINDS = {"ProcessRollup2": "process", "SyntheticProcessRollup2": "process", "DnsRequest": "dns",
          "NetworkConnectIP4": "network", "NetworkConnectIP6": "network", "UserLogon": "logon", "UserLogonFailed2": "logon_failed"}


def stack_of(e):
    """(kind, value, sha256, fields) for one FDR event, or None when it isn't one we keep."""
    kind = _KINDS.get(e.get("event_simpleName"))
    if not kind:
        return None
    if kind == "process":
        img = _txt(e.get("ImageFileName"), 512)
        if not img:
            return None
        sha = str(e.get("SHA256HashData") or "").lower()
        return kind, img, sha if re.match(r"^[0-9a-f]{64}$", sha) else None, {
            "command_line": _txt(e.get("CommandLine"), 1000), "parent": _txt(e.get("ParentBaseFileName"), 256), "user": _txt(e.get("UserName"), 256)}
    if kind == "dns":
        d = _txt(e.get("DomainName"), 253)
        return (kind, d.lower().rstrip("."), None, {}) if d else None
    if kind == "network":
        ip, port = _txt(e.get("RemoteAddressIP4") or e.get("RemoteAddressIP6"), 45), str(e.get("RemotePort") or "")
        return (kind, f"{ip}:{port}" if port.isdigit() else ip, None, {"protocol": _txt(str(e.get("Protocol") or ""), 8)}) if ip else None
    u = _txt(e.get("UserName"), 256)
    return (kind, u, None, {"logon_type": _txt(str(e.get("LogonType") or ""), 8)}) if u else None


def fdr(s, secret, state, notes):
    """FDR: read the SQS queue for FDR_SECONDS, fold each file's events into fleet stacks, send them, then delete the
    message (so a crash replays it). Needs the queue URL and region in the source's settings and the FDR key and
    secret on the box; off until they're set."""
    if not (_on(s, "fdr", "off") and s.get("fdr_queue_url") and secret.get("fdr_secret_key") and s.get("fdr_access_key_id")):
        return
    try:
        import boto3  # optional: only FDR needs it
    except ImportError:
        notes.append("FDR is on but boto3 isn't installed on the shipper box; re-run the installer to add it")
        return
    kw = {"region_name": s.get("fdr_region") or "us-west-1", "aws_access_key_id": s["fdr_access_key_id"],
          "aws_secret_access_key": secret["fdr_secret_key"]}
    sqs, s3 = boto3.client("sqs", **kw), boto3.client("s3", **kw)
    deadline = time.time() + FDR_SECONDS
    while time.time() < deadline:
        msgs = sqs.receive_message(QueueUrl=s["fdr_queue_url"], MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                   VisibilityTimeout=900).get("Messages") or []
        if not msgs:
            break
        for m in msgs:
            stacks = {}
            body = json.loads(m.get("Body") or "{}")
            for f in body.get("files") or []:
                path = f.get("path") if isinstance(f, dict) else None
                if not path:
                    continue
                obj = s3.get_object(Bucket=body["bucket"], Key=path)["Body"].read()
                raw = gzip.GzipFile(fileobj=io.BytesIO(obj)) if obj[:2] == b"\x1f\x8b" else io.BytesIO(obj)
                for line in raw:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    _fold(stacks, e)
                    if len(stacks) >= 5000:
                        yield {"hunt": list(stacks.values())}
                        stacks = {}
            if stacks:
                yield {"hunt": list(stacks.values())}
            sqs.delete_message(QueueUrl=s["fdr_queue_url"], ReceiptHandle=m["ReceiptHandle"])


def _fold(stacks, e):
    st = stack_of(e)
    aid = str(e.get("aid") or "")
    if st is None or not re.match(r"^[0-9a-f]{32}$", aid):
        return
    kind, value, sha, fields = st
    try:
        ts = datetime.fromtimestamp(int(e.get("timestamp")) / 1000, timezone.utc)
    except (TypeError, ValueError):
        return
    day = ts.date().isoformat()
    key = hashlib.sha256(f"{kind}|{value.lower()}|{sha or ''}".encode()).hexdigest()
    k = (day, key)
    row = stacks.get(k)
    if row is None:
        row = stacks[k] = {"day": day, "kind": kind, "key": key, "value": value, "sha256": sha, "fields": fields,
                           "hosts": [], "events": 0, "first_seen": ts.isoformat(), "last_seen": ts.isoformat()}
    if aid not in row["hosts"] and len(row["hosts"]) < 200:
        row["hosts"].append(aid)
    row["events"] += 1
    row["first_seen"] = min(row["first_seen"], ts.isoformat())
    row["last_seen"] = max(row["last_seen"], ts.isoformat())
