"""CrowdStrike Falcon alert (Alerts API v2) -> what CTEM keeps. Standard library only.

Used by the on-prem shipper and by CTEM's direct connector, so both keep the same fields. Everything
is capped and type-checked here, and checked again by clean() on the CTEM side, because it is untrusted.
"""
import re
from datetime import datetime, timezone

_ID = re.compile(r"^[0-9a-fA-F]{32}$")
_ALERT_ID = re.compile(r"^[A-Za-z0-9:_.-]{1,200}$")
_TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_TACTIC = re.compile(r"^TA\d{4}$")
_LINK = re.compile(r"^https://falcon(?:\.[a-z0-9-]+)*\.crowdstrike\.com/[^\s\"'<>]*$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_MD5 = re.compile(r"^[0-9a-fA-F]{32}$")
_IP = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")
_MAC = re.compile(r"^[0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")

# What Falcon did about it; only these flags are kept (pattern_disposition_details)
ACTIONS = {
    "kill_process": "killed the process", "kill_parent": "killed the parent process",
    "kill_subprocess": "killed child processes", "quarantine_file": "quarantined the file",
    "quarantine_machine": "network-contained the host", "process_blocked": "blocked the process",
    "operation_blocked": "blocked the operation", "registry_operation_blocked": "blocked a registry change",
    "fs_operation_blocked": "blocked a file operation", "handle_operation_downgraded": "downgraded a handle",
    "suspend_process": "suspended the process", "suspend_parent": "suspended the parent process",
    "critical_process_disabled": "disabled a critical process", "bootup_safeguard_enabled": "enabled bootup safeguard",
    "containment_file_system": "contained the file system", "response_action_triggered": "ran a response action",
    "response_action_failed": "a response action failed", "kill_action_failed": "a kill action failed",
    "policy_disabled": "detect only: prevention is off in the policy", "sensor_only": "detect only (sensor only)",
    "detect": "detected it", "indicator": "matched an indicator",
}
LIST_CAP = 50


def txt(v, cap=300):
    """A single-line, capped string, or None."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        v = str(v)
    if not isinstance(v, str):
        return None
    v = _CTRL.sub(" ", v).strip()
    return v[:cap] or None


def _match(rx, v, cap=200):
    v = txt(v, cap)
    return v if v and rx.match(v) else None


def _int(v, lo=0, hi=2 ** 63):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if lo <= n <= hi else None


def when(v):
    """ISO 8601 UTC from an ISO string or epoch seconds/milliseconds; None if it isn't a time."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        n = float(v)
        if n > 1e12:
            n /= 1000.0
        if not 946684800 <= n <= 4102444800:   # 2000-01-01 .. 2100-01-01
            return None
        return datetime.fromtimestamp(n, timezone.utc).isoformat()
    s = txt(v, 40)
    if not s:
        return None
    if s.isdigit():
        return when(int(s))
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()


def _proc(p, user=None):
    if not isinstance(p, dict):
        return None
    out = {"filename": txt(p.get("filename") or p.get("image_file_name"), 260),
           "filepath": txt(p.get("filepath"), 1024), "cmdline": txt(p.get("cmdline"), 4000),
           "sha256": _match(_SHA256, p.get("sha256"), 64), "md5": _match(_MD5, p.get("md5"), 32),
           "pid": _int(p.get("local_process_id") or p.get("process_id")),
           "start": when(p.get("process_start_time") or p.get("timestamp")),
           "end": when(p.get("process_end_time")),
           "user": txt(p.get("user_name") or user, 256)}
    out = {k: v for k, v in out.items() if v is not None}
    return out or None


def _list(items, fn, cap=LIST_CAP):
    out = []
    for x in items if isinstance(items, list) else []:
        if len(out) >= cap:
            break
        y = fn(x) if isinstance(x, dict) else None
        if y:
            out.append(y)
    return out


def _file(f):
    out = {"filename": txt(f.get("filename"), 260), "filepath": txt(f.get("filepath"), 1024),
           "sha256": _match(_SHA256, f.get("sha256"), 64), "at": when(f.get("timestamp"))}
    out = {k: v for k, v in out.items() if v is not None}
    return out if out.get("filename") or out.get("filepath") else None


def _quarantined(f):
    out = {"filename": txt(f.get("filename"), 260), "sha256": _match(_SHA256, f.get("sha256"), 64),
           "state": txt(f.get("state"), 32)}
    out = {k: v for k, v in out.items() if v is not None}
    return out if out.get("filename") or out.get("sha256") else None


def _net(n):
    out = {"direction": txt(n.get("connection_direction"), 16), "protocol": txt(n.get("protocol"), 16),
           "local": _match(_IP, n.get("local_address"), 45), "local_port": _int(n.get("local_port"), 0, 65535),
           "remote": _match(_IP, n.get("remote_address"), 45), "remote_port": _int(n.get("remote_port"), 0, 65535),
           "at": when(n.get("access_timestamp"))}
    if isinstance(out["direction"], str) and out["direction"].isdigit():
        out["direction"] = {"0": "outbound", "1": "inbound"}.get(out["direction"], out["direction"])
    out = {k: v for k, v in out.items() if v is not None}
    return out if out.get("remote") else None


def _dns(d):
    out = {"domain": txt(d.get("domain_name"), 253), "type": txt(d.get("request_type"), 16),
           "at": when(d.get("load_timestamp") or d.get("timestamp"))}
    out = {k: v for k, v in out.items() if v is not None}
    return out if out.get("domain") else None


def _mitre(m):
    out = {"tactic": txt(m.get("tactic"), 128), "tactic_id": _match(_TACTIC, m.get("tactic_id"), 8),
           "technique": txt(m.get("technique"), 128), "technique_id": _match(_TECH, m.get("technique_id"), 16)}
    out = {k: v for k, v in out.items() if v is not None}
    return out or None


def detail(a):
    """Everything worth showing about one alert, from the Alerts API v2 entity."""
    dev = a.get("device") if isinstance(a.get("device"), dict) else {}
    disp = a.get("pattern_disposition_details") if isinstance(a.get("pattern_disposition_details"), dict) else {}
    out = {
        "severity_score": _int(a.get("severity"), 0, 100), "confidence": _int(a.get("confidence"), 0, 100),
        "objective": txt(a.get("objective"), 128), "scenario": txt(a.get("scenario"), 128),
        "type": txt(a.get("type") or a.get("product"), 64), "pattern_id": _int(a.get("pattern_id")),
        "aggregate_id": _match(_ALERT_ID, a.get("aggregate_id")),
        "event_time": when(a.get("timestamp")), "created": when(a.get("created_timestamp")),
        "updated": when(a.get("updated_timestamp")), "assigned_to": txt(a.get("assigned_to_name"), 128),
        "resolution": txt(a.get("resolution"), 64),
        "user": {k: v for k, v in {"name": txt(a.get("user_name"), 256), "domain": txt(a.get("logon_domain"), 256),
                                   "principal": txt(a.get("user_principal"), 256),
                                   "sid": txt(a.get("user_id"), 128)}.items() if v} or None,
        "process": _proc(a), "parent": _proc(a.get("parent_details")),
        "grandparent": _proc(a.get("grandparent_details")),
        "disposition": {"summary": txt(a.get("pattern_disposition_description"), 500),
                        "actions": [k for k in ACTIONS if disp.get(k) is True]},
        "ioc": {k: v for k, v in {"type": txt(a.get("ioc_type"), 64), "value": txt(a.get("ioc_value"), 1024),
                                  "source": txt(a.get("ioc_source"), 128),
                                  "description": txt(a.get("ioc_description"), 500)}.items() if v} or None,
        "quarantined": _list(a.get("quarantined_files"), _quarantined, 20),
        "files_written": _list(a.get("files_written") or a.get("executables_written"), _file),
        "documents": _list(a.get("documents_accessed"), _file),
        "network": _list(a.get("network_accesses"), _net),
        "dns": _list(a.get("dns_requests"), _dns),
        "mitre": _list(a.get("mitre_attack"), _mitre, 10),
        "prevalence": {k: v for k, v in {"global": txt(a.get("global_prevalence"), 32),
                                         "local": txt(a.get("local_prevalence"), 32)}.items() if v} or None,
        "host": {k: v for k, v in {
            "platform": txt(dev.get("platform_name"), 32), "os_version": txt(dev.get("os_version"), 128),
            "product_type": txt(dev.get("product_type_desc"), 64),
            "local_ip": _match(_IP, dev.get("local_ip"), 45), "external_ip": _match(_IP, dev.get("external_ip"), 45),
            "mac": _match(_MAC, dev.get("mac_address"), 17), "domain": txt(dev.get("machine_domain"), 253),
            "site": txt(dev.get("site_name"), 128), "ou": [x for x in (txt(o, 128) for o in (dev.get("ou") or [])
                                                                       if isinstance(dev.get("ou"), list)) if x][:5],
            "agent_version": txt(dev.get("agent_version"), 32), "containment": txt(dev.get("status"), 32)}.items()
            if v} or None,
    }
    if not out["disposition"]["summary"] and not out["disposition"]["actions"]:
        out["disposition"] = None
    return {k: v for k, v in out.items() if v not in (None, [], {})}


def summary(a):
    """The alert's list fields plus its detail, in the shape CTEM ingests (CsDetection)."""
    cid = a.get("composite_id")
    if not isinstance(cid, str) or not _ALERT_ID.match(cid):
        return None
    desc = a.get("description") or a.get("display_name")
    dev = a.get("device") if isinstance(a.get("device"), dict) else {}
    did = dev.get("device_id")
    return {"detection_id": cid, "max_severity_displayname": (txt(a.get("severity_name"), 32) or None),
            "title": txt(a.get("display_name") or a.get("name"), 300),
            "status": txt(a.get("status"), 32),
            "detected_at": txt(a.get("created_timestamp") or a.get("timestamp"), 40),
            "tactic": txt(a.get("tactic"), 128), "technique": txt(a.get("technique"), 128),
            "tactic_id": _match(_TACTIC, a.get("tactic_id"), 8), "technique_id": _match(_TECH, a.get("technique_id"), 16),
            "link": _match(_LINK, a.get("falcon_host_link"), 1000),
            "device": {"hostname": txt(dev.get("hostname"), 253),
                       "device_id": did if isinstance(did, str) and _ID.match(did) else None},
            "behaviors": [{"description": txt(desc, 2000)}] if txt(desc, 2000) else [],
            "detail": detail(a)}


# ── the CTEM side: received detail is untrusted, so rebuild it from known keys only ──

_PROC_KEYS = {"filename": 260, "filepath": 1024, "cmdline": 4000, "user": 256}


def _clean_proc(p):
    if not isinstance(p, dict):
        return None
    out = {k: txt(p.get(k), cap) for k, cap in _PROC_KEYS.items()}
    out.update({"sha256": _match(_SHA256, p.get("sha256"), 64), "md5": _match(_MD5, p.get("md5"), 32),
                "pid": _int(p.get("pid")), "start": when(p.get("start")), "end": when(p.get("end"))})
    out = {k: v for k, v in out.items() if v is not None}
    return out or None


def _clean_flat(d, spec):
    if not isinstance(d, dict):
        return None
    out = {}
    for k, kind in spec.items():
        v = d.get(k)
        if kind == "at":
            v = when(v)
        elif kind == "port":
            v = _int(v, 0, 65535)
        elif kind == "ip":
            v = _match(_IP, v, 45)
        elif kind == "sha256":
            v = _match(_SHA256, v, 64)
        elif kind == "tactic":
            v = _match(_TACTIC, v, 8)
        elif kind == "tech":
            v = _match(_TECH, v, 16)
        elif kind == "mac":
            v = _match(_MAC, v, 17)
        else:
            v = txt(v, kind)
        if v is not None:
            out[k] = v
    return out or None


def _clean_list(items, spec, cap=LIST_CAP):
    return [y for y in (_clean_flat(x, spec) for x in (items if isinstance(items, list) else [])[:cap]) if y]


def clean(d):
    """Rebuild a received detail dict from the keys and types detail() produces; drop anything else."""
    if not isinstance(d, dict):
        return {}
    file_spec = {"filename": 260, "filepath": 1024, "sha256": "sha256", "at": "at"}
    disp = d.get("disposition") if isinstance(d.get("disposition"), dict) else {}
    host = _clean_flat(d.get("host"), {"platform": 32, "os_version": 128, "product_type": 64, "local_ip": "ip",
                                       "external_ip": "ip", "mac": "mac", "domain": 253, "site": 128,
                                       "agent_version": 32, "containment": 32})
    ou = [x for x in (txt(o, 128) for o in ((d.get("host") or {}).get("ou") or [])
                      if isinstance((d.get("host") or {}).get("ou"), list)) if x][:5] if isinstance(d.get("host"), dict) else []
    if ou:
        host = {**(host or {}), "ou": ou}
    out = {
        "severity_score": _int(d.get("severity_score"), 0, 100), "confidence": _int(d.get("confidence"), 0, 100),
        "objective": txt(d.get("objective"), 128), "scenario": txt(d.get("scenario"), 128), "type": txt(d.get("type"), 64),
        "pattern_id": _int(d.get("pattern_id")), "aggregate_id": _match(_ALERT_ID, d.get("aggregate_id")),
        "event_time": when(d.get("event_time")), "created": when(d.get("created")), "updated": when(d.get("updated")),
        "assigned_to": txt(d.get("assigned_to"), 128), "resolution": txt(d.get("resolution"), 64),
        "user": _clean_flat(d.get("user"), {"name": 256, "domain": 256, "principal": 256, "sid": 128}),
        "process": _clean_proc(d.get("process")), "parent": _clean_proc(d.get("parent")),
        "grandparent": _clean_proc(d.get("grandparent")),
        "disposition": {"summary": txt(disp.get("summary"), 500),
                        "actions": [k for k in (disp.get("actions") or []) if k in ACTIONS][:len(ACTIONS)]}
        if isinstance(disp.get("actions", []), list) else None,
        "ioc": _clean_flat(d.get("ioc"), {"type": 64, "value": 1024, "source": 128, "description": 500}),
        "quarantined": _clean_list(d.get("quarantined"), {"filename": 260, "sha256": "sha256", "state": 32}, 20),
        "files_written": _clean_list(d.get("files_written"), file_spec),
        "documents": _clean_list(d.get("documents"), file_spec),
        "network": _clean_list(d.get("network"), {"direction": 16, "protocol": 16, "local": "ip", "local_port": "port",
                                                  "remote": "ip", "remote_port": "port", "at": "at"}),
        "dns": _clean_list(d.get("dns"), {"domain": 253, "type": 16, "at": "at"}),
        "mitre": _clean_list(d.get("mitre"), {"tactic": 128, "tactic_id": "tactic", "technique": 128,
                                              "technique_id": "tech"}, 10),
        "prevalence": _clean_flat(d.get("prevalence"), {"global": 32, "local": 32}),
        "host": host,
    }
    if out["disposition"] and not out["disposition"]["summary"] and not out["disposition"]["actions"]:
        out["disposition"] = None
    if out["disposition"] and out["disposition"]["summary"] is None:
        out["disposition"].pop("summary")
    return {k: v for k, v in out.items() if v not in (None, [], {})}
