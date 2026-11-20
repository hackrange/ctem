"""No-AI planner: pick scoped lookups from keywords and the names in the question."""
from __future__ import annotations

import re

from api.hunt.catalog import _TEMPLATES
from api.hunt.scope import notable_clause, scoped
from api.hunt.spl_guard import quote_value

# keyword pattern -> catalog template titles it maps to
_INTENTS = [
    (r"fail|brute|guess|spray|password|lock", ("Password guessing and lockouts", "Password spraying (one source, many accounts)")),
    (r"detect|malware|edr|virus|credential|dump|lsass|steal", ("EDR detections",)),
    (r"lateral|scan|network|segment|exfil|data|transfer|leav", ("Segmentation incidents",)),
    (r"persist|service|scheduled|task|startup", ("New services or scheduled tasks",)),
    (r"admin|privilege|group|escalat|rights", ("Admin group changes", "Admin sign-ins")),
]

HOST_FIELDS = ("host", "ComputerName", "WorkstationName", "source_asset", "destination_asset", "dest_host", "hostname")
USER_FIELDS = ("TargetUserName", "SubjectUserName", "UserName", "user", "src_user")
IP_FIELDS = ("IpAddress", "aip", "LocalAddressIP4", "RemoteAddressIP4", "source_ip", "destination_ip", "src_ip", "dest_ip")

_HOST = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+\b")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER = re.compile(r"\b(?:user|account|username)\s+(?:named\s+)?([A-Za-z0-9._\\-]{2,64})", re.I)


def entities(question: str) -> dict[str, list[str]]:
    ips = _IP.findall(question)
    hosts = [h for h in _HOST.findall(question) if h not in ips and any(c.isdigit() for c in h)]
    users = [u for u in _USER.findall(question) if u.lower() not in ("the", "a", "an", "account", "user")]
    return {"hosts": hosts[:3], "ips": ips[:3], "users": users[:3]}


def entity_filter(kind: str, value: str) -> tuple[tuple[str, ...], str]:
    """The fields to scope on and the OR filter that finds this entity in them."""
    if kind == "user":
        bare = value.split("\\")[-1]
        terms = [f"{f}={quote_value(bare)}" for f in USER_FIELDS]
        terms.append(f"UserName={quote_value('*' + bare)}")
        return USER_FIELDS, "(" + " OR ".join(terms) + ")"
    fields = HOST_FIELDS if kind == "host" else IP_FIELDS
    return fields, "(" + " OR ".join(f"{f}={quote_value(value)}" for f in fields) + ")"


def plan(question: str, schema: dict | None) -> list[dict]:
    q = question.lower()
    found = entities(question)
    by_title = {t[1]: t for t in _TEMPLATES}
    lookups: list[dict] = []
    if schema:
        for pattern, titles in _INTENTS:
            if re.search(pattern, q):
                for title in titles:
                    _, _, fields, body, desc = by_title[title]
                    spl = scoped(schema, fields, body)
                    if spl:
                        lookups.append({"source": "splunk", "title": title, "why": desc, "spl": spl})
        notable = notable_clause(schema)
        for kind, values in (("host", found["hosts"]), ("ip", found["ips"]), ("user", found["users"])):
            for value in values:
                fields, filt = entity_filter(kind, value)
                spl = scoped(schema, fields, f"{filt} {notable}" if notable else filt)
                if spl:
                    lookups.append({"source": "splunk", "title": f"Notable activity involving {value}",
                                    "why": "Named in your question", "spl": spl + " | sort - _time"})
        if not lookups and notable:
            lookups.append({"source": "splunk", "title": "All notable security events",
                            "why": "Nothing specific was named, so this is the overview",
                            "spl": f"search {notable} | stats count min(_time) as first_seen "
                                   "max(_time) as last_seen by index host | sort -count"})
    for h in found["hosts"]:
        lookups.append({"source": "ctem", "title": f"What open-ctem knows about {h}", "why": "Asset record",
                        "table": "devices", "filters": {"hostname": h}, "limit": 5})
        lookups.append({"source": "ctem", "title": f"Tool alerts for {h}", "why": "Alerts from connected tools",
                        "table": "alerts", "filters": {"hostname": h}, "limit": 25})
    for u in found["users"]:
        lookups.append({"source": "ctem", "title": f"Directory record for {u}", "why": "Account details",
                        "table": "users", "filters": {"username": u}, "limit": 5})
    if not any(lk["source"] == "ctem" for lk in lookups):
        lookups.append({"source": "ctem", "title": "Latest alerts from connected tools",
                        "why": "Everything your security tools flagged recently", "table": "alerts",
                        "filters": {}, "limit": 50})
    return lookups[:8]
