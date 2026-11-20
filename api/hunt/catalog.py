"""Ready-made Splunk searches, scoped to the indexes that actually hold the fields."""
from __future__ import annotations

from api.hunt.scope import index_clause, scoped

# (category, title, fields the search needs, body after the index clause, plain description)
# No earliest= here: the hunt page's time picker sets the window, and the text
# pastes cleanly into Splunk where its own picker applies.
_TEMPLATES = [
    ("threat-hunting", "Password guessing and lockouts", ("EventCode", "TargetUserName"),
     "(EventCode=4625 OR EventCode=4740) | stats count(eval(EventCode=4625)) as failed_signins "
     "count(eval(EventCode=4740)) as lockouts min(_time) as first_seen max(_time) as last_seen "
     "values(IpAddress) as from_ips values(WorkstationName) as from_machines by TargetUserName "
     "| where failed_signins > 10 OR lockouts > 0 | sort -failed_signins",
     "Accounts with many failed sign-ins or lockouts, where the attempts came from, and when"),
    ("threat-hunting", "Password spraying (one source, many accounts)", ("EventCode", "IpAddress"),
     "(EventCode=4625 OR EventCode=4740) | stats dc(TargetUserName) as accounts_tried "
     "values(TargetUserName) as accounts count min(_time) as first_seen max(_time) as last_seen "
     "by IpAddress | where accounts_tried > 2 | sort -accounts_tried",
     "One machine trying lots of different accounts, a sign of password spraying"),
    ("threat-hunting", "Remote sign-ins (RDP and network)", ("EventCode", "LogonType"),
     "EventCode=4624 LogonType IN (3, 10) | stats count min(_time) as first_seen max(_time) as last_seen "
     "by TargetUserName IpAddress host | sort -count",
     "Who signed in to which machine over the network"),
    ("threat-hunting", "New services or scheduled tasks", ("EventCode", "ServiceName", "TaskName"),
     "(EventCode=4698 OR EventCode=7045) | table _time host ServiceName ImagePath TaskName SubjectUserName",
     "Programs set up to start by themselves, a common way attackers stay in"),
    ("threat-hunting", "EDR detections", ("event_simpleName", "DetectName"),
     "event_simpleName=DetectionSummaryEvent | table _time ComputerName UserName Tactic Technique "
     "SeverityName FileName CommandLine",
     "Endpoint security alerts with the program that set them off"),
    ("threat-hunting", "Segmentation incidents", ("event_type", "source_asset"),
     "(event_type=incident OR event_type=policy_violation) | table _time source_asset "
     "destination_asset destination_port severity description",
     "Traffic that broke network rules, including scans and data leaving"),
    ("compliance", "Admin group changes", ("EventCode", "MemberName"),
     "(EventCode=4728 OR EventCode=4732 OR EventCode=4756) | table _time host SubjectUserName MemberName",
     "Someone added to a privileged group"),
    ("compliance", "Admin sign-ins", ("EventCode", "SubjectUserName"),
     "EventCode=4672 | stats count min(_time) as first_seen max(_time) as last_seen by SubjectUserName host "
     "| sort -count",
     "Accounts using special admin rights"),
]


def build_spl_catalog(indexes: list[dict], schema: dict | None = None) -> list[dict]:
    catalog = []
    for category, title, fields, body, description in _TEMPLATES:
        spl = scoped(schema, fields, body)
        if spl:
            catalog.append({"category": category, "title": title, "spl": spl.removeprefix("search "),
                            "description": description})
    names = [i.get("name") for i in indexes if i.get("name") and not i["name"].startswith("_")
             and int(i.get("totalEventCount") or 0) > 0]
    everything = index_clause(names)
    if everything:
        catalog.append({"category": "incident-response", "title": "Everything about one host",
                        "spl": f'{everything} (host="REPLACE_ME" OR ComputerName="REPLACE_ME" OR '
                               'source_asset="REPLACE_ME") | stats count min(_time) as first_seen '
                               "max(_time) as last_seen by index sourcetype",
                        "description": "Replace REPLACE_ME with the hostname you are looking into"})
    for name in names:
        catalog.append({"category": "index-specific", "index": name, "title": f"What is in {name}",
                        "spl": f"{index_clause([name])} | stats count by sourcetype | sort -count",
                        "description": f"The kinds of events stored in {name}"})
    return catalog
