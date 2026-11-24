"""Cloud configuration findings (CSPM) are scored on their own terms: a misconfiguration has no CVE, EPSS or KEV, so the
host formula left every one of them, critical or not, at about 33 (a B). Here the tool's own severity sets the base,
and what the check is about moves it: open to the internet or anonymous access raises it most, identity and admin
rights raise it, logging and housekeeping checks lower it.

    critical 70, high 50, medium 30, low 15, info 5
    + 20 public or internet-facing, + 10 identity, credentials or admin rights, - 10 logging, tagging or backups
A critical public bucket is 90 (F), a critical check 70 (D), a high one 50 (C), a high logging check 40 (B)."""
from __future__ import annotations

import re

BASE = {5: 70.0, 4: 50.0, 3: 30.0, 2: 15.0, 1: 5.0}
SEVERITY_NAME = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}
_PUBLIC = re.compile(r"\b(public(ly)?|internet|anonymous|world[- ]?(readable|writ|access)|0\.0\.0\.0|unrestricted|open to all|"
                     r"exposed|ingress from any)", re.I)
_IDENTITY = re.compile(r"\b(admin\w*|root|privilege\w*|mfa|multi[- ]factor|access keys?|passwords?|credentials?|iam|"
                       r"wildcard|full access|owner role|service account keys?|secrets?)\b", re.I)
_HYGIENE = re.compile(r"\b(logging|logs?|audit\w*|trail|monitor\w*|retention|backups?|tag(s|ging)?|versioning|"
                      r"deletion protection|description)\b", re.I)
_TAG_PUBLIC = {"public access", "internet exposure", "exposure", "public"}
_TAG_IDENTITY = {"iam", "identity", "identity and access management", "privilege escalation", "credentials", "mfa"}
_TAG_HYGIENE = {"logging", "monitoring", "auditing", "best practices", "tagging", "backup", "cost"}
SIGNALS = ("public", "identity", "hygiene")


def signals(name: str | None, tags: list | None) -> list[str]:
    """What the check is about, from its name and the tool's tags (an allow-list, never free text)."""
    t = {str(x).strip().lower() for x in tags or []}
    text = str(name or "")
    out = []
    if t & _TAG_PUBLIC or _PUBLIC.search(text):
        out.append("public")
    if t & _TAG_IDENTITY or _IDENTITY.search(text):
        out.append("identity")
    if not out and (t & _TAG_HYGIENE or _HYGIENE.search(text)):
        out.append("hygiene")   # a logging check about a public bucket is still about the public bucket
    return out


def severity_of(details: dict | None, cvss: float | None) -> int:
    sev = (details or {}).get("severity")
    if isinstance(sev, int) and sev in BASE:
        return sev
    c = cvss or 0.0   # findings stored before severity was kept: the CVSS-ish number it was mapped to
    return 5 if c >= 9 else 4 if c >= 7 else 3 if c >= 4 else 2 if c > 0 else 1


def score(details: dict | None, cvss: float | None) -> tuple[float, list[str]]:
    """(0-100, why) for one cloud finding."""
    sev = severity_of(details, cvss)
    sig = [s for s in (details or {}).get("signals") or [] if s in SIGNALS]
    s = BASE[sev]
    why = [f"{SEVERITY_NAME[sev]} in the cloud security tool"]
    if "public" in sig:
        s += 20
        why.append("open to the internet or anonymous access")
    if "identity" in sig:
        s += 10
        why.append("identity, credentials or admin rights")
    if "hygiene" in sig:
        s -= 10
        why.append("logging or housekeeping")
    return round(max(1.0, min(100.0, s)), 1), why
