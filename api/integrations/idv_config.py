"""Checks on the Persona and Twilio integration settings before they are stored (a saved secret arrives as
__REDACTED__ on an edit and is left alone)."""
from __future__ import annotations

import re

_KEPT = "__REDACTED__"
_PERSONA_KEY = re.compile(r"^persona_(production|sandbox)_[A-Za-z0-9\-]{20,80}$")
_TEMPLATE = re.compile(r"^(itmpl|tmpl)_[A-Za-z0-9]{8,40}$")
_E164 = re.compile(r"^\+[1-9][0-9]{7,14}$")


def _num(config: dict, key: str, lo: int, hi: int, what: str) -> None:
    v = config.get(key)
    if v in (None, ""):
        return
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{what} must be a whole number") from None
    if not lo <= n <= hi:
        raise ValueError(f"{what} must be from {lo} to {hi}")


def check(vendor: str, config: dict) -> None:
    if config.get("base_url"):
        raise ValueError("This integration doesn't take a base URL")
    if vendor == "persona":
        for key in ("api_key", "action_api_key"):
            v = config.get(key)
            if v not in (None, "", _KEPT) and not _PERSONA_KEY.match(str(v)):
                raise ValueError("A Persona API key looks like persona_production_...")
        t = config.get("template_id")
        if t not in (None, "") and not _TEMPLATE.match(str(t)):
            raise ValueError("The inquiry template id looks like itmpl_...")
        for t in str(config.get("badge_templates") or "").split(","):
            if t.strip() and not _TEMPLATE.match(t.strip()):
                raise ValueError("Badge templates are itmpl_... ids, comma separated")
        _num(config, "detail_budget", 0, 5000, "Device lookups per sync")
        _num(config, "max_pages", 1, 500, "Pages per sync")
        return
    if not re.fullmatch(r"AC[0-9a-f]{32}", str(config.get("account_sid") or "")):
        raise ValueError("The Account SID looks like AC followed by 32 letters and digits")
    k = config.get("api_key_sid")
    if k != _KEPT and not re.fullmatch(r"SK[0-9a-f]{32}", str(k or "")):
        raise ValueError("The API key SID looks like SK followed by 32 letters and digits")
    if isinstance(config.get("from_number"), str):   # +1 (555) 010-0100 is stored as +15550100100
        config["from_number"] = re.sub(r"[\s\-.()]", "", config["from_number"])
    if not _E164.match(str(config.get("from_number") or "")):
        raise ValueError("The sending number goes in international form, like +15550100100")
