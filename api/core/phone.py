"""Phone numbers in one shape: +<country code><number>, with ;ext=N when there is one."""
from __future__ import annotations

import phonenumbers

_MAX_RAW = 64


def normalize(raw: str | None, country: str | None = None, default_region: str = "US") -> str | None:
    """'(555) 010-0199 x12' with country US -> '+15550100199;ext=12'. None when it isn't a real number."""
    if not raw or not isinstance(raw, str):
        return None
    raw = raw.strip()[:_MAX_RAW]
    region = (country or default_region or "US").upper()
    if raw.startswith("00"):  # international dialing prefix used outside North America
        raw = "+" + raw[2:]
    try:
        num = phonenumbers.parse(raw, None if raw.startswith("+") else region)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_possible_number(num):
        return None
    out = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    ext = "".join(ch for ch in (num.extension or "") if ch.isdigit())[:10]
    return f"{out};ext={ext}" if ext else out
