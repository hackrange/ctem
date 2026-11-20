"""Shared bits for Rapid7 Insight Platform connectors (one key, many products)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

# Insight Platform data regions. Allow-listed so a config value can never steer us at a random host.
REGIONS = ("us", "us2", "us3", "eu", "ca", "au", "ap")
_REGION_ALIASES = {"us1": "us", "us-east-1": "us", "eu-central-1": "eu", "ca-central-1": "ca",
                   "ap-southeast-2": "au", "ap-northeast-1": "ap"}
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:\-]{1,200}$")


def region(config: dict) -> str:
    raw = str(config.get("region") or "us").strip().lower()
    raw = _REGION_ALIASES.get(raw, raw)
    if raw not in REGIONS:
        raise ValueError(f"Unknown Rapid7 region (expected one of: {', '.join(REGIONS)})")
    return raw


def platform_base(config: dict) -> str:
    return f"https://{region(config)}.api.insight.rapid7.com"


def headers(config: dict) -> dict:
    return {"X-Api-Key": config["api_key"], "Content-Type": "application/json", "Accept": "application/json"}


def safe_id(value: str) -> bool:
    # Ids get dropped into the v4 query language, so keep them boring
    return bool(value) and bool(_SAFE_ID.match(value))


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)  # CloudSec hands out naive UTC


def int_cfg(config: dict, key: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(config.get(key, default))))
    except (TypeError, ValueError):
        return default
