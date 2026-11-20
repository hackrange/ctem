"""Read-only gate for every SPL search the hunt runs, AI-written or not."""
from __future__ import annotations

import re

MAX_SPL_LEN = 2000

# Commands that only read and reshape. Anything that writes, emails, calls out,
# runs scripts, or expands to unseen SPL (map, macros, subsearches) stays out.
_ALLOWED = {
    "search", "where", "stats", "eventstats", "streamstats", "timechart", "chart",
    "table", "fields", "rename", "sort", "head", "tail", "dedup", "eval", "rex",
    "spath", "top", "rare", "bin", "bucket", "fillnull", "convert", "makemv",
    "mvexpand", "regex", "reverse", "addtotals", "transaction", "iplocation",
}

TIME_RANGES = {"24h": "-24h", "7d": "-7d", "30d": "-30d", "all": "0"}

_HAS_INDEX = re.compile(r"\bindex\s*(=\s*[\"']?[A-Za-z0-9_]|in\s*\()", re.I)
_WILD_INDEX = re.compile(r"\bindex\s*=\s*[\"']?[^\s\"')]*\*|\bindex\s+in\s*\([^)]*\*", re.I)


def _split_pipes(spl: str) -> list[str]:
    """Split on | outside quotes, refusing the syntax that hides extra commands."""
    parts, buf, quote, escaped = [], [], None, False
    for ch in spl:
        if escaped:
            buf.append(ch); escaped = False; continue
        if ch == "\\":
            buf.append(ch); escaped = True; continue
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch; buf.append(ch); continue
        if ch in "[]`":
            raise ValueError("subsearches and macros are not allowed")
        if ch == "|":
            parts.append("".join(buf)); buf = []; continue
        buf.append(ch)
    if quote:
        raise ValueError("unbalanced quotes")
    parts.append("".join(buf))
    return [p.strip() for p in parts]


def vet_spl(spl: str, max_rows: int = 200) -> str:
    """Return a safe, capped version of the search or raise ValueError."""
    spl = (spl or "").strip()
    if not spl or len(spl) > MAX_SPL_LEN:
        raise ValueError("search is empty or too long")
    if spl.startswith("|"):
        raise ValueError("generating commands are not allowed")
    if not spl.lower().startswith("search "):
        spl = "search " + spl
    parts = _split_pipes(spl)
    # Every search names its indexes; index=* makes Splunk read everything
    first = parts[0]
    if not _HAS_INDEX.search(first):
        raise ValueError("name the index to search, like index=wineventlog")
    if _WILD_INDEX.search(first):
        raise ValueError("index=* and wildcard indexes are not allowed; name the indexes")
    for part in parts[1:]:
        cmd = part.split(None, 1)[0].lower() if part else ""
        if cmd not in _ALLOWED:
            raise ValueError(f"command '{cmd or '?'}' is not allowed")
    return " | ".join(parts) + f" | head {int(max_rows)}"


def quote_value(value: str) -> str:
    """Quote a user value for use as a literal search term."""
    return '"' + re.sub(r'(["\\])', r"\\\1", str(value))[:200] + '"'
