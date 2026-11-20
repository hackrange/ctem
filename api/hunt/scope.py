"""Name exactly the indexes a search needs. Splunk pays for every index it scans."""
from __future__ import annotations

import re

from api.hunt.spl_guard import quote_value

_INDEX_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}$")


def indexes_with(schema: dict | None, fields) -> list[str]:
    """Indexes whose mapped data carries any of these fields."""
    wanted = {f.lower() for f in fields}
    out = []
    for name, idx in ((schema or {}).get("indexes") or {}).items():
        have = {f.lower() for f in (idx.get("fields") or {})}
        if idx.get("type_field"):
            have.add(idx["type_field"].lower())
        if have & wanted:
            out.append(name)
    return sorted(out)


def index_clause(names: list[str]) -> str:
    names = [n for n in names if _INDEX_NAME.match(n)]
    if not names:
        return ""
    return f"index={names[0]}" if len(names) == 1 else "(" + " OR ".join(f"index={n}" for n in names) + ")"


def scoped(schema: dict | None, fields, body: str) -> str | None:
    """'search <indexes> <body>' over just the indexes that have the fields, or None."""
    clause = index_clause(indexes_with(schema, fields))
    return f"search {clause} {body}".strip() if clause else None


def rare_types(schema: dict | None, ceiling: float = 0.01, floor: int = 200) -> dict[str, list[str]]:
    """Per index, the event types rare enough to be interesting (not the routine firehose)."""
    out = {}
    for name, idx in ((schema or {}).get("indexes") or {}).items():
        types = idx.get("types") or {}
        total = sum(types.values()) or 1
        rare = [t for t, c in types.items() if c <= max(floor, total * ceiling)]
        if rare and idx.get("type_field") and len(rare) < len(types):
            out[name] = rare
    return out


def notable_clause(schema: dict | None) -> str:
    """Rare event types across indexes, as one filter: the stuff worth an analyst's eyes."""
    parts = []
    for name, rare in rare_types(schema).items():
        field = schema["indexes"][name]["type_field"]
        vals = " OR ".join(f"{field}={quote_value(v)}" for v in rare[:15])
        if _INDEX_NAME.match(name):
            parts.append(f"(index={name} ({vals}))")
    return "(" + " OR ".join(parts) + ")" if parts else ""
