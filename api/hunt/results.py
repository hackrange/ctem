"""Turn raw lookup output into tidy tables and a token-budgeted evidence brief."""
from __future__ import annotations

import json
from datetime import datetime, timezone

MAX_COLS = 15
UI_ROWS = 100
_DROP = {"_bkt", "_cd", "_indextime", "_serial", "_si", "_sourcetype", "_eventtype_color",
         "punct", "linecount", "splunk_server", "splunk_server_group", "timestartpos",
         "timeendpos", "eventtype", "tag", "_raw"}
_EPOCH_COLS = {"first_seen", "last_seen", "firsttime", "lasttime", "earliest", "latest"}


def _when(v) -> str:
    """Splunk hands back ISO strings or epoch seconds; show both the same way."""
    try:
        return datetime.fromtimestamp(float(v), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        s = str(v)
        return s[:19].replace("T", " ") if len(s) >= 19 and s[4] == "-" else s


def _flat(v) -> str:
    if isinstance(v, list):
        return ", ".join(str(x) for x in v[:10])
    if isinstance(v, dict):
        return json.dumps(v)[:300]
    return str(v)[:300] if v is not None else ""


def splunk_table(rows: list[dict]) -> tuple[list[str], list[dict]]:
    out = []
    for r in rows:
        row = {}
        raw = r.get("_raw")
        # Raw events with few extracted fields: lift the JSON body's own fields
        if raw and len([k for k in r if not k.startswith("_")]) < 4:
            try:
                body = json.loads(raw)
                if isinstance(body, dict):
                    row.update({k: v for k, v in body.items() if not isinstance(v, (dict, list))})
            except ValueError:
                row["event"] = raw[:300]
        for k, v in r.items():
            if k in _DROP or (k.startswith("_") and k != "_time") or k.startswith("date_"):
                continue
            row[k] = v
        if "_time" in row:
            row["time"] = _when(row.pop("_time"))
        for k in list(row):
            row[k] = _when(row[k]) if k.lower() in _EPOCH_COLS else _flat(row[k])
        out.append(row)
    cols: list[str] = []
    for row in out:
        for k in row:
            if k not in cols:
                cols.append(k)
    cols.sort(key=lambda c: (c != "time", c not in ("host", "ComputerName", "hostname")))
    cols = cols[:MAX_COLS]
    return cols, [{c: row.get(c, "") for c in cols} for row in out]


def ctem_table(rows: list[dict]) -> tuple[list[str], list[dict]]:
    cols = list(rows[0].keys())[:MAX_COLS] if rows else []
    return cols, [{c: _flat(r.get(c)) for c in cols} for r in rows]


def for_ui(results: list[dict]) -> list[dict]:
    return [{**r, "rows": r["rows"][:UI_ROWS]} for r in results]


def evidence_brief(results: list[dict], budget: int = 28000) -> str:
    """Numbered evidence for the AI, trimmed evenly so no single lookup hogs the tokens."""
    if not results:
        return "(no lookups ran)"
    per = max(800, budget // len(results))
    parts = []
    for n, r in enumerate(results, 1):
        where = r.get("spl") or f"open-ctem {r.get('table')} {json.dumps(r.get('filters') or {})}"
        head = f"[{n}] {r['source_label']}: {r['title']} ({r['count']} rows)\n    {where[:400]}"
        if r.get("error"):
            parts.append(head + f"\n    failed: {r['error']}")
            continue
        body, used = [], 0
        for row in r["rows"][:40]:
            line = "    " + json.dumps({k: v for k, v in row.items() if v not in ("", None)})[:350]
            if used + len(line) > per:
                body.append(f"    ... {r['count'] - len(body)} more rows")
                break
            body.append(line)
            used += len(line)
        parts.append(head + ("\n" + "\n".join(body) if body else "\n    (no rows)"))
    return "\n".join(parts)
