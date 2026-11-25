"""Hunt > a finding > Suppress similar (Cyber or Admin): the finding's evidence alerts grouped into signatures (the
detection, its source, the process and the process that started it), and accepting the ones picked, so alerts with
the same signature stop raising hunt, watch, hourly-check and SIEM findings (api/core/alert_allow.py).

Each picked signature becomes one accepted-alert entry, or one per host or per file hash when narrowed that far, with
a reason and an end date (a year at most), each audited. Nothing is deleted: the alerts stay in CTEM and in the tool.
A watch finding whose every alert is now accepted leaves the watch at once; the next run would drop it anyway."""
from __future__ import annotations

import json
import re
from datetime import date
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/hunt", tags=["hunt"])
SOURCE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
HOST = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
SHA = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_SIGNATURES, MAX_ENTRIES, MAX_HASHES = 20, 100, 10


def _base(name) -> str:
    return str(name or "").replace("\\", "/").rsplit("/", 1)[-1]


def _rows(result: dict, issue: dict) -> list[dict]:
    lookups = result.get("lookups") or []
    return [r for n in issue.get("lookups") or [] if isinstance(n, int) and 0 < n <= len(lookups)
            for r in lookups[n - 1].get("rows") or [] if isinstance(r, dict) and r.get("alert")]


def signatures(result: dict, issue: dict) -> list[dict]:
    """The distinct (detection, source, process, parent) among the finding's evidence alerts, most alerts first."""
    groups: dict[tuple, dict] = {}
    for r in _rows(result, issue):
        k = (str(r["alert"])[:300], str(r.get("source") or "")[:32], _base(r.get("process"))[:260], _base(r.get("parent"))[:260])
        g = groups.setdefault(k, {"alerts": 0, "hosts": set(), "hashes": set()})
        g["alerts"] += 1
        if r.get("host"):
            g["hosts"].add(str(r["host"]))
        if r.get("sha256") and SHA.match(str(r["sha256"])):
            g["hashes"].add(str(r["sha256"]).lower())
    out = [{"detection": k[0], "source": k[1] or None, "process": k[2] or None, "parent": k[3] or None, "alerts": g["alerts"],
            "hosts": sorted(g["hosts"], key=str.lower), "hashes": sorted(g["hashes"])}
           for k, g in sorted(groups.items(), key=lambda x: -x[1]["alerts"])]
    return [{"id": i, **s} for i, s in enumerate(out[:MAX_SIGNATURES])]


async def _issue(db, source: str, index: int, me: User):
    from api.hunt.handoff import load_issue
    from api.routes.hunt import _owner_of
    if not SOURCE.match(source):
        raise HTTPException(404)
    return await load_issue(db, source, index, _owner_of, str(me.id))


@router.get("/suppress/{source}/{index}")
async def suppress_options(source: str, index: int, me: User = Depends(require_cyber_or_admin),
                           db: AsyncSession = Depends(get_session)):
    result, issue = await _issue(db, source, index, me)
    return {"title": issue.get("title"), "signatures": signatures(result, issue)}


class SuppressBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    signatures: list[Annotated[int, Field(ge=0, lt=MAX_SIGNATURES)]] = Field(min_length=1, max_length=MAX_SIGNATURES)
    hosts_only: bool = False      # only on the hosts in this finding
    pin_hash: bool = False        # only these exact files (a new version of the program has a new hash)
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=1000, pattern=r"^[^\x00-\x08\x0b-\x1f<>]+$")]
    expires_on: date


async def prune_watch(db: AsyncSession) -> int:
    """Drop watch findings whose every evidence alert is accepted now. Returns how many left."""
    from api.core.alert_allow import active, covers_row
    from api.hunt.watch import WATCH_KEY
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == WATCH_KEY))).scalar_one_or_none()
    try:
        saved = json.loads(row.value) if row and row.value else None
    except ValueError:
        return 0
    result = (saved or {}).get("result") or {}
    rules = await active(db)
    keep = [i for i in result.get("issues") or []
            if not ((rows := _rows(result, i)) and all(covers_row(rules, r) for r in rows))]
    gone = len(result.get("issues") or []) - len(keep)
    if gone:
        result["issues"] = keep
        row.value = json.dumps(saved)
    return gone


@router.post("/suppress/{source}/{index}", status_code=201)
async def suppress(source: str, index: int, body: SuppressBody, me: User = Depends(require_cyber_or_admin),
                   db: AsyncSession = Depends(get_session)):
    from api.core.alert_allow import active
    from api.models.alert_allow import AlertAllow
    from api.routes.alert_allow import _audit, _until, describe
    result, issue = await _issue(db, source, index, me)
    sigs = {s["id"]: s for s in signatures(result, issue)}
    if not sigs:
        raise HTTPException(409, detail="This finding has no alerts to suppress. It was raised from other evidence.")
    picked = [sigs[i] for i in dict.fromkeys(body.signatures) if i in sigs]
    if not picked:
        raise HTTPException(422, detail="Pick at least one signature from this finding.")
    until = _until(body.expires_on)
    wanted = []
    for s in picked:
        hosts = [h for h in s["hosts"] if HOST.match(h)] if body.hosts_only else [None]
        hashes = s["hashes"][:MAX_HASHES] if body.pin_hash else [None]
        if (body.hosts_only and not hosts) or (body.pin_hash and not hashes):
            raise HTTPException(422, detail=f"'{s['detection']}' has no {'hosts' if body.hosts_only and not hosts else 'file hashes'} to narrow to.")
        wanted += [(s, h, x) for h in hosts for x in hashes]
    if len(wanted) > MAX_ENTRIES:
        raise HTTPException(422, detail=f"That makes {len(wanted)} entries; narrow it to {MAX_ENTRIES} or fewer (fewer hosts or no hash).")
    have = {(r.title.lower(), r.source, (r.process or "").lower(), (r.parent or "").lower(), (r.hostname or "").lower(), r.sha256)
            for r in await active(db)}
    made = 0
    for s, host, sha in wanted:
        key = (s["detection"].lower(), s["source"], (s["process"] or "").lower(), (s["parent"] or "").lower(), (host or "").lower(), sha)
        if key in have:
            continue
        r = AlertAllow(title=s["detection"], source=s["source"], process=s["process"], parent=s["parent"], hostname=host,
                       sha256=sha, reason=body.reason, expires_at=until, enabled=True, created_by=me.username)
        db.add(r)
        await db.flush()
        scope = describe(r)
        await _audit(me, "alert_allow.create", r, f"Suppressed from hunt finding '{str(issue.get('title'))[:120]}': "
                     f"'{r.title}'{f' ({scope})' if scope else ''} until {body.expires_on}: {r.reason}", db)
        have.add(key)
        made += 1
    removed = await prune_watch(db)
    await db.commit()
    return {"created": made, "already": len(wanted) - made, "watch_removed": removed}
