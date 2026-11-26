"""Control checks and evidence for FairTPRM's continuous monitors (and any other GRC tool)."""
from __future__ import annotations

import logging
import re
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.grc import evidence
from api.grc.checks import Check, evaluate
from api.models.user import User

router = APIRouter(prefix="/api/v1/grc", tags=["grc-checks"])
log = logging.getLogger("open-ctem.grc")
_RESERVED = {"format", "max_rows"}
_REPORT_MAX = 50000
MAX_ITEMS = 50000  # checks cap their detail rows here


async def _check(db: AsyncSession, check_type: str) -> Check:
    # Only names in the registry or saved custom checks; the path segment is never used for anything else
    from api.rules.custom import get_check
    check = await get_check(db, check_type[:80])
    if check is None:
        raise HTTPException(404, detail="Unknown check")
    return check


def _thresholds(request: Request) -> dict:
    pairs = [(k, v) for k, v in request.query_params.multi_items() if k not in _RESERVED]
    if len(pairs) != len({k for k, _ in pairs}):
        raise HTTPException(400, detail="Repeated parameter")
    return dict(pairs)


@router.get("/checks")
async def list_checks(_: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    from api.rules.custom import all_checks
    return {"checks": [c.catalog() for c in (await all_checks(db)).values()]}


@router.get("/evidence-key")
async def evidence_key(_: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    """Public half of the key that signs evidence reports; FairTPRM pins the kid."""
    return evidence.public_info(await evidence.signing_key(db))


@router.get("/checks/{check_type}")
async def run_check(check_type: str, request: Request, _: User = Depends(require_permission("grc", "read")),
                    db: AsyncSession = Depends(get_session)):
    check = await _check(db, check_type)
    try:
        return await evidence.run_check(db, check, _thresholds(request))
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from None


@router.get("/checks/{check_type}/report")
async def check_report(check_type: str, request: Request, format: str = "csv", max_rows: int = _REPORT_MAX,
                       user: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    """The detail behind a check, signed. Can list hostnames and account names, so every download is audited."""
    from api.core.config import get_settings
    from api.models.settings import AuditLog

    check = await _check(db, check_type)
    if format not in ("csv", "json"):
        raise HTTPException(400, detail="format must be csv or json")
    if not 1 <= max_rows <= _REPORT_MAX:
        raise HTTPException(400, detail=f"max_rows must be between 1 and {_REPORT_MAX}")
    try:
        body, outcome = await evaluate(db, check, _thresholds(request), detail=True)
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from None
    await evidence.record(db, body)
    instance = get_settings().public_url or "open-ctem"
    payload, media = evidence.render(body, outcome, format, instance, max_rows)
    headers = evidence.signature_headers(await evidence.signing_key(db), payload)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    headers.update({"Content-Disposition": f'attachment; filename="{check.check_type}-{stamp}.{format}"',
                    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    db.add(AuditLog(actor_user_id=str(user.id), actor_username=user.username, action="grc_evidence_report",
                    resource_type="grc_check", resource_id=check.check_type[:36],
                    detail=f"{format}, {min(len(outcome.rows), max_rows)} rows, result {body['result']}"))
    await db.commit()
    return Response(content=payload, media_type=media, headers=headers)


@router.get("/checks/{check_type}/history")
async def check_history(check_type: str, request: Request, _: User = Depends(require_permission("grc", "read")),
                        db: AsyncSession = Depends(get_session)):
    check = await _check(db, check_type)
    q = request.query_params
    try:
        end = date.fromisoformat(q["to"]) if q.get("to") else datetime.now(timezone.utc).date()
        start = date.fromisoformat(q["from"]) if q.get("from") else end - timedelta(days=89)
        return await evidence.history(db, check.check_type, start, end)
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc) if "window" in str(exc) or "on or after" in str(exc)
                            else "from and to must be YYYY-MM-DD") from None


_ITEM_SORT = re.compile(r"^[a-z_]{1,40}$")


def _sort_key(v):
    # None last; numbers before text; text case-insensitive
    if v is None or v == "":
        return (2, 0, "")
    if isinstance(v, bool | int | float):
        return (0, float(v), "")
    return (1, 0, str(v).lower())


ITEMS_CACHE_SECONDS = 120


async def _items(db: AsyncSession, check: Check) -> tuple[dict, list[dict], list[str]]:
    """The check with its detail rows. Paging a 50,000-row list re-runs nothing for two minutes; a curated-rule
    change clears it (evidence.refresh drops grc:check:<type>:*)."""
    import json
    key = f"grc:check:{check.check_type}:items"
    try:
        r = await evidence._redis()
        hit = await r.get(key)
        await r.aclose()
        if hit:
            c = json.loads(hit)
            return c["body"], c["rows"], c["columns"]
    except Exception:  # noqa: BLE001 -- the cache is optional
        log.debug("check items cache unavailable")
    body, outcome = await evaluate(db, check, {}, detail=True)
    keep = {k: body[k] for k in ("result", "summary", "measured_at", "curated_rules", "details") if k in body}
    try:
        r = await evidence._redis()
        await r.set(key, json.dumps({"body": keep, "rows": outcome.rows, "columns": outcome.columns}, default=str),
                    ex=ITEMS_CACHE_SECONDS)
        await r.aclose()
    except Exception:  # noqa: BLE001
        log.debug("check items cache unavailable")
    return keep, outcome.rows, outcome.columns


@router.get("/checks/{check_type}/items")
async def check_items(check_type: str, q: str | None = Query(None, max_length=200),
                      asset: str | None = Query(None, pattern="^[a-z]{2,20}$", description="Only rows on this kind of asset"),
                      sort: str | None = Query(None, max_length=40), order: str = Query("asc", pattern="^(asc|desc)$"),
                      limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=_REPORT_MAX),
                      user: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    """What a check found to fix (for EDR: the devices without healthy EDR), paged for the GRC page.
    Same data and permission as the report download; the first page of each view is audited."""
    from api.models.settings import AuditLog

    check = await _check(db, check_type)
    body, all_rows, columns = await _items(db, check)
    rows = all_rows
    if q and q.strip():
        needle = q.strip().lower()
        rows = [r for r in rows if any(needle in str(r.get(c) or "").lower() for c in columns)]
    if asset:   # the SLA check's breakdown: one kind of asset
        rows = [r for r in rows if r.get("asset_kind") == asset]
    if sort and _ITEM_SORT.match(sort) and sort in columns:   # only the check's own columns
        rows = sorted(rows, key=lambda r: _sort_key(r.get(sort)), reverse=order == "desc")
    if offset == 0:
        db.add(AuditLog(actor_user_id=str(user.id), actor_username=user.username, action="grc_check_items",
                        resource_type="grc_check", resource_id=check.check_type[:36],
                        detail=f"{len(all_rows)} items, result {body['result']}"))
        await db.commit()
    page = rows[offset:offset + limit]
    return {"check": check.catalog(), "result": body["result"], "summary": body["summary"],
            "measured_at": body["measured_at"], "curated_rules": body.get("curated_rules", []), "details": body.get("details") or {},
            "columns": columns, "items": [{"device_id": r.get("device_id"), **{c: r.get(c) for c in columns}} for r in page],
            "total": len(rows), "all_items": len(all_rows), "truncated": len(all_rows) >= MAX_ITEMS}
