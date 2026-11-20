"""Control checks and evidence for FairTPRM's continuous monitors (and any other GRC tool)."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.grc import evidence
from api.grc.checks import REGISTRY, Check, evaluate
from api.models.user import User

router = APIRouter(prefix="/api/v1/grc", tags=["grc-checks"])
_RESERVED = {"format", "max_rows"}
_REPORT_MAX = 50000


def _check(check_type: str) -> Check:
    # Only names in the registry; the path segment is never used for anything else
    check = REGISTRY.get(check_type)
    if check is None:
        raise HTTPException(404, detail="Unknown check")
    return check


def _thresholds(request: Request) -> dict:
    pairs = [(k, v) for k, v in request.query_params.multi_items() if k not in _RESERVED]
    if len(pairs) != len({k for k, _ in pairs}):
        raise HTTPException(400, detail="Repeated parameter")
    return dict(pairs)


@router.get("/checks")
async def list_checks(_: User = Depends(require_permission("grc", "read"))):
    return {"checks": [c.catalog() for c in REGISTRY.values()]}


@router.get("/evidence-key")
async def evidence_key(_: User = Depends(require_permission("grc", "read")), db: AsyncSession = Depends(get_session)):
    """Public half of the key that signs evidence reports; FairTPRM pins the kid."""
    return evidence.public_info(await evidence.signing_key(db))


@router.get("/checks/{check_type}")
async def run_check(check_type: str, request: Request, _: User = Depends(require_permission("grc", "read")),
                    db: AsyncSession = Depends(get_session)):
    check = _check(check_type)
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

    check = _check(check_type)
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
    check = _check(check_type)
    q = request.query_params
    try:
        end = date.fromisoformat(q["to"]) if q.get("to") else datetime.now(timezone.utc).date()
        start = date.fromisoformat(q["from"]) if q.get("from") else end - timedelta(days=89)
        return await evidence.history(db, check.check_type, start, end)
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc) if "window" in str(exc) or "on or after" in str(exc)
                            else "from and to must be YYYY-MM-DD") from None
