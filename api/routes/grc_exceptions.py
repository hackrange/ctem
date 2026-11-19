"""
GRC exceptions and compliance summary sub-router.
Kept separate from grc.py to stay under the 500-line limit.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin, require_permission
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/grc", tags=["grc"])


# ── Risk exceptions ───────────────────────────────────────────────────────────

@router.get("/exceptions")
async def list_exceptions(
    _: User = Depends(require_permission("grc", "read")),
    db: AsyncSession = Depends(get_session),
    include_expired: bool = False,
    limit: int = 50,
    offset: int = 0,
):
    from api.models.risk import RiskException
    from sqlalchemy import func

    q = select(RiskException).where(RiskException.is_active.is_(True))
    if not include_expired:
        now = datetime.now(timezone.utc)
        q = q.where(
            (RiskException.is_permanent.is_(True))
            | (RiskException.expires_at > now)
        )
    q = q.order_by(RiskException.approved_at.desc())

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    result = await db.execute(q.offset(offset).limit(limit))
    items = result.scalars().all()

    return {
        "exceptions": [
            {
                "id": str(e.id),
                "finding_id": str(e.finding_id) if e.finding_id else None,
                "cve_id": e.cve_id,
                "reason": e.reason,
                "approved_by": e.approved_by,
                "approved_at": e.approved_at.isoformat(),
                "expires_at": e.expires_at.isoformat() if e.expires_at else None,
                "is_permanent": e.is_permanent,
            }
            for e in items
        ],
        "total": total,
    }


@router.post("/exceptions")
async def create_exception(
    body: ExceptionRequest,
    current_user: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    from api.models.risk import RiskException

    if not body.reason or len(body.reason.strip()) < 10:
        raise HTTPException(400, detail="reason must be at least 10 characters")

    if not body.is_permanent and not body.expires_at:
        raise HTTPException(400, detail="expires_at is required unless is_permanent=true")

    # Validate finding FK if provided
    finding_uuid = None
    if body.finding_id:
        try:
            finding_uuid = uuid.UUID(body.finding_id)
        except ValueError:
            raise HTTPException(400, detail="invalid finding_id")
        from api.models.vuln import Finding
        f = await db.get(Finding, finding_uuid)
        if f is None:
            raise HTTPException(404)

    exc = RiskException(
        finding_id=finding_uuid,
        cve_id=(body.cve_id or "")[:32] or None,
        reason=body.reason.strip()[:1024],
        approved_by=current_user.username,
        approved_at=datetime.now(timezone.utc),
        expires_at=body.expires_at,
        is_permanent=body.is_permanent,
    )
    db.add(exc)
    await db.commit()
    return {"id": str(exc.id), "created": True}


@router.delete("/exceptions/{exception_id}")
async def revoke_exception(
    exception_id: str,
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    from api.models.risk import RiskException

    try:
        eid = uuid.UUID(exception_id)
    except ValueError:
        raise HTTPException(404)

    exc = await db.get(RiskException, eid)
    if exc is None:
        raise HTTPException(404)

    exc.is_active = False
    await db.commit()
    return {"revoked": True}


# ── Compliance summary ────────────────────────────────────────────────────────

@router.get("/compliance")
async def get_compliance(
    _: User = Depends(require_permission("grc", "read")),
    db: AsyncSession = Depends(get_session),
):
    """
    Aggregates evidence records from AppSetting (written by /grc/evidence)
    into a per-framework score. Unknown/missing controls count as 0.
    """
    from api.models.settings import AppSetting
    import json

    _FRAMEWORKS = [
        ("nist-csf",    "NIST CSF",    15),
        ("iso-27001",   "ISO 27001",   14),
        ("nist-800-53", "NIST 800-53", 20),
    ]

    result = await db.execute(select(AppSetting).where(AppSetting.key.like("grc_evidence_%")))
    rows = {r.key: r.value for r in result.scalars().all()}

    now = datetime.now(timezone.utc)
    frameworks = []
    for slug, label, total_controls in _FRAMEWORKS:
        passed = 0
        for key, val in rows.items():
            if not key.startswith(f"grc_evidence_{slug}_"):
                continue
            try:
                d = json.loads(val or "{}")
            except Exception:
                continue
            if d.get("status") not in ("pass", "partial"):
                continue
            if d.get("expires_at"):
                try:
                    exp = datetime.fromisoformat(d["expires_at"].replace("Z", "+00:00"))
                    if now > exp:
                        continue
                except Exception:
                    pass
            passed += 1

        score = round((passed / total_controls) * 100) if total_controls else 0
        frameworks.append({"slug": slug, "name": label, "score": score,
                           "passed": passed, "total": total_controls})

    return {"frameworks": frameworks}


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ExceptionRequest(BaseModel):
    finding_id: str | None = None
    cve_id: str | None = None
    reason: str
    expires_at: datetime | None = None
    is_permanent: bool = False
