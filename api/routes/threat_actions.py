"""Update CrowdStrike alerts from Cyber Threats: close, reopen, put in progress, classify and comment (cyber and admin
only). The rules and the two ways an update reaches Falcon are in api/core/cs_alert_actions.py."""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/threat", tags=["threat"])
AlertKey = Annotated[str, StringConstraints(pattern=r"^threat_alert_[A-Za-z0-9:_.-]{1,200}$")]


class UpdateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[AlertKey] = Field(min_length=1, max_length=100)
    status: Literal["new", "in_progress", "reopened", "closed"] | None = None
    classification: Literal["true_positive", "false_positive", "benign"] | None = None
    comment: Annotated[str, StringConstraints(max_length=1000)] | None = None


@router.post("/alerts/update")
async def update_alerts(body: UpdateBody, request: Request, me: User = Depends(require_cyber_or_admin),
                        db: AsyncSession = Depends(get_session)):
    """Change alerts in CrowdStrike. Direct integrations answer at once; a shipper sends it on its next check-in."""
    from api.core import cs_alert_actions as act
    from api.core.security import _client_ip
    from api.models.settings import AppSetting, AuditLog
    from sqlalchemy import select
    import json
    ids = list(dict.fromkeys(body.ids))
    rows = dict((await db.execute(select(AppSetting.key, AppSetting.value).where(AppSetting.key.in_(ids)))).all())
    if len(rows) != len(ids):
        raise HTTPException(404, detail="Alert not found")
    for v in rows.values():   # only CrowdStrike's own alerts ever go to CrowdStrike
        try:
            src = (json.loads(v) or {}).get("source") if v else None
        except (ValueError, AttributeError):
            src = None
        if src != "crowdstrike":
            raise HTTPException(400, detail="Only CrowdStrike alerts can be updated from CTEM.")
    params = {"status": body.status, "classification": body.classification, "comment": body.comment}
    try:
        params["comment"] = act.csx.clean_comment(body.comment)
        rows = await act.request(db, ids, {k: v for k, v in params.items() if v is not None}, me)
    except ValueError as e:   # refused before anything was recorded
        raise HTTPException(409 if isinstance(e, act.Unavailable) else 400, detail=str(e)) from None
    what = act.csx.describe(body.status, body.classification) or "comment"
    db.add(AuditLog(actor_user_id=str(me.id), actor_username=me.username, action="threat.alert_update",
                    resource_type="alert", resource_id=ids[0][:255],
                    detail=f"CrowdStrike alert update ({what}) on {len(ids)} alert(s) via {rows[0].via}"[:500],
                    ip_address=_client_ip(request)))
    await db.commit()
    return {"via": rows[0].via, "updates": [{"id": str(a.id), "alert": a.alert_key, "state": a.state, "error": a.error}
                                            for a in rows]}


class ExplainBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: Annotated[str, StringConstraints(pattern=r"^threat_alert_[^#\s]{1,280}(#\d{1,4})?$")]
    fresh: bool = False


@router.post("/alerts/explain")
async def explain_alert(body: ExplainBody, _: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    """A light AI read of the alert and its story (api/core/threat_explain.py): names and MITRE data only."""
    from api.core import threat_explain
    from api.routes.threat import story_of
    got = await story_of(db, body.id)
    if got is None:
        raise HTTPException(404, detail="Alert not found")
    return await threat_explain.explain(db, *got, fresh=body.fresh)


@router.get("/alerts/pdf", include_in_schema=False)
async def alert_pdf(me: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session),
                    id: str = Query(..., min_length=14, max_length=300, pattern=r"^threat_alert_[^#\s]+(#\d{1,4})?$")):
    """The alert as a printable PDF (api/core/alert_pdf.py): everything on its page, inside the margins."""
    import asyncio
    from datetime import datetime, timezone

    from fastapi.responses import Response

    from api.core.alert_pdf import build
    from api.main import _get_branding
    from api.routes.threat import get_threat_alert
    a = await get_threat_alert(id=id, _=me, db=db)
    brand = await _get_branding(db)
    meta = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "prepared_by": me.username,
            "app_title": brand.get("title", "open-ctem"), "org_name": brand.get("org_name"), "accent_color": brand.get("accent_color", "#f5a623"),
            "logo_url": brand.get("logo_url"), "light_logo_url": brand.get("login_logo_url")}
    pdf = await asyncio.to_thread(build, a, meta)   # CPU work off the event loop
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="alert-report.pdf"', "Cache-Control": "no-store"})
