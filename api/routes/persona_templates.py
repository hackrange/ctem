"""Settings > Integrations > Persona > Templates in use (admins): each inquiry template, its status in Persona, how
often it is used (from the checks CTEM has read), and what CTEM uses it for. Reads only: Persona's template list
(GET, allow-listed) and CTEM's own records."""
from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_admin
from api.core.db import get_session
from api.models.idv import IdvRequest
from api.models.integration import IntegrationConfig, Vendor
from api.models.user import User

log = logging.getLogger("open-ctem.persona")
router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


@router.get("/{integration_id}/persona-templates")
async def templates(integration_id: uuid.UUID, _: User = Depends(require_admin), db: AsyncSession = Depends(get_session)):
    from api.integrations.base import get_connector
    from api.integrations.persona import PersonaError
    cfg = await db.get(IntegrationConfig, str(integration_id))
    if cfg is None or cfg.vendor != Vendor.persona:
        raise HTTPException(404)
    c = cfg.config or {}
    listed, error = {}, None
    conn = get_connector("persona", c)
    try:
        async with conn.client() as client:
            async for t in conn.pages("/api/v1/inquiry-templates", client, {}, 5):
                a = t.get("attributes") or {}
                tid = str(t.get("id") or "")
                if tid.startswith("itmpl_"):
                    listed[tid] = {"name": str(a.get("name") or "")[:200], "status": str(a.get("status") or "")[:20]}
    except PersonaError as e:
        log.warning("Persona template list failed: %s", e)
        error = "Persona didn't list the templates; showing what CTEM has seen"
    rows = (await db.execute(select(IdvRequest.template_id, IdvRequest.template, IdvRequest.state, IdvRequest.created_at, IdvRequest.facts)
                             .where(IdvRequest.integration_id == cfg.id))).all()
    since = datetime.now(timezone.utc) - timedelta(days=30)
    use = defaultdict(lambda: {"uses": 0, "last_30_days": 0, "passed": 0, "selfie_only": 0, "last_used": None, "name": ""})
    for tid, name, state, at, facts in rows:
        if not tid:
            continue
        u = use[tid]
        u["uses"] += 1
        u["passed"] += state == "approved"
        u["name"] = u["name"] or (name or "")
        kinds = {v.get("kind", "") for v in (facts or {}).get("verifications") or []}
        u["selfie_only"] += "selfie" in kinds and not any(k.startswith("government-id") for k in kinds)
        if at is not None:
            at = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
            u["last_30_days"] += at > since
            u["last_used"] = max(u["last_used"], at) if u["last_used"] else at
    roles = {}
    for key, label in (("template_id", "Government ID + selfie links"), ("selfie_template_id", "Selfie-only links")):
        if c.get(key):
            roles.setdefault(c[key], []).append(label)
    for t in str(c.get("badge_templates") or "").split(","):
        if t.strip():
            roles.setdefault(t.strip(), []).append("Earns the IDV badge")
    out = []
    for tid in sorted(set(listed) | set(use)):
        u = use.get(tid) or {"uses": 0, "last_30_days": 0, "passed": 0, "selfie_only": 0, "last_used": None, "name": ""}
        out.append({"id": tid, "name": (listed.get(tid) or {}).get("name") or u["name"], "status": (listed.get(tid) or {}).get("status") or "unknown",
                    "uses": u["uses"], "last_30_days": u["last_30_days"], "passed": u["passed"], "selfie_only": u["selfie_only"],
                    "last_used": u["last_used"].isoformat() if u["last_used"] else None, "ctem_uses": roles.get(tid, [])})
    out.sort(key=lambda r: (-r["last_30_days"], -r["uses"], r["name"].lower()))
    return {"templates": out, "error": error}
