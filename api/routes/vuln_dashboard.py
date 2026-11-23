"""Vulnerability dashboard API: fleet-wide posture and trends, for the roles that see every device."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.middleware import get_current_user
from api.core import vuln_dashboard as vd
from api.core.db import get_session
from api.models.device import DeviceType
from api.models.user import User

router = APIRouter(prefix="/api/v1/vuln-dashboard", tags=["vulns"])
# The Vulnerabilities page's roles. Anyone who sees only some assets (IT users, scoped read-only) gets numbers for
# those assets alone (device_scope below), never the fleet's
_ROLES = {"admin", "cyber", "it_user", "read_only"}


def _viewer(u: User = Depends(get_current_user)) -> User:
    if not _ROLES.intersection(u.role_names):
        raise HTTPException(404)
    return u


@router.get("")
async def dashboard(u: User = Depends(_viewer), db: AsyncSession = Depends(get_session),
                    range: str = Query("90d", pattern="^(30d|90d|180d|365d|all)$"),  # noqa: A002
                    source: str | None = Query(None, max_length=64),
                    device_type: str | None = Query(None, max_length=32),
                    kind: str = Query("infra", pattern="^(infra|code|web|cloud)$"),
                    org: str | None = Query(None, max_length=200),
                    app: str | None = Query(None, max_length=128),
                    repo: str | None = Query(None, max_length=253)):
    if source and source not in vd.SOURCES:
        raise HTTPException(422, detail="unknown source")
    if device_type and device_type not in DeviceType.__members__:
        raise HTTPException(422, detail="unknown device type")
    if kind != "infra":
        device_type = None   # Code is all repositories, Web apps all sites, Cloud all resources; a host type left in a link matches nothing
    from api.auth.device_scope import device_scope
    scope = await device_scope(u, db)   # None for fleet-wide roles; otherwise only the devices this person may see
    # Code picks must be names this person may see; missing and out-of-scope get the same 422
    code, code_opts = None, None
    if kind == "code":
        code_opts = await vd.code_filters(db, scope)
        app_tags = next((a["tags"] for a in code_opts["apps"] if a["value"] == app), None) if app else None
        if (org and org not in code_opts["orgs"]) or (repo and repo not in {r["name"] for r in code_opts["repos"]}) \
                or (app and app_tags is None):
            raise HTTPException(422, detail="unknown organization, application or repository")
        code = {k: v for k, v in (("org", org), ("repo", repo), ("app_tags", app_tags)) if v} or None
    kw = {"code": code} if code else {}
    out = await vd.cached(db, range, source or None, device_type or None, scope=scope, viewer=str(u.id), kind=kind, **kw)
    # Only sources this install uses: a configured integration, or open findings left from one
    used = set(await vd.configured_sources(db)) | {r["source"] for r in out.get("by_source") or []} | ({source} if source else set())
    from api.core.finding_domain import sources_by_domain
    srcs = [s for s in vd.SOURCES if s in used]
    return {**out, "scoped": scope is not None, "kind": kind,
            "filters": {"sources": srcs, "by_type": sources_by_domain(srcs), "device_types": list(DeviceType.__members__),
                        **({"code": {"orgs": code_opts["orgs"], "repos": code_opts["repos"],
                                     "apps": [a["value"] for a in code_opts["apps"]],
                                     "app_tags": {a["value"]: a["tags"][:10] for a in code_opts["apps"]}}} if code_opts else {})},
            "code_filter": {"org": org, "app": app, "repo": repo} if code else None}


@router.get("/code-filters")
async def code_filters(u: User = Depends(_viewer), db: AsyncSession = Depends(get_session)):
    """The Code tab's organization, application and repository lists, limited to what this person may see."""
    from api.auth.device_scope import device_scope
    opts = await vd.code_filters(db, await device_scope(u, db))
    return {"orgs": opts["orgs"], "repos": opts["repos"], "apps": [a["value"] for a in opts["apps"]],
            "app_tags": {a["value"]: a["tags"][:10] for a in opts["apps"]}}
