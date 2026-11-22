"""Fixes: the patches, upgrades and rollups that resolve open findings, ranked by the risk each removes.

Same viewers and the same device scope as the Vulnerability Dashboard. Every filter is allow-listed or bound."""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.device_scope import device_scope
from api.core import vuln_dashboard as vd
from api.core.db import get_session
from api.models.user import User
from api.models.vuln import Finding, Fix, Vulnerability
from api.routes.vuln_dashboard import _viewer

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/fixes", tags=["vulns"])
_KEY = r"^[A-Za-z0-9._:@/+\-]{1,160}$"
_SORTS = {"risk", "findings", "devices", "vulns", "kev", "pct"}
CACHE_SECONDS = 900


async def _ranked(db, kind: str, source: str | None, scope, viewer: str) -> list[dict]:
    """Every fix with its open counts, for one tab, source and viewer (cached 15 minutes; the list is small)."""
    import redis.asyncio as aioredis

    from api.core.config import get_settings
    ck = f"fixes:v1:{kind}:{source or '-'}:{viewer if scope is not None else 'all'}"
    r = aioredis.from_url(get_settings().redis_url)
    try:
        try:
            hit = await r.get(ck)
            dirty = await r.get(vd.DIRTY_KEY)
            if hit:
                body = json.loads(hit)
                if not dirty or body["at"] >= float(dirty):
                    return body["rows"]
        except Exception:  # noqa: BLE001 -- no Redis means no cache, not no list
            log.warning("fixes cache unavailable")
        w = vd._where(source, None, kind) + vd.scoped(scope)
        crit = func.count().filter(Vulnerability.cvss_base >= 9.0)
        high = func.count().filter(Vulnerability.cvss_base >= 7.0, Vulnerability.cvss_base < 9.0)
        rows = (await db.execute(
            select(Finding.fix_key, func.count(), crit, high, func.count().filter(Vulnerability.is_kev == True),  # noqa: E712
                   func.count().filter(Vulnerability.exploit_available == True),  # noqa: E712
                   func.count(func.distinct(Finding.vuln_id)), func.count(func.distinct(Finding.device_id)))
            .select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
            .where(Finding.status.in_(vd.OPEN), Finding.fix_key.is_not(None), *w).group_by(Finding.fix_key))).all()
        names = {}
        keys = [x[0] for x in rows]
        for i in range(0, len(keys), 1000):
            for f in (await db.execute(select(Fix.key, Fix.title, Fix.kind, Fix.source).where(Fix.key.in_(keys[i:i + 1000])))).all():
                names[f[0]] = f
        out = []
        for k, n, c, h, kv, ex, nv, nd in rows:
            meta = names.get(k)
            out.append({"key": k, "title": (meta[1] if meta else k.split(":", 1)[-1])[:300], "kind": meta[2] if meta else None,
                        "source": meta[3] if meta else k.split(":", 1)[0], "findings": n, "critical": c, "high": h,
                        "kev": kv, "exploitable": ex, "vulns": nv, "devices": nd,
                        # risk removed: known exploited first, then critical, then high, then everything else
                        "risk": kv * 1000 + c * 100 + h * 10 + n})
        try:
            await r.set(ck, json.dumps({"at": vd._now().timestamp(), "rows": out}), ex=CACHE_SECONDS)
        except Exception:  # noqa: BLE001
            log.warning("fixes not cached")
        return out
    finally:
        await r.aclose()


@router.get("")
async def list_fixes(u: User = Depends(_viewer), db: AsyncSession = Depends(get_session),
                     kind: str = Query("infra", pattern="^(infra|code|web|all)$"),
                     source: str | None = Query(None, max_length=64),
                     q: str | None = Query(None, max_length=120),
                     severity: str | None = Query(None, pattern="^(critical|high|kev|exploitable)$"),
                     sort: str = Query("risk", max_length=16),
                     limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100000)):
    if source and source not in vd.SOURCES:
        return {"ok": False, "error": "Unknown source"}
    scope = await device_scope(u, db)
    rows = await _ranked(db, kind, source, scope, str(u.id))
    fixable = sum(r["findings"] for r in rows)   # open findings with a known fix, before search and filters
    rows = [{**r, "pct": round(r["findings"] * 100.0 / fixable, 2) if fixable else 0.0} for r in rows]
    if q:
        needle = q.strip().lower()
        rows = [r for r in rows if needle in r["title"].lower() or needle in r["key"].lower()]
    if severity:
        rows = [r for r in rows if r[severity] > 0]
    rows = sorted(rows, key=lambda r: r[sort if sort in _SORTS else "risk"], reverse=True)
    covered = sum(r["findings"] for r in rows)
    return {"total": len(rows), "findings_covered": covered, "fixable_findings": fixable, "fixes": rows[offset:offset + limit],
            "scoped": scope is not None}


@router.get("/detail")
async def fix_detail(u: User = Depends(_viewer), db: AsyncSession = Depends(get_session),
                     key: str = Query(..., pattern=_KEY)):
    """One fix: what to do, and the vulnerabilities it resolves (with how many of the viewer's assets have each)."""
    scope = await device_scope(u, db)
    w = vd._where(None, None, "all") + vd.scoped(scope)
    vulns = (await db.execute(
        select(Vulnerability.id, Vulnerability.cve_id, Vulnerability.title, Vulnerability.cvss_base, Vulnerability.is_kev,
               Vulnerability.exploit_available, func.count())
        .select_from(Finding).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
        .where(Finding.fix_key == key, Finding.status.in_(vd.OPEN), *w)
        .group_by(Vulnerability.id, Vulnerability.cve_id, Vulnerability.title, Vulnerability.cvss_base,
                  Vulnerability.is_kev, Vulnerability.exploit_available)
        .order_by(Vulnerability.is_kev.desc(), Vulnerability.cvss_base.desc().nulls_last()).limit(500))).all()
    fix = (await db.execute(select(Fix).where(Fix.key == key))).scalar_one_or_none()
    if fix is None and not vulns:
        return {"ok": False, "error": "That fix isn't available to you."}   # the same for absent and not yours
    devices = (await db.execute(select(func.count(func.distinct(Finding.device_id))).where(
        Finding.fix_key == key, Finding.status.in_(vd.OPEN), *w))).scalar_one()
    return {"ok": True, "key": key, "title": fix.title if fix else key.split(":", 1)[-1], "kind": fix.kind if fix else None,
            "source": fix.source if fix else key.split(":", 1)[0], "steps": fix.steps if fix else None,
            "links": [x for x in (fix.links or []) if str(x).lower().startswith(("https://", "http://"))] if fix else [],
            "devices": devices,
            "vulns": [{"id": str(i), "cve_id": c, "title": (t or "")[:300], "cvss": cv, "kev": bool(k), "exploit": bool(e),
                       "devices": n} for i, c, t, cv, k, e, n in vulns]}
