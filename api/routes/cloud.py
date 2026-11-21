"""Cloud Inventory API: cloud instances with reachability, coverage and exposure. Admin and cyber only (it shows
the whole estate's internet-facing surface)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.cloud import inventory as inv
from api.core.csv_export import csv_paged_response
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/cloud", tags=["cloud"])
_SHOW = Query(None, pattern="^(" + "|".join(inv.FILTERS) + ")$")
_PROVIDER = Query(None, pattern="^(aws|azure|oci|gcp)$")


def _query(provider, account, region, show, q, sort, order):
    stmt = inv.base().where(*inv.conditions(provider, account, region, show, q))
    col = inv.SORTS.get(sort or "", None)
    if col is None:   # default: what matters first, then by name
        return stmt.order_by(inv.CloudAsset.internet_exposed.desc(), func.coalesce(inv.Device.kev_findings, 0).desc(),
                             inv.CloudAsset.name)
    return stmt.order_by(col.asc().nulls_last() if order == "asc" else col.desc().nulls_last(), inv.CloudAsset.name)


@router.get("/summary")
async def cloud_summary(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    return await inv.summary(db)


@router.get("")
async def cloud_list(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session),
                     provider: str | None = _PROVIDER, account: str | None = Query(None, max_length=128),
                     region: str | None = Query(None, max_length=64), show: str | None = _SHOW,
                     q: str | None = Query(None, max_length=128),
                     sort: str | None = Query(None, max_length=32), order: str | None = Query(None, pattern="^(asc|desc)$"),
                     limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0, le=1_000_000)):
    stmt = _query(provider, account, region, show, q, sort, order)
    total = (await db.execute(select(func.count()).select_from(stmt.order_by(None).subquery()))).scalar_one()
    rows = (await db.execute(inv.with_tags(stmt).limit(limit).offset(offset))).unique().all()
    return {"items": [inv.row(a, d) for a, d in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/export")
async def cloud_export(_: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session),
                       provider: str | None = _PROVIDER, account: str | None = Query(None, max_length=128),
                       region: str | None = Query(None, max_length=64), show: str | None = _SHOW,
                       q: str | None = Query(None, max_length=128),
                       sort: str | None = Query(None, max_length=32), order: str | None = Query(None, pattern="^(asc|desc)$")):
    stmt = inv.with_tags(_query(provider, account, region, show, q, sort, order))
    header = ["Provider", "Account", "Region", "Name", "Resource ID", "Public IPs", "Internet exposed", "Open to the internet",
              "Firewalls", "CTEM device", "Scanned", "EDR", "Open findings", "KEV findings", "Grade", "Owner"]

    async def fetch(offset: int, limit: int) -> list[list]:
        out = []
        for a, d in (await db.execute(stmt.limit(limit).offset(offset))).unique().all():
            r = inv.row(a, d)
            out.append([r["provider"], r["account"], r["region"], r["name"], r["resource_id"], " ".join(r["public_ips"]),
                        r["internet_exposed"], " ".join(r["internet_ports"]),
                        "; ".join(f"{f['id']} {f['name'] or ''}".strip() for f in r["firewalls"]),
                        r["hostname"], r["scanned"], r["edr"], r["open_findings"], r["kev_findings"], r["risk_grade"], r["owner"]])
        db.expunge_all()
        return out

    return await csv_paged_response("cloud-inventory", header, fetch)
