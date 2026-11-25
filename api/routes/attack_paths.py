"""
Attack paths: CVE chain analysis across devices.

Identifies exploitable pivot paths: CVE A on host X that, once exploited,
gives network access to host Y which has CVE B leading to domain admin.
Built from open findings + reachability data from NodeZero / Horizon3.
"""
from __future__ import annotations

import heapq

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from api.auth.middleware import get_current_user
from api.auth.rbac import require_cyber_or_admin
from api.core.db import get_session
from api.core.device_scope_exempt import in_scope_findings
from api.models.device import Device
from api.models.user import User
from api.models.vuln import Finding, FindingStatus, Vulnerability

router = APIRouter(prefix="/api/v1/attack-paths", tags=["attack-paths"])


@router.get("/chains")
async def list_attack_chains(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    min_hops: int = Query(2, ge=1, le=10),
    kev_only: bool = False,
    limit: int = Query(25, ge=1, le=100),
):
    """
    Return probable exploit chains: devices with reachable KEV/high-CVSS findings
    that share network segments, ordered by chain severity.
    """
    result = await db.execute(
        select(Finding)
        .options(
            selectinload(Finding.vuln),
            selectinload(Finding.device),
        )
        .where(
            Finding.status.in_([FindingStatus.open, FindingStatus.in_progress]),
            Finding.is_reachable == True,  # noqa: E712
            in_scope_findings(),
        )
    )
    findings = result.scalars().all()

    if kev_only:
        findings = [f for f in findings if f.vuln and f.vuln.is_kev]

    # Group by device, then find devices that share a network segment
    by_device: dict[str, list] = {}
    for f in findings:
        if f.device_id:
            by_device.setdefault(str(f.device_id), []).append(f)

    chains, total = _build_chains(by_device, findings, limit)
    return {
        "chains": chains,
        "total": total,
        "reachable_devices": len(by_device),
    }


@router.get("/pivot-points")
async def list_pivot_points(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
    limit: int = Query(20, le=100),
):
    """
    Devices that appear in the most attack chains -- highest lateral movement risk.
    Fixing these cuts the most paths simultaneously.
    """
    result = await db.execute(
        select(Device)
        .where(Device.is_internet_exposed == True)  # noqa: E712
        .order_by(Device.risk_score.desc().nullslast())
        .limit(limit)
    )
    devices = result.scalars().all()

    # Enrich with open reachable finding count
    pivot_data = []
    for d in devices:
        f_result = await db.execute(
            select(Finding)
            .options(selectinload(Finding.vuln))
            .where(
                Finding.device_id == d.id,
                Finding.status.in_([FindingStatus.open, FindingStatus.in_progress]),
                Finding.is_reachable == True,  # noqa: E712
                in_scope_findings(),
            )
        )
        reachable_findings = f_result.scalars().all()
        kev_count = sum(1 for f in reachable_findings if f.vuln and f.vuln.is_kev)

        pivot_data.append({
            "device_id": str(d.id),
            "hostname": d.hostname,
            "ip_address": d.ip,
            "device_type": d.device_type.value if d.device_type else None,
            "risk_score": d.risk_score,
            "risk_grade": d.risk_grade,
            "reachable_findings": len(reachable_findings),
            "kev_findings": kev_count,
            "is_internet_exposed": d.is_internet_exposed,
            "top": _top(reachable_findings),
            "pivot_risk": "critical" if kev_count >= 2 else "high" if kev_count == 1 else "medium",
        })

    pivot_data.sort(key=lambda p: (p["kev_findings"], p["risk_score"] or 0), reverse=True)
    return {"pivot_points": pivot_data, "total": len(pivot_data)}


@router.get("/summary")
async def attack_path_summary(
    _: User = Depends(require_cyber_or_admin),
    db: AsyncSession = Depends(get_session),
):
    """Quick counts for the attack paths dashboard panel."""
    from sqlalchemy import func

    total_reachable = (await db.execute(
        select(func.count(Finding.id))
        .where(Finding.is_reachable == True, Finding.status.in_([FindingStatus.open, FindingStatus.in_progress]),  # noqa: E712
               in_scope_findings())
    )).scalar_one()

    kev_reachable = (await db.execute(
        select(func.count(Finding.id))
        .join(Finding.vuln)
        .where(
            Finding.is_reachable == True,  # noqa: E712
            Vulnerability.is_kev == True,  # noqa: E712
            in_scope_findings(),
            Finding.status.in_([FindingStatus.open, FindingStatus.in_progress]),
        )
    )).scalar_one()

    return {
        "total_reachable_findings": total_reachable,
        "kev_reachable": kev_reachable,
    }


# ── Pure chain builder (no DB, testable) ──────────────────────────────────────

TOP = 5


def _top(findings: list) -> list[dict]:
    """A host's worst reachable findings (KEV first, then CVSS), for the expanded chain or pivot point."""
    worst = sorted(findings, key=lambda f: (bool(f.vuln and f.vuln.is_kev), (f.vuln.cvss_base or 0) if f.vuln else 0), reverse=True)
    return [{"id": str(f.id), "title": (f.vuln.title if f.vuln else None) or getattr(f, "title", None) or "",
             "cve": f.vuln.cve_id if f.vuln else None, "cvss": f.vuln.cvss_base if f.vuln else None,
             "kev": bool(f.vuln and f.vuln.is_kev)} for f in worst[:TOP]]


BIG_SUBNET = 64   # past this many hosts in one /24, only its strongest hosts can make the top chains


def _build_chains(by_device: dict, all_findings: list, limit: int | None = None) -> tuple[list[dict], int]:
    """
    Naive chain detector: devices sharing the same /24 subnet that both have
    reachable high-severity findings form a 2-hop chain.
    Real graph traversal lives in the NodeZero integration.
    Returns the `limit` strongest chains (all when None), strongest first, and how many chains there are.
    Each host is summarized once; pairs are scored as plain tuples and only the chains returned are built.
    """
    # Build subnet -> device map
    subnet_map: dict[str, list[str]] = {}
    device_ips: dict[str, str | None] = {}
    for f in all_findings:
        if f.device and f.device_id:
            ip = f.device.ip
            device_ips[str(f.device_id)] = ip
            if ip:
                subnet = ".".join(ip.split(".")[:3])
                subnet_map.setdefault(subnet, {})[str(f.device_id)] = None

    side: dict[str, dict] = {}
    total = 0

    def summary(dev_id: str) -> dict:
        if dev_id not in side:
            fs = by_device[dev_id]
            dev = fs[0].device
            side[dev_id] = {"device_id": dev_id, "hostname": dev.hostname if dev else None,
                            "ip": device_ips.get(dev_id),
                            "max_cvss": max(((f.vuln.cvss_base or 0) for f in fs if f.vuln), default=0),
                            "finding_count": len(fs), "_fs": fs}
        return side[dev_id]

    def pairs():
        nonlocal total
        for subnet, ids in subnet_map.items():
            dev_ids = [d for d in ids if by_device.get(d)]
            total += len(dev_ids) * (len(dev_ids) - 1) // 2
            if limit is not None and len(dev_ids) > BIG_SUBNET:   # a pair with a weaker host can't outrank these
                ranked = sorted(dev_ids, key=lambda d: summary(d)["max_cvss"], reverse=True)
                keep = set(ranked[:limit + 1])
                dev_ids = [d for d in dev_ids if d in keep]
            for i, src_id in enumerate(dev_ids):
                a = summary(src_id)["max_cvss"]
                for dst_id in dev_ids[i + 1:]:
                    yield round((a + summary(dst_id)["max_cvss"]) / 2, 1), src_id, dst_id, subnet

    scored = list(pairs()) if limit is None else heapq.nlargest(limit, pairs(), key=lambda p: p[0])
    if limit is None:
        scored.sort(key=lambda p: p[0], reverse=True)

    def host(dev_id: str) -> dict:
        h = summary(dev_id)
        if "top" not in h:
            h["top"] = _top(h.pop("_fs"))
        return {k: v for k, v in h.items() if k != "_fs"}

    return [{"chain_id": f"{src_id[:8]}-{dst_id[:8]}", "chain_score": score, "hops": 2,
             "source": host(src_id), "destination": host(dst_id), "subnet": subnet + ".0/24"}
            for score, src_id, dst_id, subnet in scored], total
