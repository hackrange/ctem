"""
Attack paths: CVE chain analysis across devices.

Identifies exploitable pivot paths: CVE A on host X that, once exploited,
gives network access to host Y which has CVE B leading to domain admin.
Built from open findings + reachability data from NodeZero / Horizon3.
"""
from __future__ import annotations

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
    limit: int = Query(25, le=100),
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

    chains = _build_chains(by_device, findings)
    chains.sort(key=lambda c: c["chain_score"], reverse=True)

    return {
        "chains": chains[:limit],
        "total": len(chains),
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


def _build_chains(by_device: dict, all_findings: list) -> list[dict]:
    """
    Naive chain detector: devices sharing the same /24 subnet that both have
    reachable high-severity findings form a 2-hop chain.
    Real graph traversal lives in the NodeZero integration.
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
                subnet_map.setdefault(subnet, [])
                if str(f.device_id) not in subnet_map[subnet]:
                    subnet_map[subnet].append(str(f.device_id))

    chains = []
    seen = set()
    for subnet, dev_ids in subnet_map.items():
        if len(dev_ids) < 2:
            continue
        for i, src_id in enumerate(dev_ids):
            for dst_id in dev_ids[i + 1:]:
                pair = tuple(sorted([src_id, dst_id]))
                if pair in seen:
                    continue
                seen.add(pair)

                src_findings = by_device.get(src_id, [])
                dst_findings = by_device.get(dst_id, [])
                if not src_findings or not dst_findings:
                    continue

                src_max = max((f.vuln.cvss_base or 0) for f in src_findings if f.vuln)
                dst_max = max((f.vuln.cvss_base or 0) for f in dst_findings if f.vuln)
                chain_score = round((src_max + dst_max) / 2, 1)

                src_dev = src_findings[0].device
                dst_dev = dst_findings[0].device

                chains.append({
                    "chain_id": f"{src_id[:8]}-{dst_id[:8]}",
                    "chain_score": chain_score,
                    "hops": 2,
                    "source": {
                        "device_id": src_id,
                        "hostname": src_dev.hostname if src_dev else None,
                        "ip": device_ips.get(src_id),
                        "max_cvss": src_max,
                        "finding_count": len(src_findings),
                        "top": _top(src_findings),
                    },
                    "destination": {
                        "device_id": dst_id,
                        "hostname": dst_dev.hostname if dst_dev else None,
                        "ip": device_ips.get(dst_id),
                        "max_cvss": dst_max,
                        "finding_count": len(dst_findings),
                        "top": _top(dst_findings),
                    },
                    "subnet": subnet + ".0/24",
                })
    return chains
