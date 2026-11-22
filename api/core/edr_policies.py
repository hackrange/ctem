"""EDR policies from the shipper (prevention settings, firewall rulesets, device control) and what they mean.

Stored once per policy (api/models/edr_policy.py); hosts point at theirs. The views here turn a policy into what
the asset page shows (the Firewall and USB tabs) and into the protections the scoring credits."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

KINDS = ("prevention", "firewall", "device_control")


async def upsert(db: AsyncSession, vendor: str, policies: list[dict]) -> int:
    from api.models.edr_policy import EdrPolicy
    now, n = datetime.now(timezone.utc), 0
    for p in policies:
        if p.get("kind") not in KINDS or not p.get("id"):
            continue
        row = (await db.execute(select(EdrPolicy).where(EdrPolicy.vendor == vendor, EdrPolicy.policy_id == p["id"],
                                                        EdrPolicy.kind == p["kind"]))).scalar_one_or_none()
        if row is None:
            row = EdrPolicy(vendor=vendor, policy_id=p["id"], kind=p["kind"])
            db.add(row)
        row.name, row.enabled, row.platform, row.reported_at = p.get("name"), bool(p.get("enabled")), p.get("platform"), now
        row.body = {k: p.get(k) for k in ("settings", "enforce", "test_mode", "default_inbound", "default_outbound", "rules",
                                          "enforcement", "classes") if p.get(k) is not None}
        n += 1
    return n


async def of_device(db: AsyncSession, device, kind: str):
    from api.models.edr_policy import EdrPolicy
    pid = {"prevention": device.edr_prevention_policy, "firewall": device.edr_firewall_policy,
           "device_control": device.edr_usb_policy}[kind]
    if not pid or not device.edr_vendor:
        return None
    return (await db.execute(select(EdrPolicy).where(EdrPolicy.vendor == device.edr_vendor, EdrPolicy.policy_id == pid,
                                                     EdrPolicy.kind == kind))).scalar_one_or_none()
