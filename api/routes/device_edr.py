"""An asset's Firewall and USB tabs: the effective host firewall ruleset and device control (USB) policy, as the
EDR reported them. Admins and cyber only (a ruleset maps which paths are open); 404 for anyone else and for assets
they can't see, alike."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])
_ACTION = {"ALLOW": "Allow", "DENY": "Block", "BLOCK": "Block"}
_DIR = {"IN": "Inbound", "OUT": "Outbound", "BOTH": "Both"}
USB_ACTION = {"FULL_ACCESS": "Allowed", "FULL_BLOCK": "Blocked", "BLOCK_ALL": "Blocked", "WHITELIST": "Blocked except allowed devices",
              "READ_ONLY": "Read only", "BLOCK_EXECUTE": "Can't run programs from it",
              "BLOCK_WRITE_EXECUTE": "Read only, can't run programs from it"}
USB_CLASS = {"MASS_STORAGE": "USB storage", "ANY": "Any USB device", "IMAGING": "Cameras and scanners", "AUDIO_VIDEO": "Audio and video",
             "MOBILE": "Phones and tablets", "PRINTERS": "Printers", "WIRELESS": "Wireless adapters"}
_MODE = {"MONITOR_ENFORCE": "Enforced", "MONITOR_ONLY": "Monitor only (logs, doesn't block)", "OFF": "Off"}


def _deciders(u: User) -> bool:
    return bool({"admin", "cyber"} & set(u.role_names))


async def _device(device_id: uuid.UUID, u: User, db: AsyncSession):
    if not _deciders(u):
        raise HTTPException(404)
    from api.routes.devices import _visible_device
    return await _visible_device(device_id, u, db)


def _ports(v) -> str:
    return ", ".join(f"{a}" if a == b else f"{a}-{b}" for a, b in v or []) or "Any"


def _addrs(v) -> str:
    return ", ".join("Any" if a == "*" else a for a in v or []) or "Any"


def ruleset(policy) -> dict:
    """The policy as a traditional ruleset: its rules in order, then the default actions."""
    b = policy.body or {}
    rows = []
    for i, r in enumerate(b.get("rules") or [], 1):
        act = _ACTION.get(str(r.get("action") or "").upper(), r.get("action") or "?")
        rows.append({"n": i, "action": act, "logged": bool(r.get("logged") or r.get("monitor_only")),
                     "direction": _DIR.get(str(r.get("direction") or "").upper(), r.get("direction") or "Any"),
                     "protocol": r.get("protocol") or "Any", "remote": _addrs(r.get("remote_address")),
                     "fqdn": "; ".join(r.get("fqdn") or []) or None, "program": r.get("program"),
                     "remote_port": _ports(r.get("remote_port")), "local": _addrs(r.get("local_address")),
                     "local_port": _ports(r.get("local_port")), "name": r.get("name"), "description": r.get("description"),
                     "enabled": bool(r.get("enabled"))})
    for d, key in (("Inbound", "default_inbound"), ("Outbound", "default_outbound")):
        if b.get(key):
            rows.append({"n": None, "action": _ACTION.get(str(b[key]).upper(), b[key]), "direction": d, "protocol": "Any",
                         "remote": "Any", "remote_port": "Any", "local": "Any", "local_port": "Any",
                         "name": f"Default {d.lower()}", "description": "Anything no rule above matches", "enabled": True, "default": True})
    state = "Disabled" if not policy.enabled else "Monitor only (test mode)" if b.get("test_mode") else \
        "Enforced" if b.get("enforce") else "Not enforced"
    return {"state": state, "enforced": bool(policy.enabled and b.get("enforce") and not b.get("test_mode")),
            "platform": policy.platform, "rules": rows, "reported_at": policy.reported_at.isoformat() if policy.reported_at else None}


def usb_view(policy) -> dict:
    b = policy.body or {}
    classes = [{"class": USB_CLASS.get(c.get("id"), (c.get("id") or "").replace("_", " ").title()), "id": c.get("id"),
                "action": USB_ACTION.get(str(c.get("action") or "").upper(), c.get("action") or "Not set"),
                "allowed": [{**a, "action": USB_ACTION.get(str(a.get("action") or "").upper(), a.get("action") or "Allowed")}
                            for a in c.get("allowed") or []]} for c in b.get("classes") or []]
    classes.sort(key=lambda c: (c["id"] != "MASS_STORAGE", c["class"]))
    return {"state": _MODE.get(b.get("enforcement"), b.get("enforcement") or "Unknown") if policy.enabled else "Disabled",
            "enforced": bool(policy.enabled and b.get("enforcement") == "MONITOR_ENFORCE"), "platform": policy.platform,
            "classes": classes, "reported_at": policy.reported_at.isoformat() if policy.reported_at else None}


@router.get("/{device_id}/firewall")
async def device_firewall(device_id: uuid.UUID, u: User = Depends(require_permission("devices", "read")),
                          db: AsyncSession = Depends(get_session)):
    from api.core.edr_policies import of_device
    d = await _device(device_id, u, db)
    pol = await of_device(db, d, "firewall")
    if pol is None:
        return {"available": False, "edr": d.edr_vendor}
    return {"available": True, "edr": d.edr_vendor, **ruleset(pol)}


@router.get("/{device_id}/usb")
async def device_usb(device_id: uuid.UUID, u: User = Depends(require_permission("devices", "read")),
                     db: AsyncSession = Depends(get_session)):
    from api.core.edr_policies import of_device
    d = await _device(device_id, u, db)
    pol = await of_device(db, d, "device_control")
    if pol is None:
        return {"available": False, "edr": d.edr_vendor, "blocked": d.usb_storage_blocked}
    return {"available": True, "edr": d.edr_vendor, "blocked": d.usb_storage_blocked, **usb_view(pol)}


ENCRYPTION = __import__("re").compile(r"bitlocker|filevault|disk encrypt|drive encrypt|encrypt", __import__("re").I)


def posture_view(p: dict) -> dict:
    """Falcon's posture checks, disk encryption first, then the ones the host fails."""
    sig = []
    for s in p.get("signals") or []:
        meets = str(s.get("meets") or "").strip().lower()
        sig.append({**s, "passed": True if meets in ("yes", "true", "pass", "passed", "met") else
                    False if meets in ("no", "false", "fail", "failed", "not met") else None,
                    "encryption": bool(ENCRYPTION.search(f"{s.get('name') or ''} {s.get('criteria') or ''}"))})
    sig.sort(key=lambda s: (not s["encryption"], s["passed"] is not False, s["kind"], s["name"] or ""))
    enc = [s for s in sig if s["encryption"]]
    return {"overall": p.get("overall"), "os": p.get("os"), "sensor_config": p.get("sensor_config"), "assessed_at": p.get("at"),
            "signals": sig, "disk_encryption": (None if not enc else all(s["passed"] for s in enc) if all(s["passed"] is not None for s in enc) else None),
            "disk_encryption_reported": bool(enc)}


@router.get("/{device_id}/posture")
async def device_posture(device_id: uuid.UUID, u: User = Depends(require_permission("devices", "read")),
                         db: AsyncSession = Depends(get_session)):
    d = await _device(device_id, u, db)
    if not d.edr_posture:
        return {"available": False, "edr": d.edr_vendor}
    return {"available": True, "edr": d.edr_vendor, **posture_view(d.edr_posture)}


@router.get("/{device_id}/pentest")
async def device_pentest(device_id: uuid.UUID, u: User = Depends(require_permission("devices", "read")),
                         db: AsyncSession = Depends(get_session)):
    """The newest autonomous pentest's view of this asset (NodeZero): its rating, open services, attack paths,
    credentials and shares, with the weaknesses NodeZero still has open on it from any pentest."""
    from sqlalchemy import select

    from api.models.vuln import Finding, FindingStatus, Vulnerability
    d = await _device(device_id, u, db)
    rows = (await db.execute(select(Finding, Vulnerability).join(Vulnerability, Vulnerability.id == Finding.vuln_id).where(
        Finding.device_id == d.id, Finding.source == "horizon3",
        Finding.status.in_((FindingStatus.open, FindingStatus.merged)))   # merged: a scanner has it too, still NodeZero's proof
        .order_by(Vulnerability.cvss_base.desc().nulls_last()).limit(200))).all()
    found = [{"vuln_id": str(v.id), "name": v.title, "cve": v.cve_id, "score": v.cvss_base, "kev": bool(v.is_kev),
              "ports": f.ports, "proved": bool((f.details or {}).get("has_proof")), "paths": (f.details or {}).get("impact_paths"),
              "last_seen": f.last_seen.isoformat() if f.last_seen else None, "source_vuln_id": v.source_vuln_id,
              "description": (v.description or "")[:1200] or None, "proof": (f.details or {}).get("proof")} for f, v in rows]
    from api.models.risk import AttackPath
    chains = [{"title": p.path_description, "impact_detail": p.impact_description, "score": p.path_score, "active": p.is_active,
               "seen": p.last_seen.isoformat() if p.last_seen else None, **(p.graph or {})}
              for p in (await db.execute(select(AttackPath).where(AttackPath.target_device_id == d.id, AttackPath.confirmed_by == "horizon3")
                                         .order_by(AttackPath.is_active.desc(), AttackPath.last_seen.desc().nulls_last()).limit(25))).scalars()]
    for c in chains:
        c.pop("pairs", None)
    if not d.pentest and not found and not chains:
        return {"available": False}
    view = dict(d.pentest or {})
    view["open_services"] = sorted(view.get("open_services") or [], key=lambda s: (s.get("port") or 0, s.get("protocol") or ""))
    from api.integrations.horizon3_graph import graphs
    return {"available": True, **view, "findings": found, "chains": chains, "graphs": graphs(chains)}
