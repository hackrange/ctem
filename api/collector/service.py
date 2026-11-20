"""Profile + sealed-secret operations shared by the admin GUI routes and the shipper routes."""
from __future__ import annotations

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.collector import ingest
from api.collector.profile import DEST_KEYS, SCHEDULES, SECRET_FIELDS, check_envelope, dest_digest, validate_settings
from api.models.collector import CollectorProfile, CollectorSecret, CollectorToken


def clean_modules(raw: dict, existing: dict | None = None) -> dict:
    """Validate each module's settings; keep integration ids we already handed out."""
    existing = existing or {}
    out = {}
    for kind, m in (raw or {}).items():
        if kind not in DEST_KEYS:
            raise HTTPException(400, detail="Unknown source type")
        m = m if isinstance(m, dict) else {}
        settings = m.get("settings", m)
        try:
            clean = validate_settings(kind, {k: v for k, v in settings.items() if k not in ("enabled", "integration_id")})
        except ValidationError:
            raise HTTPException(400, detail=f"Check the {kind} settings") from None
        out[kind] = {"enabled": bool(m.get("enabled", True)), "settings": clean,
                     "integration_id": (existing.get(kind) or {}).get("integration_id")}
    if not out:
        raise HTTPException(400, detail="Pick at least one source")
    return out


def check_schedule(minutes: int) -> int:
    if minutes not in SCHEDULES:
        raise HTTPException(400, detail="Unsupported schedule")
    return minutes


async def active_token(db: AsyncSession, profile_id: str) -> CollectorToken | None:
    return (await db.execute(select(CollectorToken).where(
        CollectorToken.profile_id == profile_id, CollectorToken.is_active == True))).scalars().first()  # noqa: E712


async def secrets_of(db: AsyncSession, profile_id: str) -> list[CollectorSecret]:
    return list((await db.execute(select(CollectorSecret).where(CollectorSecret.profile_id == profile_id))).scalars())


async def store_secrets(db: AsyncSession, prof: CollectorProfile, tok: CollectorToken | None, items, who: str) -> int:
    if tok is None:
        raise HTTPException(409, detail="No shipper has enrolled for this profile yet")
    mods = prof.modules or {}
    current = {(s.kind, s.field): s for s in await secrets_of(db, prof.id)}
    for it in items:
        if it.kind not in mods or it.field not in SECRET_FIELDS[it.kind]:
            raise HTTPException(400, detail="That source doesn't take that secret")
        try:
            check_envelope(it.envelope, tok.key_fp)
        except (ValueError, TypeError):
            raise HTTPException(400, detail="Secret must be sealed to the shipper's current key") from None
        row = current.get((it.kind, it.field))
        if row is None:
            row = CollectorSecret(profile_id=prof.id, kind=it.kind, field=it.field)
            db.add(row)
        row.envelope, row.key_fp, row.updated_by = it.envelope, tok.key_fp, who[:64]
    prof.config_version = (prof.config_version or 1) + 1
    return len(items)


def agent_config(prof: CollectorProfile, secrets: list[CollectorSecret], tok: CollectorToken) -> dict:
    mods = []
    for kind, m in (prof.modules or {}).items():
        mods.append({"kind": kind, "integration_id": m.get("integration_id"), "enabled": m.get("enabled", True),
                     "settings": m.get("settings", {}), "dest_digest": dest_digest(kind, m.get("settings", {}))})
    return {
        "profile_id": str(prof.id), "name": prof.name, "config_version": prof.config_version,
        "schedule_minutes": prof.schedule_minutes, "modules": mods,
        # Only envelopes sealed to this box's key; older ones are useless to it anyway
        "secrets": [{"kind": s.kind, "field": s.field, "envelope": s.envelope} for s in secrets if s.key_fp == tok.key_fp],
    }


def admin_view(prof: CollectorProfile, tok: CollectorToken | None, secrets: list[CollectorSecret]) -> dict:
    approved = (tok.approved or {}) if tok else {}
    mods = {}
    for kind, m in (prof.modules or {}).items():
        want = dest_digest(kind, m.get("settings", {}))
        mods[kind] = {
            **m,
            "approval": "approved" if approved.get(kind) == want else ("pending" if tok else "not enrolled"),
            "secrets": {f: next(({"set": True, "updated_at": s.updated_at.isoformat() if s.updated_at else None,
                                  "by": s.updated_by, "current_key": s.key_fp == (tok.key_fp if tok else None)}
                                 for s in secrets if s.kind == kind and s.field == f), {"set": False})
                        for f in SECRET_FIELDS[kind]},
        }
    return {
        "id": str(prof.id), "name": prof.name, "schedule_minutes": prof.schedule_minutes,
        "config_version": prof.config_version, "modules": mods,
        "shipper": None if tok is None else {
            "id": str(tok.id), "host": tok.collector_host, "agent_version": tok.agent_version,
            "last_seen": tok.last_seen.isoformat() if tok.last_seen else None, "last_seen_ip": tok.last_seen_ip,
            "last_error": tok.last_error, "key_fp": tok.key_fp, "public_key": tok.public_key,
        },
    }


async def save_profile_modules(db: AsyncSession, prof: CollectorProfile, modules: dict) -> None:
    prof.modules = modules
    await ingest.ensure_integrations(db, prof)
    prof.config_version = (prof.config_version or 1) + 1
