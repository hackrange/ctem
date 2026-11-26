"""Does a person have a valid verified government ID on file? That decides what a re-verification asks for.

Yes: a selfie is enough (Persona compares the face with the verified one). No: a government ID and a selfie.
"Valid" means a government ID passed in a check that counts (started by an API key, Okta's flow or the service desk,
or approved by an approver) since the person's last expire or revoke; after a revoke, only a check an approver
approved since then. Nothing older than an expire or revoke counts, so after one it is always ID + selfie."""
from __future__ import annotations

from datetime import timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

KINDS = ("id_selfie", "selfie")


def _aware(d):
    return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)


async def active_id(db: AsyncSession, user) -> dict | None:
    """The latest valid verified ID: {"id_type", "country", "at"}, or None."""
    from api.integrations.persona_checks import gov_id_passed
    from api.integrations.persona_ingest import trusted_by_integration
    from api.models.idv import IdvRequest
    since = _aware(user.idv_revoked_at)
    trusted = await trusted_by_integration(db)
    rows = (await db.execute(select(IdvRequest).where(IdvRequest.user_id == user.id, IdvRequest.state == "approved")
                             .order_by(IdvRequest.created_at.desc().nullslast()).limit(200))).scalars().all()
    for r in rows:
        if since is not None and (r.created_at is None or _aware(r.created_at) <= since):
            continue
        if since is not None and (user.idv_revoked_kind or "revoke") == "revoke" and not r.reviewed_by:
            continue   # after a revoke only an approver's decision restores trust
        if not (r.reviewed_by or r.origin == "service_desk" or r.created_via == "API"):
            continue
        names = trusted.get(r.integration_id or "") or set()
        if names and r.template_id not in names and not r.reviewed_by:
            continue
        if gov_id_passed(r.facts):
            f = r.facts or {}
            ids = [v for v in f.get("verifications") or [] if v.get("kind", "").startswith("government-id") and v.get("status") == "passed"]
            last = ids[-1] if ids else {}
            at = r.completed_at or r.decided_at or r.created_at
            return {"id_type": last.get("id_type") or f.get("id_type"), "country": last.get("country") or f.get("country"),
                    "at": at.isoformat() if at else None}
    return None


async def plan(db: AsyncSession, user, persona_config: dict, asked: str = "auto") -> dict:
    """What a link for this person will ask for: {"kind", "active_id", "selfie_available", "why"}.
    asked: auto picks a selfie when the person has a valid ID and a selfie template is set; id_selfie can always be
    chosen; selfie only when there is a valid ID (never a way around the ID)."""
    from fastapi import HTTPException
    has = await active_id(db, user)
    selfie_ok = bool(has) and bool(persona_config.get("selfie_template_id"))
    if asked == "selfie" and not has:
        raise HTTPException(409, detail="This person has no valid verified ID on file, so they must verify with a government ID and a selfie")
    if asked == "selfie" and not selfie_ok:
        raise HTTPException(409, detail="Set a selfie-only template on the Persona integration to send a selfie check")
    kind = "id_selfie" if asked == "id_selfie" else ("selfie" if selfie_ok else "id_selfie")
    why = ("They have a verified ID on file, so a selfie is enough." if kind == "selfie"
           else "No valid verified ID on file, so they verify with a government ID and a selfie." if not has
           else "A government ID and a selfie, as chosen." if asked == "id_selfie"
           else "No selfie-only template is set, so they verify with a government ID and a selfie.")
    return {"kind": kind, "active_id": has, "selfie_available": selfie_ok, "why": why}
