"""An asset's Identity tab: what the identity provider (Okta) knows about the computer and the people who sign in on
it, including the phone their MFA codes go to, the most reliable way to reach them. Phones and MFA state are
personal, so it's admins and cyber only, as the directory's people pages are; 404 for anyone else and for assets
they can't see, alike."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.models.user import User

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])
_KEEP = ("platform", "os_version", "manufacturer", "model", "serial", "disk_encryption", "secure_hardware", "managed",
         "screen_lock", "status", "registered", "updated")


def _person(u: User, why: str) -> dict:
    idp = u.idp or {}
    return {"id": str(u.id), "name": u.display_name or u.username, "upn": u.upn, "title": u.title, "department": u.department,
            "why": why, "mfa_phone": u.mfa_phone, "mfa_phone_kind": idp.get("mfa_phone_kind"), "mobile": u.mobile,
            "phone": u.phone, "email": u.email, "account_status": idp.get("status"), "last_login": idp.get("last_login"),
            "factors": idp.get("factors"), "factors_at": idp.get("factors_at"),
            "idv_verified_at": u.idv_verified_at.isoformat() if u.idv_verified_at else None}


@router.get("/{device_id}/identity")
async def device_identity(device_id: uuid.UUID, u: User = Depends(require_permission("devices", "read")),
                          db: AsyncSession = Depends(get_session)):
    if not {"admin", "cyber"} & set(u.role_names):
        raise HTTPException(404)
    from api.core.encryption import search_hash
    from api.routes import device_query as dq
    from api.routes.devices import _visible_device
    d = await _visible_device(device_id, u, db)   # 404 for absent and not yours alike
    rec = d.idp_device or {}
    people: list[dict] = []
    seen: set[str] = set()

    def add(person, why):
        if person is not None and str(person.id) not in seen:
            seen.add(str(person.id))
            people.append(_person(person, why))

    a = dq.assignment(d)
    add(a.user if a is not None else None, "assigned")
    add(d.owner, "detected")
    hashes = [search_hash(x.lower()) for x in (rec.get("logins") or [])[:10] if isinstance(x, str) and "@" in x]
    if hashes:
        for p in (await db.execute(select(User).where(User.upn_hash.in_(hashes), User.is_local.is_(False)))).scalars():
            add(p, "signed in (identity provider)")
    return {"device": {k: rec.get(k) for k in _KEEP} if rec else None,
            "owner_from_idp": bool(rec.get("owner_from_idp")), "people": people}
