"""View as: an admin sees CTEM exactly as one other person does (their roles, pages and data access), to check what
they can and can't see. Started from Admin > Users.

Held tight on purpose:
  - only an admin, only from a signed-in browser (never an API token), and never as another admin
  - read-only: anything but GET, HEAD or OPTIONS is refused while viewing as someone, except stopping
  - 30 minutes at most, and it ends the moment the admin loses the admin role or the person is disabled or locked
  - the admin stays the one signed in: the session token is still theirs, checked on every request
  - started, stopped and expired are in the Audit Log under the admin, with the reason they gave, and anything else
    that writes to the Audit Log meanwhile is put under the admin too, marked with who they were viewing as
"""
from __future__ import annotations

import contextvars
import logging
import time

from fastapi import HTTPException, Request
from sqlalchemy import event, select
from sqlalchemy.orm import Session, selectinload

from api.models.user import User

log = logging.getLogger("open-ctem.auth.impersonation")
KEY = "acting_as"
MAX_SECONDS = 30 * 60
SAFE = frozenset({"GET", "HEAD", "OPTIONS"})
ALWAYS = frozenset({"/api/v1/impersonate/stop", "/api/v1/impersonate"})
_who: contextvars.ContextVar[tuple[str, str, str] | None] = contextvars.ContextVar("ctem_acting", default=None)


def can_be_viewed(target: User) -> str | None:
    """Why this person can't be viewed as, or None."""
    if not target.is_active or target.is_locked:
        return "That account is disabled or locked."
    if "admin" in target.role_names:
        return "Admins can't be viewed as."
    return None


def start(request: Request, admin: User, target: User) -> int:
    until = int(time.time()) + MAX_SECONDS
    request.session[KEY] = {"uid": str(target.id), "by": str(admin.id), "until": until}
    return until


def end(request: Request) -> dict | None:
    return request.session.pop(KEY, None)


async def _audit(db, admin: User, action: str, target_id: str, detail: str, request: Request) -> None:
    from api.core.security import _client_ip
    from api.models.settings import AuditLog
    db.add(AuditLog(actor_user_id=str(admin.id), actor_username=admin.username, action=action, resource_type="user",
                    resource_id=target_id, detail=detail[:500], ip_address=_client_ip(request)))
    await db.commit()


async def resolve(request: Request, admin: User, db) -> User:
    """The person the request is for: the signed-in admin, or whoever they are viewing as."""
    v = request.session.get(KEY)
    if not isinstance(v, dict) or v.get("by") != str(admin.id):
        if v is not None:
            end(request)   # not this admin's: never carried over
        return admin
    target = (await db.execute(select(User).where(User.id == str(v.get("uid"))).options(selectinload(User.roles)))).scalar_one_or_none()
    why = None
    if "admin" not in admin.role_names:
        why = "the admin role was removed"
    elif not isinstance(v.get("until"), int) or v["until"] <= time.time():
        why = "the 30 minutes ran out"
    elif target is None or can_be_viewed(target):
        why = "the account can no longer be viewed as"
    if why:
        end(request)
        await _audit(db, admin, "impersonate.expired", str(v.get("uid"))[:36],
                     f"Stopped viewing as {target.username if target else 'a removed account'}: {why}", request)
        return admin
    if request.method not in SAFE and request.url.path not in ALWAYS:
        raise HTTPException(403, detail=f"You are viewing as {target.username}, which is read-only. Stop viewing as them first.")
    request.state.impersonator = admin
    request.state.impersonating_until = v["until"]
    _who.set((str(admin.id), admin.username, target.username))
    return target


@event.listens_for(Session, "before_flush")
def _audit_as_admin(session, _ctx, _instances) -> None:
    """While viewing as someone, an Audit Log row is the admin's, never the person's."""
    who = _who.get()
    if who is None:
        return
    from api.models.settings import AuditLog
    for obj in session.new:
        if isinstance(obj, AuditLog) and obj.actor_user_id != who[0]:
            obj.actor_user_id, obj.actor_username = who[0], who[1]
            obj.detail = f"[viewing as {who[2]}] {obj.detail or ''}"[:2000]
