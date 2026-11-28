"""Identity > a person, an app and a posture finding in full (Cyber or Admin), and the password-change notice.

Grip identities are kept as keyed email hashes; the person behind one is the directory record with the same hash, so
nobody's address is stored again here. The notice goes to that directory address only, names the apps and what is
wrong with each password, carries no links (people are told to sign in to each app directly) and never a password.
Sending needs a signed-in browser, is refused more than once a day per person, and is audited."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_cyber_or_admin
from api.auth.step_up import browser_only
from api.core.config import get_settings
from api.core.db import get_session
from api.models.identity import IdentityRiskScore, IdentityThreat, PostureFinding, SaasAppRecord
from api.models.settings import AuditLog
from api.models.user import User

router = APIRouter(prefix="/api/v1/identity", tags=["identity"])
NOTICE_GAP = timedelta(hours=24)
MAX_ROWS = 100


async def people_for(db: AsyncSession, hashes: set[str]) -> dict[str, User]:
    """The directory person for each email hash (matched on email or UPN), people over sign-in accounts."""
    hashes = {h for h in hashes if h}
    if not hashes:
        return {}
    rows = (await db.execute(select(User).where(or_(User.email_hash.in_(hashes), User.upn_hash.in_(hashes))))).scalars().all()
    out: dict[str, User] = {}
    for u in sorted(rows, key=lambda u: (u.is_local, u.oidc_sub is not None)):   # directory people first
        for h in (u.email_hash, u.upn_hash):
            if h in hashes and h not in out:
                out[h] = u
    return out


def person_view(u: User | None) -> dict | None:
    if u is None:
        return None
    name = u.display_name or " ".join(x for x in (u.first_name, u.last_name) if x) or u.username
    return {"id": str(u.id), "name": name, "email": u.email or u.upn, "username": u.ad_username or u.username,
            "title": getattr(u, "title", None), "disabled": bool(u.ad_disabled) if u.ad_disabled is not None else not u.is_active,
            "last_logon": u.ad_last_logon.isoformat() if u.ad_last_logon else None}


def _iso(d):
    return d.isoformat() if d else None


def _problems(e: dict) -> list[str]:
    return [w for k, w in (("leaked", "found in a known breach list"), ("reused", "also used for other accounts"),
                           ("weak", "weak (easy to guess)")) if e.get(k)]


def notice(person: dict, apps: list[dict], org: str) -> dict:
    """The message for one person: the apps and what is wrong with each password; no links, no passwords."""
    first = (person.get("name") or "").split(" ")[0] or "there"
    names = [a["app"] for a in apps][:4]
    lines = [f"  - {a['app']}: the password {'may be ' if not a.get('certain') else 'is '}" + "; ".join(_problems(a)) for a in apps]
    body = (f"Hello {first},\n\n"
            f"{org}'s security team found that a password you use is at risk:\n\n" + "\n".join(lines) + "\n\n"
            "Please change the password for each app listed. Sign in to the app the way you normally do, typing its address "
            "yourself, rather than following a link in any email. Use a new password that you don't use anywhere else, and "
            "turn on multi-factor sign-in where the app offers it. If you used the same password on any other site, change "
            "it there too.\n\n"
            "This message contains no links, and we will never ask you for your password. If you have any questions, "
            f"contact {org}'s IT or security team directly.\n")
    return {"subject": "Action needed: change your password for " + ", ".join(names) + ("" if len(apps) <= 4 else ", and others"),
            "body": body, "to": person.get("email")}


async def _org(db: AsyncSession) -> str:
    from api.main import _get_branding
    b = await _get_branding(db)
    return b.get("org_name") or b.get("title") or "Our"


async def _score(db: AsyncSession, score_id: uuid.UUID) -> IdentityRiskScore:
    rec = await db.get(IdentityRiskScore, str(score_id))
    if rec is None:
        raise HTTPException(404, detail="Not found")
    return rec


@router.get("/people/{score_id}")
async def person(score_id: uuid.UUID, _: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    """Everything about one identity: who they are, their scores, the apps holding their weak, reused or leaked passwords,
    their ITDR alerts and posture findings, and the notice they would get."""
    from api.core import email
    from api.routes.identity import _serialize_threat
    rec = await _score(db, score_id)
    who = person_view((await people_for(db, {rec.user_email_hash})).get(rec.user_email_hash))
    threats = (await db.execute(select(IdentityThreat).where(IdentityThreat.user_email_hash == rec.user_email_hash)
                                .order_by(IdentityThreat.detected_at.desc()).limit(MAX_ROWS))).scalars().all()
    posture = (await db.execute(select(PostureFinding).where(PostureFinding.user_email_hash == rec.user_email_hash,
                                                             PostureFinding.is_resolved == False)  # noqa: E712
                                .limit(MAX_ROWS))).scalars().all()
    apps = rec.credential_apps or []
    return {
        "id": str(rec.id), "user_display": rec.user_display, "person": who,
        "scores": {k: getattr(rec, k) for k in ("composite_identity_score", "itdr_score", "posture_score", "credential_score",
                                                 "shadow_saas_score", "shadow_ai_score")},
        "credentials": {"leaked": rec.leaked_password_accounts, "reused": rec.reused_password_accounts,
                        "weak": rec.weak_password_accounts, "mfa_coverage_pct": rec.mfa_coverage_pct,
                        "risky_extensions": rec.risky_extensions, "apps": apps},
        "counts": {"shadow_saas_apps": rec.shadow_saas_apps, "shadow_ai_apps": rec.shadow_ai_apps},
        "threats": [_serialize_threat(t) for t in threats],
        "posture": [{"id": str(f.id), "severity": f.severity, "title": f.title, "app_name": f.app_name,
                     "detected_at": _iso(f.detected_at)} for f in posture],
        # AI agents this person owns (the AI inventory matches owners to identities)
        "ai_agents": [{k: a[k] for k in ("name", "platform", "state", "concerns", "sharing", "internet", "last_seen")}
                      for a in await _agents_owned(db, str(rec.id))],
        "notified_at": _iso(rec.notified_at), "notified_by": rec.notified_by, "last_synced": _iso(rec.last_synced),
        "notice": notice(who, apps, await _org(db)) if who and apps else None,
        "email_on": await email.configured(),
    }


async def _agents_owned(db: AsyncSession, identity_id: str) -> list[dict]:
    from api.core.ai_inventory import agents
    return [a for a in await agents(db) if a["owner_identity_id"] == identity_id]


class NotifyBody(BaseModel):
    confirm: bool


@router.post("/people/{score_id}/notify")
async def notify(score_id: uuid.UUID, body: NotifyBody, request: Request, me: User = Depends(require_cyber_or_admin),
                 _b: None = Depends(browser_only), db: AsyncSession = Depends(get_session)):
    """Email the person the password-change notice. Cyber or Admin, from a browser, at most once a day per person."""
    from api.core import email
    if not body.confirm:
        raise HTTPException(400, detail="Confirm sending the notice.")
    rec = await _score(db, score_id)
    who = person_view((await people_for(db, {rec.user_email_hash})).get(rec.user_email_hash))
    if not who or not who.get("email"):
        raise HTTPException(409, detail="No email address for this person in the directory.")
    if not rec.credential_apps:
        raise HTTPException(409, detail="No apps with weak, reused or leaked passwords for this person.")
    now = datetime.now(timezone.utc)
    if rec.notified_at and now - (rec.notified_at if rec.notified_at.tzinfo else rec.notified_at.replace(tzinfo=timezone.utc)) < NOTICE_GAP:
        raise HTTPException(409, detail="A notice already went to this person in the last 24 hours.")
    if not await email.configured():
        raise HTTPException(409, detail="Email is turned off. Set it up in Settings, or copy the message and send it yourself.")
    msg = notice(who, rec.credential_apps, await _org(db))
    if not await email.EmailClient(get_settings()).send(msg["to"], msg["subject"], msg["body"]):
        raise HTTPException(502, detail="The email could not be sent. The reason is in the server log.")
    rec.notified_at, rec.notified_by = now, me.username
    db.add(AuditLog(actor_user_id=str(me.id), actor_username=me.username, action="identity.password_notice",
                    resource_type="identity", resource_id=str(rec.id),
                    detail=f"Password-change notice sent for {len(rec.credential_apps)} app(s)"))
    await db.commit()
    return {"sent": True, "notified_at": now.isoformat()}


@router.get("/saas-apps/{app_id}")
async def app_detail(app_id: uuid.UUID, _: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    a = await db.get(SaasAppRecord, str(app_id))
    if a is None:
        raise HTTPException(404, detail="Not found")
    return {"id": str(a.id), "app_name": a.app_name, "vendor": a.vendor, "app_category": a.app_category, "source": a.source,
            "is_shadow_ai": a.is_shadow_ai, "is_sanctioned": a.is_sanctioned, "risk_level": a.risk_level, "risk_score": a.risk_score,
            "user_count": a.user_count, "last_seen": _iso(a.last_seen), "first_seen": _iso(a.created_at),
            "oauth_scopes": a.oauth_scopes, "data_access": a.data_access_scopes}


@router.get("/posture/{finding_id}")
async def posture_detail(finding_id: uuid.UUID, _: User = Depends(require_cyber_or_admin), db: AsyncSession = Depends(get_session)):
    f = await db.get(PostureFinding, str(finding_id))
    if f is None:
        raise HTTPException(404, detail="Not found")
    who = person_view((await people_for(db, {f.user_email_hash})).get(f.user_email_hash)) if f.user_email_hash else None
    score = (await db.execute(select(IdentityRiskScore.id).where(IdentityRiskScore.user_email_hash == f.user_email_hash))).scalar() \
        if f.user_email_hash else None
    return {"id": str(f.id), "source": f.source, "finding_type": f.finding_type, "severity": f.severity, "title": f.title,
            "description": f.description, "app_name": f.app_name, "user_display": f.user_display, "person": who,
            "identity_id": str(score) if score else None, "affected_count": f.affected_count, "is_resolved": f.is_resolved,
            "detected_at": _iso(f.detected_at), "resolved_at": _iso(f.resolved_at), "external_id": f.external_id}
