"""Caller verification for the service desk, embedded in ServiceNow (docs/servicenow-caller-verification.md).

1. ServiceNow's server starts a session: POST /api/v1/idv/desk/sessions with an IDV Validation API token, which works
   only from ServiceNow's address ranges (the token's IP allow-list). Cookies can't: a bearer token is required. It
   names the ticket and the analyst, and gets a one-time launch token (2 minutes, used once).
2. ServiceNow's form frames /desk/embed#<launch token>. The page may be framed only by the exact service desk origins
   set on the Persona integration (CSP frame-ancestors); it holds no data. The fragment never reaches a server.
3. The page trades the launch token for a session key (POST /api/v1/idv/desk/exchange), only from the analysts'
   network ranges. The key lives in the page's memory only, lasts 30 minutes, works only from the address that traded
   it, and is sent as X-Desk-Key: no cookie is involved anywhere, so nothing rides on a sign-in.
4. With the key the panel looks up the caller (a few results, a capped number of searches), sends the Persona link
   to their verified MFA contact (api/core/idv_send.py, the same rules as everywhere), and watches the status.
5. ServiceNow's server can read the outcome with its token (GET /api/v1/idv/desk/sessions/{id}): the record to keep.

CORS stays closed: CTEM sends no Access-Control-Allow-Origin, so no other site's script can read any of this."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.rbac import require_permission
from api.core.db import get_session
from api.models.idv import DeskEmbed, DeskSession, IdvRequest
from api.models.user import User

router = APIRouter(tags=["idv-desk"])
requester = require_permission("idv", "desk")   # an embed's token
LAUNCH = timedelta(minutes=2)
LIFE = timedelta(minutes=30)
MAX_LOOKUPS = 40
PER_TOKEN_HOUR = 1000   # a session per ticket form opened
PER_ANALYST_HOUR = 30   # links one analyst sends an hour
PER_EMBED_HOUR = 300    # links the whole service desk sends an hour through one embed
_TEXT = r"^[^\x00-\x1f\x7f<>]*$"


def _h(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(d: datetime | None) -> datetime | None:
    return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)


async def _origins(db: AsyncSession) -> list[str]:
    """Every live embed's site: the panel page may be framed by these and nothing else."""
    rows = (await db.execute(select(DeskEmbed.frame_origin).where(DeskEmbed.revoked_at.is_(None)))).scalars().all()
    return sorted(set(rows))[:20]


async def _embed(db: AsyncSession, embed_id: str | None) -> DeskEmbed | None:
    e = await db.get(DeskEmbed, embed_id) if embed_id else None
    return e if e is not None and e.revoked_at is None else None


def _ip(request: Request) -> str:
    from api.core.security import _client_ip
    return _client_ip(request)


# ── 1. ServiceNow's server starts a session ────────────────────────────────────────────────────────────────────────
class Start(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ticket: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9_.\-]+$")
    analyst: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._@+\- ]+$")
    caller: str | None = Field(None, max_length=128, pattern=_TEXT)


async def _token(request: Request, db: AsyncSession):
    """The API token behind this call; refused for a browser session, so only a server holding the token starts one."""
    from api.models.user import ApiToken
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(403, detail="Use the service desk's API token")
    t = (await db.execute(select(ApiToken).where(ApiToken.token_hash == _h(auth[7:].strip())))).scalar_one_or_none()
    if t is None:
        raise HTTPException(403, detail="Use the service desk's API token")
    return t


@router.post("/api/v1/idv/desk/sessions")
async def start(body: Start, request: Request, me: User = Depends(requester), db: AsyncSession = Depends(get_session)):
    from api.models.settings import AuditLog
    tok = await _token(request, db)   # get_current_user already checked it is live and from its own address range
    emb = (await db.execute(select(DeskEmbed).where(DeskEmbed.token_id == str(tok.id), DeskEmbed.revoked_at.is_(None)))).scalar_one_or_none()
    if emb is None:
        raise HTTPException(403, detail="This token isn't a caller verification embed's; make one on the IDV page (Iframe Code)")
    n = (await db.execute(select(func.count()).select_from(DeskSession).where(
        DeskSession.token_id == str(tok.id), DeskSession.created_at > _now() - timedelta(hours=1)))).scalar_one()
    if n >= PER_TOKEN_HOUR:
        raise HTTPException(429, detail="Too many caller verifications started this hour")
    launch, now = secrets.token_urlsafe(32), _now()
    s = DeskSession(launch_hash=_h(launch), token_id=str(tok.id), embed_id=emb.id, started_by=str(me.id), analyst=body.analyst.strip(),
                    ticket=body.ticket, caller_hint=(body.caller or "").strip() or None, frame_origin=emb.frame_origin,
                    launch_expires_at=now + LAUNCH, expires_at=now + LIFE, created_at=now)
    db.add(s)
    db.add(AuditLog(actor_user_id=str(me.id), actor_username=me.username, action="idv.desk_start", resource_type="desk_session",
                    resource_id=s.id, detail=f"ticket {body.ticket} analyst {body.analyst}"[:300]))
    await db.commit()
    return {"session": s.id, "launch_path": f"/desk/embed#{launch}", "expires_in": int(LAUNCH.total_seconds())}


@router.get("/api/v1/idv/desk/sessions/{session_id}")
async def outcome(session_id: uuid.UUID, request: Request, me: User = Depends(requester), db: AsyncSession = Depends(get_session)):
    """The outcome, for ServiceNow's server to record on the ticket (only the token that started the session)."""
    from api.core.desk_status import refresh, view
    tok = await _token(request, db)
    s = await db.get(DeskSession, str(session_id))
    if s is None or s.token_id != str(tok.id):
        raise HTTPException(404)
    row = await db.get(IdvRequest, s.request_id) if s.request_id else None
    if row is not None:
        await refresh(db, row)
    v = view(row)
    r = v.get("result") or {}
    return {"session": s.id, "ticket": s.ticket, "analyst": s.analyst, "verified": r.get("kind") == "verified",
            "result": r.get("kind") or ("waiting" if row is not None else "not_started"), "detail": r.get("detail"),
            "sent_at": v.get("sent_at"), "updated_at": row.updated_at.isoformat() if row is not None and row.updated_at else None}


# ── 2. The framed page ─────────────────────────────────────────────────────────────────────────────────────────────
@router.get("/desk/embed", response_class=HTMLResponse, include_in_schema=False)
async def page(request: Request, db: AsyncSession = Depends(get_session)):
    from api.web.assets import static_url
    origins = await _origins(db)
    resp = HTMLResponse(_PAGE.format(css=static_url("css/desk_embed.css"), js=static_url("js/desk_embed.js")))
    ancestors = " ".join(origins) or "'none'"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
        f"frame-ancestors {ancestors}; base-uri 'none'; form-action 'none';")
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Desk-Frame"] = "1"   # tells the security middleware not to add X-Frame-Options: DENY here
    return resp


# A fixed shell: no data and nothing from the request in it. The script fills it once it holds a session key.
_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><title>Caller verification</title>
<link rel="stylesheet" href="{css}"></head>
<body><main id="desk" class="desk" aria-live="polite"><p class="desk-muted">Starting...</p></main>
<script src="{js}"></script></body></html>"""


# ── 3. The page trades the launch token for its session key ────────────────────────────────────────────────────────
class Exchange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    launch: str = Field(min_length=20, max_length=64, pattern=r"^[A-Za-z0-9_\-]+$")


def _in(ip: str, ranges: list[str]) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(r, strict=False) for r in ranges)


@router.post("/api/v1/idv/desk/exchange")
async def exchange(body: Exchange, request: Request, db: AsyncSession = Depends(get_session)):
    if request.headers.get("sec-fetch-site") != "same-origin":
        raise HTTPException(403)   # only the panel's own page trades a launch token
    ip = _ip(request)
    s = (await db.execute(select(DeskSession).where(DeskSession.launch_hash == _h(body.launch)).with_for_update())).scalar_one_or_none()
    if s is None or s.exchanged_at is not None or _aware(s.launch_expires_at) < _now():
        raise HTTPException(401, detail="This panel link has expired or was already used; reopen the panel")
    emb = await _embed(db, s.embed_id)
    if emb is None or not _in(ip, emb.client_ips or []):
        raise HTTPException(403, detail="The caller verification panel works only from the service desk's network")
    key = secrets.token_urlsafe(32)
    s.key_hash, s.exchanged_at, s.client_ip = _h(key), _now(), ip
    await db.commit()
    return {"key": key, "expires_at": _aware(s.expires_at).isoformat(), "ticket": s.ticket, "analyst": s.analyst,
            "caller": s.caller_hint, "parent_origin": s.frame_origin}


async def desk(request: Request, x_desk_key: str = Header(..., min_length=20, max_length=64),
               db: AsyncSession = Depends(get_session)) -> DeskSession:
    s = (await db.execute(select(DeskSession).where(DeskSession.key_hash == _h(x_desk_key)))).scalar_one_or_none()
    if s is None or _aware(s.expires_at) < _now() or s.client_ip != _ip(request):
        raise HTTPException(401, detail="This panel session ended; reopen the panel")
    emb = await _embed(db, s.embed_id)
    if emb is None or not _in(s.client_ip, emb.client_ips or []):   # revoked, or its ranges narrowed since
        raise HTTPException(401, detail="This panel session ended; reopen the panel")
    from api.models.user import ApiToken
    tok = await db.get(ApiToken, emb.token_id) if emb.token_id else None
    exp = _aware(tok.expires_at) if tok is not None else None
    if tok is None or not tok.is_active or (exp is not None and exp < _now()):   # its token was turned off or ran out
        raise HTTPException(401, detail="This panel session ended; reopen the panel")
    return s


# ── 4. The panel's own calls ───────────────────────────────────────────────────────────────────────────────────────
def _person_card(u: User) -> dict:
    return {"id": u.id, "name": " ".join(filter(None, [u.first_name, u.last_name])) or u.display_name or u.username,
            "username": u.username, "title": u.title, "department": u.department,
            "verified_at": u.idv_verified_at.isoformat() if u.idv_verified_at else None}


@router.get("/api/v1/idv/desk/s/lookup")
async def lookup(q: str = Query(..., min_length=2, max_length=64, pattern=_TEXT), s: DeskSession = Depends(desk),
                 db: AsyncSession = Depends(get_session)):
    from api.core.accounts import directory_person
    from api.core.encryption import search_hash
    from api.routes.directory_users import _by_name_or_phone
    from sqlalchemy import update
    left = (await db.execute(update(DeskSession).where(DeskSession.id == s.id, DeskSession.lookups < MAX_LOOKUPS)
                             .values(lookups=DeskSession.lookups + 1).returning(DeskSession.lookups))).scalar_one_or_none()
    if left is None:   # counted in one statement, so parallel searches can't pass the cap
        raise HTTPException(429, detail="That's the most searches one panel can make; reopen it for a new caller")
    term = q.strip()
    key = search_hash(term.lower())
    ids = await _by_name_or_phone(db, term) if " " in term or term.isalpha() else []
    rows = (await db.execute(select(User).where(directory_person(), User.is_active.is_(True), or_(
        User.username.ilike(term.replace("%", "").replace("_", r"\_") + "%"), User.upn_hash == key, User.upn_local_hash == key,
        User.email_hash == key, User.id.in_(ids[:200]))).order_by(User.username).limit(8))).scalars().all()
    await db.commit()
    return {"people": [_person_card(u) for u in rows], "searches_left": MAX_LOOKUPS - left}


@router.get("/api/v1/idv/desk/s/person/{user_id}")
async def person(user_id: uuid.UUID, s: DeskSession = Depends(desk), db: AsyncSession = Depends(get_session)):
    from api.core.accounts import directory_person
    from api.core.idv_send import readiness
    from api.core.verified_contacts import ineligible, verified_contacts
    u = (await db.execute(select(User).where(User.id == str(user_id), directory_person()))).scalar_one_or_none()
    if u is None:
        raise HTTPException(404)
    ready, c = await readiness(db), verified_contacts(u)
    why = ineligible(u) or (None if u.okta_id else "isn't linked to an identity provider account")
    chans = [{"channel": ch, "shown": c[ch]["shown"], "source": c[ch]["source"], "since": c[ch]["since"], "recent": c[ch]["recent"],
              "available": ok} for ch, ok in (("sms", ready["twilio"] is not None), ("email", ready["email"])) if c[ch]]
    from api.core.verified_id import plan
    what = await plan(db, u, (ready["persona"].config or {}) if ready["persona"] else {})
    return {**_person_card(u), "channels": chans, "blocked": why, "missing": ready["missing"], "plan": what}


class DeskSend(BaseModel):
    model_config = ConfigDict(extra="forbid")
    person: uuid.UUID
    channel: str = Field(pattern="^(sms|email)$")
    confirm_recent: bool = False
    kind: str = Field("auto", pattern="^(auto|id_selfie|selfie)$")


@router.post("/api/v1/idv/desk/s/send")
async def send(body: DeskSend, s: DeskSession = Depends(desk), db: AsyncSession = Depends(get_session)):
    from api.core.accounts import directory_person
    from api.core.idv_send import send_link
    if not (await db.execute(select(User.id).where(User.id == str(body.person), directory_person()))).first():
        raise HTTPException(404)
    sid, ticket, analyst, started_by, embed = s.id, s.ticket, s.analyst, s.started_by, s.embed_id
    hour = _now() - timedelta(hours=1)
    mine = (await db.execute(select(func.count()).select_from(DeskSession).join(IdvRequest, IdvRequest.id == DeskSession.request_id).where(
        DeskSession.embed_id == embed, DeskSession.analyst == analyst, IdvRequest.created_at > hour))).scalar_one()
    if mine >= PER_ANALYST_HOUR:
        raise HTTPException(429, detail="That's the most verification links one analyst can send in an hour")
    row, out = await send_link(db, str(body.person), body.channel, body.confirm_recent, started_by,
                               f"desk:{analyst}"[:128], note=f" ticket {ticket}", sender_limit=PER_EMBED_HOUR, kind=body.kind)
    s = await db.get(DeskSession, sid)
    s.user_id, s.request_id = str(body.person), row.id
    await db.commit()
    return out


@router.get("/api/v1/idv/desk/s/status")
async def status(s: DeskSession = Depends(desk), db: AsyncSession = Depends(get_session)):
    from api.core.desk_status import refresh, view
    row = await db.get(IdvRequest, s.request_id) if s.request_id else None
    if row is not None:
        await refresh(db, row)
    return {**view(row), "session_expires_at": _aware(s.expires_at).isoformat()}
