"""What Okta knows about people and their machines, merged into CTEM's directory users and devices.

People are matched by their Okta sign-in name, which is normally their UPN (api/core/user_match.py). Okta only fills
gaps in what the directory already holds (phone, title, department); its own facts go in User.idp and User.mfa_phone.
Devices are matched by name, computers only: a phone called "iPhone" must never land on someone's laptop."""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.okta")
COMPUTERS = {"WINDOWS": "Windows", "MACOS": "macOS"}
# Okta keeps every phone and long-retired device; ask for live computers only. With expand=user Okta pages 20 at a time.
DEVICE_SEARCH = 'status eq "ACTIVE" and (profile.platform eq "WINDOWS" or profile.platform eq "MACOS")'
LIVE_DEVICE = ("ACTIVE",)
FACTOR_TTL = timedelta(days=7)      # MFA enrollments don't change often; re-read each person's weekly
NEW_DEVICE_DAYS = 90                # only add a computer CTEM has never seen when Okta heard from it lately
_CHUNK = 500
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._'-]{0,127}$")
_PHONE = re.compile(r"^\+?[0-9 ().-]{7,24}$")


@dataclass
class People:
    """Okta user id -> what we learned, and the CTEM user id it matched (None when no directory user has it)."""
    by_okta: dict[str, dict] = field(default_factory=dict)
    on_devices: set[str] = field(default_factory=set)   # Okta ids signed in on a computer
    conflicts: list[str] = field(default_factory=list)   # names claimed by computers with different serial numbers
    skipped: set[str] = field(default_factory=set)       # names CTEM holds for a server or other non-computer
    devices_pulled: bool = False                          # the slow device pull ran this sync


def when(s) -> datetime | None:
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")) if s else None
    except ValueError:
        return None


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _clean(v, n: int = 128) -> str | None:
    v = str(v or "").strip()
    return v[:n] if v and not any(ord(c) < 32 for c in v) and not re.search(r"[<>]", v) else None


def _phone(v) -> str | None:
    v = _clean(v, 32)
    return v if v and _PHONE.match(v) else None


def _match(index, login: str) -> tuple[str | None, bool]:
    """(directory user id, matched by the full UPN). Only the UPN, or a bare name the directory user has no UPN
    for: tim@partner.example must never land on the directory's tim (checked once the rows are loaded)."""
    from api.core.encryption import search_hash
    from api.core.user_match import bare
    uid = index.upns.get(search_hash(login.strip().lower()))
    if uid:
        return uid, True
    return index.ids.get(bare(login)), False


async def users(conn, client, db: AsyncSession) -> People:
    """Every Okta user (Okta's list leaves out deprovisioned ones), matched to directory users by UPN."""
    from collections import Counter

    from api.core.user_match import UserIndex
    from api.models.user import User
    index, people = await UserIndex.load(db), People()
    async for u in conn.pages("/api/v1/users?limit=200", client):
        p, oid = u.get("profile") or {}, str(u.get("id") or "")
        login = _clean(p.get("login"), 256)
        if not oid or not login:
            continue
        uid, by_upn = _match(index, login)
        people.by_okta[oid] = {"uid": uid, "by_upn": by_upn, "login": login, "status": _clean(u.get("status"), 32),
                               "last_login": when(u.get("lastLogin")), "password_changed": when(u.get("passwordChanged")),
                               "profile": p}
    ids = [v["uid"] for v in people.by_okta.values() if v["uid"]]
    rows: dict[str, User] = {}
    for i in range(0, len(ids), _CHUNK):
        for r in (await db.execute(select(User).where(User.id.in_(ids[i:i + _CHUNK])))).scalars():
            rows[r.id] = r
    claimed = Counter(v["uid"] for v in people.by_okta.values() if v["uid"])
    for v in people.by_okta.values():
        user = rows.get(v["uid"])
        # never a local break-glass account, a bare-name match on someone who has a UPN, or a person two Okta
        # accounts both claim (whose phone would we keep?)
        if (user is None or user.is_local or claimed[v["uid"]] > 1
                or (not v["by_upn"] and user.upn and user.upn.lower() != v["login"].lower())):
            v["uid"] = None
            continue
        merge_user(user, v)
    await db.commit()
    return people


def merge_user(user, v: dict) -> None:
    """Okta's account facts into User.idp; profile fields only where the directory left a gap."""
    from api.core.config import get_settings
    from api.core.phone import normalize
    p, region = v["profile"], get_settings().phone_default_region
    old = dict(user.idp or {})
    user.idp = {**old, "source": "okta", "status": v["status"], "last_login": _iso(v["last_login"]),
                "password_changed": _iso(v["password_changed"])}
    for col, key in (("title", "title"), ("department", "department"), ("first_name", "firstName"),
                     ("last_name", "lastName"), ("city", "city"), ("state", "state")):
        if not getattr(user, col) and _clean(p.get(key)):
            setattr(user, col, _clean(p.get(key)))
    for col, key in (("mobile", "mobilePhone"), ("phone", "primaryPhone")):
        raw = _phone(p.get(key))
        if not getattr(user, col) and raw:
            setattr(user, col, normalize(raw, p.get("countryCode"), region) or raw)
    if not user.display_name and _clean(p.get("displayName")):
        user.display_name = _clean(p.get("displayName"))


def _owner(embedded: list) -> tuple[str | None, list[str]]:
    """(the Okta id of who uses it: the newest active enrollment, every signed-in login)."""
    live = [e for e in embedded if (e.get("user") or {}).get("status") in ("ACTIVE", "PASSWORD_EXPIRED", "LOCKED_OUT", "RECOVERY")]
    live.sort(key=lambda e: str(e.get("created") or ""), reverse=True)
    logins = [_clean((e.get("user") or {}).get("profile", {}).get("login"), 256) for e in embedded]
    return (str(live[0]["user"].get("id")) if live else None), [x for x in logins if x][:10]


def device_record(d: dict) -> dict | None:
    """The fields CTEM keeps from one Okta device, or None when it isn't a live computer."""
    p = d.get("profile") or {}
    name = _clean(p.get("displayName"), 63)
    if d.get("status") not in LIVE_DEVICE or p.get("platform") not in COMPUTERS or not name or not _NAME.match(name):
        return None
    emb = (d.get("_embedded") or {}).get("users") or []
    owner, logins = _owner(emb)
    first = emb[0] if emb else {}
    return {"name": name, "okta_id": _clean(d.get("id"), 40), "status": d.get("status"), "platform": COMPUTERS[p["platform"]],
            "os_version": _clean(p.get("osVersion"), 64), "manufacturer": _clean(p.get("manufacturer"), 64),
            "model": _clean(p.get("model"), 64), "serial": _clean(p.get("serialNumber"), 64),
            "disk_encryption": _clean(p.get("diskEncryptionType"), 32), "secure_hardware": p.get("secureHardwarePresent"),
            "managed": first.get("managementStatus") == "MANAGED" if first else None,
            "screen_lock": _clean(first.get("screenLockType"), 32) if first else None,
            "registered": _iso(when(d.get("created"))), "updated": _iso(when(d.get("lastUpdated"))),
            "owner_okta": owner, "logins": logins}


async def devices(conn, client, db: AsyncSession, people: People) -> int:
    """Okta's computers onto CTEM's devices: who uses each one, and its posture as Okta Verify saw it."""
    from api.core.device_match import host_key
    from urllib.parse import quote
    best: dict[str, dict] = {}
    serials: dict[str, set] = {}
    async for d in conn.pages(f"/api/v1/devices?limit=200&expand=user&search={quote(DEVICE_SEARCH)}", client, max_pages=10000):
        rec = device_record(d)
        key = host_key(rec["name"]) if rec else None
        if key:
            serials.setdefault(key, set()).add((rec["serial"] or "").upper())
        if key and (key not in best or str(rec["updated"]) > str(best[key]["updated"])):
            best[key] = rec   # a re-registered machine: the newest record wins
    # Okta Verify names a device by its own hostname, which its user can change: two live computers with one
    # name but different serial numbers can't both be that host, so neither is applied (people review them)
    people.conflicts = sorted(best[k]["name"] for k, v in serials.items() if len(v) > 1)
    recs = [r for k, r in best.items() if len(serials[k]) == 1]
    people.devices_pulled = True
    for r in recs:
        if r["owner_okta"]:
            people.on_devices.add(r["owner_okta"])
    await _ensure_owners(db, people)
    count = 0
    for i in range(0, len(recs), _CHUNK):
        count += await _apply(conn, db, recs[i:i + _CHUNK], people)
        await db.commit()
    return count


async def device_owners(db: AsyncSession, people: People) -> None:
    """Between device pulls: the people on computers, read back from what the last pull saved, so their MFA
    factors are still read first."""
    from api.models.device import Device
    by_login = {v["login"].lower(): oid for oid, v in people.by_okta.items()}
    for (rec,) in (await db.execute(select(Device.idp_device).where(Device.sources.like("%,okta,%")))).all():
        for login in (rec or {}).get("logins") or []:
            oid = by_login.get(str(login).lower())
            if oid:
                people.on_devices.add(oid)


async def _apply(conn, db: AsyncSession, recs: list[dict], people: People) -> int:
    from api.core.device_match import add_source, find_devices
    from api.models.device import Device, DeviceType
    found = await find_devices(db, [r["name"] for r in recs])
    for name, dev in list(found.items()):   # computers people use, never a server or a network device of that name
        if dev.device_type not in (DeviceType.workstation, DeviceType.unknown):
            people.skipped.add(name)
    fresh = datetime.now(timezone.utc) - timedelta(days=NEW_DEVICE_DAYS)
    create = str(conn.config.get("create_devices", "")).lower() in ("true", "1", "on", "yes")
    n = 0
    for r in recs:
        dev = found.get(r["name"])
        if r["name"] in people.skipped:
            continue
        if dev is None:
            if not create or (when(r["updated"]) or fresh) < fresh or r["status"] != "ACTIVE":
                continue
            dev = Device(hostname=r["name"], device_type=DeviceType.workstation, source="okta")
            db.add(dev)
        add_source(dev, "okta")
        owner = (people.by_okta.get(r["owner_okta"] or "") or {}).get("uid")
        prev = dev.idp_device or {}
        # The EDR's sign-in history names the user when it has one; Okta fills in when it doesn't, and keeps
        # the owner it set up to date
        mine = prev.get("owner_from_idp") or dev.owner_user_id is None
        if owner and mine and not (dev.last_login_user or dev.recent_logins):
            dev.owner_user_id = owner
        dev.idp_device = {k: v for k, v in r.items() if k != "owner_okta"} | {
            "source": "okta", "owner_from_idp": bool(owner and mine and dev.owner_user_id == owner)}
        if not dev.os:
            dev.os = f"{r['platform']} {r['os_version'] or ''}".strip()[:128]
        n += 1
    return n


async def _ensure_owners(db: AsyncSession, people: People) -> None:
    """A person signed in on a computer but missing from the directory feed still needs a user to own it."""
    from api.core.accounts import same_name
    from api.core.encryption import search_hash
    from api.models.user import User
    need = [o for o in people.on_devices if o in people.by_okta and not people.by_okta[o]["uid"]
            and people.by_okta[o]["status"] in ("ACTIVE", "PASSWORD_EXPIRED", "LOCKED_OUT", "RECOVERY")]
    for oid in need:
        v = people.by_okta[oid]
        p = v["profile"]
        name = _clean(p.get("sam"), 128) or v["login"].split("@", 1)[0]
        if not _USERNAME.match(name or ""):
            continue
        taken = (await db.execute(select(User).where(same_name(name)))).scalars().first()
        if taken is not None:
            continue   # someone else's name; don't guess
        user = User(username=name, is_local=False, is_active=True)
        if "@" in v["login"]:
            user.upn, user.upn_hash = v["login"], search_hash(v["login"].lower())
        email = _clean(p.get("email"), 256)
        if email and "@" in email:
            user.email, user.email_hash = email, search_hash(email)
        merge_user(user, v)
        db.add(user)
        await db.flush()
        v["uid"] = user.id
    await db.commit()


def factor_summary(factors: list) -> dict:
    """Which factors are enrolled, and the phone the SMS (else voice) factor reaches. Factor device names and
    credential ids stay in Okta."""
    live = [f for f in factors if isinstance(f, dict) and f.get("status") == "ACTIVE"]
    kinds = sorted({str(f.get("factorType"))[:40] for f in live if f.get("factorType")})
    phone, kind = None, None
    for want in ("sms", "call"):
        for f in live:
            if f.get("factorType") == want and _phone((f.get("profile") or {}).get("phoneNumber")):
                phone, kind = _phone(f["profile"]["phoneNumber"]), want
                break
        if phone:
            break
    return {"factors": kinds, "mfa_phone": phone, "mfa_phone_kind": kind}


async def factors(conn, client, db: AsyncSession, people: People) -> int:
    """MFA enrollments, people on computers first, each refreshed at most weekly, within a per-sync budget."""
    from api.models.user import User
    budget = max(0, min(20000, int(conn.config.get("factor_budget") or 3000)))
    uids = {v["uid"]: oid for oid, v in people.by_okta.items() if v["uid"] and v["status"] != "DEPROVISIONED"}
    ids = list(uids)
    rows: dict[str, User] = {}
    for i in range(0, len(ids), _CHUNK):
        for r in (await db.execute(select(User).where(User.id.in_(ids[i:i + _CHUNK])))).scalars():
            rows[r.id] = r
    stale = datetime.now(timezone.utc) - FACTOR_TTL
    due = [u for u in rows.values() if (when((u.idp or {}).get("factors_at")) or datetime.min.replace(tzinfo=timezone.utc)) < stale]
    due.sort(key=lambda u: (uids[u.id] not in people.on_devices, str((u.idp or {}).get("factors_at") or "")))
    due = due[:budget]
    sem, done = asyncio.Semaphore(4), 0

    async def one(user):
        from api.integrations.okta import OktaError
        async with sem:
            try:
                body, _ = await conn.fetch(f"/api/v1/users/{uids[user.id]}/factors", client)
            except OktaError:
                return user, None   # this person waits for the next sync; the rest carry on
        return user, factor_summary(body if isinstance(body, list) else [])

    failed = 0
    for i in range(0, len(due), 100):
        for user, s in await asyncio.gather(*(one(u) for u in due[i:i + 100])):
            if s is None:
                failed += 1
                continue
            user.mfa_phone = s["mfa_phone"]
            user.idp = {**(user.idp or {}), "factors": s["factors"], "mfa_phone_kind": s["mfa_phone_kind"],
                        "factors_at": datetime.now(timezone.utc).isoformat()}
            done += 1
        await db.commit()
    if failed:
        conn.warnings.append(f"MFA factors couldn't be read for {failed} people this run; they're retried next sync")
    if len(due) == budget and budget:
        conn.warnings.append(f"read MFA factors for {budget} people this run; the rest follow on later syncs")
    return done
