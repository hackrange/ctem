"""Who holds which app at the identity provider and when they last signed in to it (IdpAppAccess). Each person's app
list (their Okta dashboard apps) is read weekly, in batches within a per-sync budget like the MFA factors. Sign-ins
come from the System Log's SSO events, caught up 90 days back a few pages per sync."""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.integrations.okta_ingest import People, _clean, when

log = logging.getLogger("open-ctem.okta")
SOURCE = "okta"
APP_TTL = timedelta(days=7)
SSO_BACK = timedelta(days=90)      # all Okta keeps
SSO_PAGES = 150                    # up to 150,000 sign-ins a sync while catching up
_ID = re.compile(r"^[A-Za-z0-9]{10,40}$")
SSO_FILTER = quote('eventType eq "user.authentication.sso"')
_CHUNK = 500


def app_links(body) -> dict[str, dict]:
    """app instance id -> its label, kind and hidden flag, from one person's app list."""
    out: dict[str, dict] = {}
    for a in body if isinstance(body, list) else []:
        aid = str(a.get("appInstanceId") or "") if isinstance(a, dict) else ""
        if _ID.match(aid):
            out[aid] = {"label": _clean(a.get("label"), 256), "name": _clean(a.get("appName"), 128),
                        "hidden": a["hidden"] if isinstance(a.get("hidden"), bool) else None}
    return out


async def _rows(db: AsyncSession, uids: list[str]) -> dict[tuple[str, str], object]:
    from api.models.identity import IdpAppAccess
    have = {}
    for i in range(0, len(uids), _CHUNK):
        for r in (await db.execute(select(IdpAppAccess).where(IdpAppAccess.source == SOURCE,
                                                              IdpAppAccess.user_id.in_(uids[i:i + _CHUNK])))).scalars():
            have[(r.app_id, r.user_id)] = r
    return have


async def assignments(conn, client, db: AsyncSession, people: People) -> int:
    """Each person's apps, refreshed at most weekly, oldest first, within app_budget people per sync."""
    from api.integrations.okta import OktaError
    from api.models.identity import IdpAppAccess
    from api.models.user import User
    budget = max(0, min(20000, int(conn.config.get("app_budget") or 3000)))
    oids = {v["uid"]: oid for oid, v in people.by_okta.items() if v["uid"] and v["status"] == "ACTIVE"}
    ids, users = list(oids), {}
    for i in range(0, len(ids), _CHUNK):
        for u in (await db.execute(select(User).where(User.id.in_(ids[i:i + _CHUNK])))).scalars():
            users[u.id] = u
    stale = datetime.now(timezone.utc) - APP_TTL
    due = [u for u in users.values() if (when((u.idp or {}).get("apps_at")) or datetime.min.replace(tzinfo=timezone.utc)) < stale]
    due.sort(key=lambda u: str((u.idp or {}).get("apps_at") or ""))
    due = due[:budget]
    sem, done, failed = asyncio.Semaphore(4), 0, 0

    async def one(user):
        async with sem:
            try:
                body, _ = await conn.fetch(f"/api/v1/users/{oids[user.id]}/appLinks", client)
            except OktaError:
                return user, None   # this person waits for the next sync
        return user, app_links(body)

    for i in range(0, len(due), 100):
        got = await asyncio.gather(*(one(u) for u in due[i:i + 100]))
        have = await _rows(db, [u.id for u, links in got if links is not None])
        now = datetime.now(timezone.utc)
        for user, links in got:
            if links is None:
                failed += 1
                continue
            for aid, a in links.items():
                row = have.get((aid, user.id))
                if row is None:
                    row = IdpAppAccess(source=SOURCE, app_id=aid, user_id=user.id)
                    db.add(row)
                row.app_label, row.app_name, row.hidden = a["label"] or row.app_label, a["name"], a["hidden"]
                row.assigned, row.seen_at = True, now
            for (aid, uid), row in have.items():
                if uid == user.id and aid not in links:   # access removed: keep the sign-in history, else drop it
                    if row.last_sign_in is None:
                        await db.delete(row)
                    else:
                        row.assigned = False
            user.idp = {**(user.idp or {}), "apps_at": now.isoformat(), "apps": len(links)}
            done += 1
        await db.commit()
    if failed:
        conn.warnings.append(f"app lists couldn't be read for {failed} people this run; they're retried next sync")
    if len(due) == budget and budget:
        conn.warnings.append(f"read app lists for {budget} people this run; the rest follow on later syncs")
    return done


def sso_event(e: dict, by_login: dict[str, str]) -> tuple[str, str, datetime, str | None] | None:
    """(app id, user id, when, app label) for one successful SSO into an app by a known person."""
    if not isinstance(e, dict) or (e.get("outcome") or {}).get("result") != "SUCCESS":
        return None
    uid = by_login.get(str((e.get("actor") or {}).get("alternateId") or "").lower())
    app = next((t for t in e.get("target") or [] if isinstance(t, dict) and t.get("type") == "AppInstance"), None)
    at = when(e.get("published"))
    if not uid or not app or not _ID.match(str(app.get("id") or "")) or at is None:
        return None
    return str(app["id"]), uid, at, _clean(app.get("displayName"), 256)


async def sign_ins(conn, client, db: AsyncSession, people: People) -> int:
    """The newest SSO sign-in per person per app since the last sync (at most 90 days back, SSO_PAGES a sync)."""
    from api.integrations.base import load_sync_state, save_sync_state
    from api.integrations.okta import OktaError
    from api.models.identity import IdpAppAccess
    state = await load_sync_state(db, conn.integration_id)
    floor = datetime.now(timezone.utc) - SSO_BACK
    since = max(when(state.get("sso_since")) or floor, floor)
    by_login = {v["login"].lower(): v["uid"] for v in people.by_okta.values() if v["uid"]}
    url = (f"/api/v1/logs?since={quote(since.strftime('%Y-%m-%dT%H:%M:%S.000Z'))}&limit=1000&sortOrder=ASCENDING"
           f"&filter={SSO_FILTER}")
    latest: dict[tuple[str, str], tuple[datetime, str | None]] = {}
    newest = since
    try:
        for _ in range(SSO_PAGES):
            body, url = await conn.fetch(url, client)
            for e in body if isinstance(body, list) else []:
                hit = sso_event(e, by_login)
                at = when(e.get("published")) if isinstance(e, dict) else None
                newest = max(newest, at) if at else newest
                if hit and (hit[:2] not in latest or hit[2] > latest[hit[:2]][0]):
                    latest[hit[:2]] = (hit[2], hit[3])
            if not body or not url:
                break   # caught up (Okta's log hands out a next link to poll; an empty page means we're current)
    except OktaError as e:   # keep what was read; the next sync carries on from there
        conn.warnings.append(f"app sign-ins stopped early ({e}); the next sync carries on")
    have = await _rows(db, list({uid for _, uid in latest}))
    for (aid, uid), (at, label) in latest.items():
        row = have.get((aid, uid))
        if row is None:
            row = IdpAppAccess(source=SOURCE, app_id=aid, user_id=uid, app_label=label, assigned=False)
            db.add(row)
            have[(aid, uid)] = row
        last = row.last_sign_in
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if last is None or at > last:
            row.last_sign_in = at
        row.app_label = row.app_label or label
    await db.commit()
    await save_sync_state(db, conn.integration_id, {**(await load_sync_state(db, conn.integration_id)), "sso_since": newest.isoformat()})
    return len(latest)
