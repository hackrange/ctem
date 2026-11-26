"""Persona inquiries into IdvRequest rows (api/models/idv.py), keeping only the approved facts.

States: Persona's created and pending are "pending" (the person hasn't finished); completed and approved are
"approved"; declined is "rejected"; expired is "expired". A failed or needs-review inquiry is "review": it waits
for cyber to approve or decline it on CTEM's IDV page. A failed one nobody reviewed within REVIEW_DAYS lapses to
"rejected", so the review queue holds what is current, not years of history. A failed check followed by a pass that
verified a government ID (or an approver approved) is "superseded": nothing is left to decide, so it leaves the queue,
and goes back if that pass goes. A later selfie-only pass is not enough: it compares a face with an earlier selfie,
not with an ID. The badge likewise needs a government ID the person passed at some point, and a revoke
(User.idv_revoked_at) sets every pass before it aside until the person verifies again."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.persona")
REVIEW_DAYS = 30
FACTS_V = 3   # bumped when what is read from an inquiry changes, so rows read before are read again once
FINAL = ("approved", "rejected", "expired", "superseded")
_COUNTRY = re.compile(r"^[A-Z]{2}$")
_REGION = re.compile(r"^[A-Za-z0-9 .\-]{1,40}$")
_WORD = re.compile(r"^[A-Za-z0-9 _.\-]{1,40}$")
_OKTA = re.compile(r"^[A-Za-z0-9]{10,40}$")
_TEMPLATE = re.compile(r"^(itmpl|tmpl)_[A-Za-z0-9]{8,40}$")
ID_CLASS = {"dl": "Driver's license", "pp": "Passport", "id": "National ID card", "rp": "Residence permit",
            "pr": "Permanent residence card", "visa": "Visa", "mil": "Military ID", "wp": "Work permit",
            "ppc": "Passport card", "tribal": "Tribal ID", "nric": "National ID card", "myn": "National ID card",
            "cid": "Consular ID", "keyp": "Proof of age card", "ipp": "Internal passport"}


def when(value) -> datetime | None:
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
    except ValueError:
        return None
    return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)


def state_of(status: str, created: datetime | None, now: datetime) -> str:
    s = (status or "").lower()
    if s in ("completed", "approved"):
        return "approved"
    if s == "declined":
        return "rejected"
    if s == "expired":
        return "expired"
    if s == "needs_review":
        return "review"
    if s == "failed":
        return "review" if created is None or now - created <= timedelta(days=REVIEW_DAYS) else "rejected"
    return "pending"


def _field(fields: dict, *names: str) -> str | None:
    """A field's value by name; Persona sends names with dashes (Key-Inflection: kebab), so either spelling works."""
    for n in names:
        f = fields.get(n) if isinstance(fields.get(n), dict) else fields.get(n.replace("_", "-"))
        v = f.get("value") if isinstance(f, dict) else None
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def id_facts(attrs: dict) -> dict:
    """Where the ID is from and what kind it is. Everything else in "fields" (names, birth date, ID number,
    address, photos) is never copied."""
    f = attrs.get("fields") if isinstance(attrs.get("fields"), dict) else {}
    out = {}
    country = (_field(f, "selected_country_code", "address_country_code") or "").upper()
    if _COUNTRY.match(country):
        out["country"] = country
    region = _field(f, "address_subdivision")
    if region and _REGION.match(region):
        out["region"] = region[:40]
    cls = (_field(f, "selected_id_class", "identification_class") or "").lower()
    if cls and _WORD.match(cls):
        out["id_class"] = cls
        out["id_type"] = ID_CLASS.get(cls, cls.upper())
    return out


DETAIL_V = 2
# checks started before CTEM read verifications count as before until their detail is read; later ones need it
LEGACY_BEFORE = datetime(2026, 11, 27, tzinfo=timezone.utc)   # what one inquiry's detail read gathers; bumped to read every inquiry's detail again


def detail_params() -> dict:
    """One inquiry's sessions and verifications, with only the approved attributes of each (sparse fieldsets)."""
    from api.integrations.persona import SESSION_FIELDS
    from api.integrations.persona_checks import VERIFICATION_FIELDS
    return {"include": "sessions,verifications", "fields[inquiry]": "status", "fields[inquiry-session]": SESSION_FIELDS,
            **{f"fields[{k}]": v for k, v in VERIFICATION_FIELDS.items()}}


def detail_facts(facts: dict | None, included: list, now: datetime) -> dict:
    """The device and network, and what was verified: the ID's type and country come from the latest government ID
    the person presented when the inquiry's own fields don't carry them (Okta's templates don't)."""
    from api.integrations.persona_checks import verification_facts
    vs = verification_facts(included)
    out = {**(facts or {}), **session_facts(included), "verifications": vs, "detail": DETAIL_V, "detail_at": now.isoformat()}
    ids = [v for v in vs if v["kind"].startswith("government-id")]
    best = ([v for v in ids if v.get("status") == "passed"] or ids)[-1:] if ids else []
    for v in best:
        for k in ("country", "id_class", "id_type"):
            if v.get(k) and not out.get(k):
                out[k] = v[k]
    return out


def session_facts(included: list) -> dict:
    """The newest session's device and network: type, OS and browser names, the risk flags, Persona's threat level.
    Never the IP address, GPS position, ISP or user agent."""
    ss = [x for x in included or [] if isinstance(x, dict) and x.get("type") == "inquiry-session"]
    if not ss:
        return {}
    a = max(ss, key=lambda x: str((x.get("attributes") or {}).get("created-at") or "")).get("attributes") or {}
    out = {}
    for key, col in (("device-type", "device_type"), ("os-name", "os"), ("browser-name", "browser"), ("threat-level", "threat_level")):
        v = a.get(key)
        if isinstance(v, str) and _WORD.match(v):
            out[col] = v[:40]
    for key, col in (("is-vpn", "vpn"), ("is-proxy", "proxy"), ("is-tor", "tor"), ("is-datacenter", "datacenter")):
        if isinstance(a.get(key), bool):
            out[col] = a[key]
    return out


async def _templates(conn, client) -> dict:
    out = {}
    async for t in conn.pages("/api/v1/inquiry-templates", client, {}, 5):
        tid, name = str(t.get("id") or ""), str((t.get("attributes") or {}).get("name") or "")
        if _TEMPLATE.match(tid):
            out[tid] = name[:256]
    return out


def _template_id(item: dict) -> str | None:
    rel = (item.get("relationships") or {})
    for key in ("inquiry-template", "template"):
        tid = str(((rel.get(key) or {}).get("data") or {}).get("id") or "")
        if _TEMPLATE.match(tid):
            return tid
    return None


def apply(row, item: dict, templates: dict, now: datetime) -> bool:
    """Persona's view of one inquiry onto its row; True when something that matters changed."""
    a = item.get("attributes") or {}
    created = when(a.get("created-at"))
    status = str(a.get("status") or "")[:32]
    before = (row.persona_status, row.state)
    row.persona_status = status
    # a cyber decision in CTEM stands until Persona reports its own (the approve or decline lands there too)
    row.state = state_of(status, created, now)
    ref = str(a.get("reference-id") or "")
    new_ref = ref if _OKTA.match(ref) else None
    if new_ref != row.okta_id:
        row.okta_id, row.user_id = new_ref, None   # relinked by link_people
    tid = _template_id(item)
    row.template_id = tid or row.template_id
    row.template = templates.get(tid or "", row.template)
    creator = a.get("creator")
    if isinstance(creator, str) and creator:
        row.created_via = "API" if creator == "API" else "other"   # never an email address
    row.created_at = created or row.created_at
    row.updated_at = when(a.get("updated-at")) or row.updated_at
    row.completed_at = when(a.get("completed-at")) or row.completed_at
    row.decided_at = when(a.get("decisioned-at")) or when(a.get("failed-at")) or when(a.get("expired-at")) or row.decided_at
    row.expires_at = when(a.get("expires-at")) or row.expires_at
    row.facts = {**(row.facts or {}), **id_facts(a), "v": FACTS_V}
    row.synced_at = now
    return before != (row.persona_status, row.state)


async def sync(conn, client, db: AsyncSession, max_pages: int, detail_budget: int) -> int:
    from api.integrations.persona import INQUIRY_FIELDS
    from api.models.idv import IdvRequest
    now = datetime.now(timezone.utc)
    templates = await _templates(conn, client)
    # this integration's rows only: a second Persona integration (another tenant) never touches them
    mine = IdvRequest.integration_id == conn.integration_id if conn.integration_id else IdvRequest.integration_id.is_(None)
    known = {r.inquiry_id: r for r in (await db.execute(select(IdvRequest).where(mine))).scalars()}
    # inquiry ids another integration already holds (inquiry_id is unique): left to that integration
    taken = {i for (i,) in (await db.execute(select(IdvRequest.inquiry_id).where(~mine))).all()}
    seen, fresh, n, quiet = set(), [], 0, 0
    params = {"fields[inquiry]": INQUIRY_FIELDS}
    async for item in conn.pages("/api/v1/inquiries", client, params, max_pages):
        iid = str(item.get("id") or "")
        if not re.fullmatch(r"inq_[A-Za-z0-9]{8,40}", iid):
            continue
        seen.add(iid)
        row = known.get(iid)
        if iid in taken:
            continue
        if row is None:
            row = IdvRequest(inquiry_id=iid, integration_id=conn.integration_id, origin="persona")
            db.add(row)
            known[iid] = row
            apply(row, item, templates, now)
            changed, quiet = True, 0
        elif (row.state in FINAL and row.persona_status == str((item.get("attributes") or {}).get("status") or "")
              and (row.facts or {}).get("v") == FACTS_V):
            changed, quiet = False, quiet + 1      # settled, and Persona says the same
        else:
            changed, quiet = apply(row, item, templates, now), 0
        if changed:
            fresh.append(row)
        n += 1
        if quiet >= 300:   # a long run of settled inquiries we already have: the rest is older history
            break
    # still open in CTEM but not on the pages read: ask Persona about them by id, 100 at a time
    open_ids = [i for i, r in known.items() if r.state in ("pending", "review") and i not in seen]
    for k in range(0, len(open_ids), 100):
        async for item in conn.pages("/api/v1/inquiries", client, {**params, "filter[inquiry-id]": ",".join(open_ids[k:k + 100])}, 1):
            row = known.get(str(item.get("id") or ""))
            if row is not None and apply(row, item, templates, now):
                fresh.append(row)
    # the device and network each new or changed check ran on (one call each, so a budget per sync)
    fresh += [r for r in known.values() if r not in fresh and (r.facts or {}).get("detail") != DETAIL_V]   # not read yet
    for row in fresh[:detail_budget]:
        try:
            body = await conn.request("GET", f"/api/v1/inquiries/{row.inquiry_id}", client, detail_params())
        except Exception as e:  # noqa: BLE001 -- the facts come next sync
            log.warning("Persona inquiry detail failed: %s", type(e).__name__)
            continue
        row.facts = detail_facts(row.facts, body.get("included") or [], now)
    await db.flush()
    await link_people(db)
    await db.commit()
    return n


def _trusted(config: dict) -> dict:
    ids = {t.strip() for t in str(config.get("badge_templates") or "").split(",") if _TEMPLATE.match(t.strip())}
    return {"templates": ids}


async def trusted_by_integration(db: AsyncSession) -> dict:
    from api.models.integration import IntegrationConfig, Vendor
    rows = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.vendor == Vendor.persona))).scalars().all()
    return {str(c.id): _trusted(c.config or {})["templates"] for c in rows}


async def link_people(db: AsyncSession) -> None:
    """Each request to its person by Okta id, and each person's latest pass for the IDV badge.
    A pass counts only when an API key started the inquiry (Okta's integration or CTEM's service desk) and, where the
    integration names trusted templates, it used one of them. An Okta id two people share links to nobody."""
    from collections import Counter

    from api.models.idv import IdvRequest
    from api.models.user import User
    rows = (await db.execute(select(IdvRequest).where(IdvRequest.okta_id.is_not(None)))).scalars().all()
    ids = sorted({r.okta_id for r in rows})
    found = []
    for k in range(0, len(ids), 1000):
        found += (await db.execute(select(User.id, User.okta_id).where(User.okta_id.in_(ids[k:k + 1000])))).all()
    twice = Counter(oid for _, oid in found)
    owner = {oid: uid for uid, oid in found if twice[oid] == 1}
    for r in rows:
        want = owner.get(r.okta_id)
        if r.user_id != want:
            r.user_id = want
    await db.flush()
    trusted = await trusted_by_integration(db)
    from api.integrations.persona_checks import gov_id_passed
    users = sorted({r.user_id for r in rows if r.user_id})
    revoked: dict = {}
    for k in range(0, len(users), 1000):   # locked: a revoke committing meanwhile waits, or is seen (no stale write-back)
        revoked.update({uid: at for uid, at in (await db.execute(select(User.id, User.idv_revoked_at).where(
            User.id.in_(users[k:k + 1000])).order_by(User.id).with_for_update())).all() if at is not None})
    tz = lambda d: d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)  # noqa: E731
    after = lambda r: r.created_at is not None and (r.user_id not in revoked or tz(r.created_at) > tz(revoked[r.user_id]))  # noqa: E731
    def trusted_pass(r) -> bool:
        """Approved, after any revoke, started by an API key (Okta's integration or the service desk) with a trusted
        template, or approved by an approver."""
        if r.state != "approved" or r.user_id is None or not after(r):
            return False
        if r.reviewed_by:
            return True
        if r.origin != "service_desk" and r.created_via != "API":
            return False
        names = trusted.get(r.integration_id or "") or set()
        return not names or r.template_id in names

    def gov(r) -> bool:
        """A government ID passed in this check. Not read yet: only checks from before CTEM read verifications count."""
        g = gov_id_passed(r.facts)
        return g if g is not None else (r.created_at is not None and tz(r.created_at) < LEGACY_BEFORE)

    # a trusted pass with a government ID (since any revoke): a later selfie-only re-check builds on it, nothing else does
    gov_ok = {r.user_id for r in rows if trusted_pass(r) and gov(r)}

    from api.integrations.persona_checks import id_and_face

    def counts(r) -> bool:
        if not trusted_pass(r):
            return False
        if r.reviewed_by:
            return True   # an approver's decision
        if r.user_id in revoked:   # after a revoke or expire: a government ID and a face that matches it, in one check
            return id_and_face(r.facts)
        return gov(r) or r.user_id in gov_ok

    latest: dict = {}
    proven: dict = {}   # the latest pass that verified a government ID itself, or an approver approved
    for r in rows:
        if not counts(r):
            continue
        at = r.completed_at or r.decided_at or r.created_at
        if at and (r.user_id not in latest or at > latest[r.user_id]):
            latest[r.user_id] = at
        if at and (r.reviewed_by or gov_id_passed(r.facts)) and (r.user_id not in proven or at > proven[r.user_id]):
            proven[r.user_id] = at
    for u in (await db.execute(select(User).where(User.idv_verified_at.is_not(None)))).scalars():
        if u.id not in latest:
            u.idv_verified_at = None
    ids = list(latest)
    for k in range(0, len(ids), 1000):
        for u in (await db.execute(select(User).where(User.id.in_(ids[k:k + 1000])))).scalars():
            if u.idv_verified_at != latest[u.id]:
                u.idv_verified_at = latest[u.id]
    now = datetime.now(timezone.utc)
    for r in rows:   # a failure the person has since passed with a government ID needs no decision; a selfie isn't enough
        passed = r.user_id in proven and r.created_at is not None and proven[r.user_id] > r.created_at
        if r.state == "review" and passed:
            r.state = "superseded"
        elif r.state == "superseded" and not passed:
            r.state = state_of(r.persona_status or "", r.created_at, now)
