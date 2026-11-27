"""Okta's signals: posture findings (people with weak or no MFA, computers without disk encryption or without an EDR)
and the System Log's security events as identity threats. Both land on the Identity page beside the other feeds."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.integrations.okta_ingest import People, when

log = logging.getLogger("open-ctem.okta")
SOURCE = "okta"
STRONG = {"push", "signed_nonce", "webauthn", "u2f", "token:software:totp", "token:hardware", "token", "token:hotp"}
PHONE = {"sms", "call"}
ACTIVE_DAYS = 90
# System Log event -> (threat type, severity, MITRE technique). All are reads of Okta's own detections.
EVENTS = {
    "security.threat.detected": ("brute_force", "medium", "T1110"),
    "user.mfa.okta_verify.deny_push": ("mfa_fatigue", "medium", "T1621"),
    "user.account.report_suspicious_activity_by_enduser": ("account_takeover", "high", "T1078"),
    "security.breached_credential.detected": ("credential_compromise", "high", "T1078"),
    "user.account.lock": ("brute_force", "low", "T1110"),
    "user.account.privilege.grant": ("privilege_escalation", "medium", "T1098"),
    "user.session.impersonation.initiate": ("anomalous_access", "high", "T1078"),
    "user.mfa.factor.reset_all": ("mfa_bypass", "medium", "T1556"),
}
LOOKBACK = timedelta(days=7)
_MAX_LOG_PAGES = 50


def _names(rows, n: int = 25) -> str:
    rows = sorted(rows)
    return ", ".join(rows[:n]) + (f" and {len(rows) - n} more" if len(rows) > n else "")


async def posture(conn, db: AsyncSession, people: People) -> int:
    from api.models.device import Device
    from api.models.user import User
    recent = datetime.now(timezone.utc) - timedelta(days=ACTIVE_DAYS)
    ids = [v["uid"] for v in people.by_okta.values() if v["uid"] and v["status"] == "ACTIVE"
           and (v["last_login"] or datetime.min.replace(tzinfo=timezone.utc)) >= recent]
    none, phone_only, read = [], [], 0
    for i in range(0, len(ids), 500):
        for u in (await db.execute(select(User).where(User.id.in_(ids[i:i + 500])))).scalars():
            f = (u.idp or {}).get("factors")
            if f is None:
                continue   # not read yet
            read += 1
            kinds = set(f)
            if not kinds & (STRONG | PHONE):
                none.append(u.id)
            elif not kinds & STRONG:
                phone_only.append(u.id)
    devs = (await db.execute(select(Device).where(Device.sources.like("%,okta,%")))).scalars().all()
    plain = [d.hostname for d in devs if (d.idp_device or {}).get("disk_encryption") == "NONE"]
    no_edr = [d.hostname for d in devs if not d.edr_active and not d.edr_vendor
              and (when((d.idp_device or {}).get("updated")) or recent) > recent]
    only = [d.hostname for d in devs if (d.sources or "") == ",okta,"]
    clash = sorted(set(people.conflicts))
    f = [
        ("idp_mfa_none", "okta:mfa:none", "high", "People who sign in with no real second factor",
         f"{len(none)} people active in the last 90 days sign in with only a password, email or security question. "
         "Their names stay out of this finding (it isn't encrypted); each one's asset page shows their factors.", len(none)),
        ("idp_mfa_phone_only", "okta:mfa:phone_only", "medium", "People whose only second factor is SMS or a voice call",
         f"{len(phone_only)} people active in the last 90 days have only SMS or voice codes, which can be phished or "
         "SIM-swapped. Enroll Okta Verify or a security key.", len(phone_only)),
        ("idp_device_unencrypted", "okta:devices:unencrypted", "high", "Computers with no disk encryption (Okta Verify)",
         "Okta Verify reports no disk encryption on: " + _names(plain), len(plain)),
        ("idp_device_no_edr", "okta:devices:no_edr", "high", "Computers people sign in from that have no EDR",
         "Seen by Okta in the last 90 days, but no EDR reports them: " + _names(no_edr), len(no_edr)),
        ("idp_device_unknown", "okta:devices:only_idp", "medium", "Computers only the identity provider knows",
         "No scanner, EDR or directory reports these computers: " + _names(only), len(only)),
        ("idp_device_name_conflict", "okta:devices:name_conflict", "medium", "Computers whose name another computer claims",
         "Okta Verify reports different serial numbers for one computer name, so CTEM didn't apply either record "
         "(a reimage, a replacement, or someone renaming a machine to pose as another): " + _names(clash), len(clash)),
    ]
    keep = () if read else ("okta:mfa:",)   # don't judge MFA before any factors were read
    if not people.devices_pulled:          # name conflicts are only known on a device pull; keep the last word
        keep += ("okta:devices:name_conflict",)
    f = [x for x in f if not x[1].startswith(keep)] if keep else f
    await _save(db, f, keep_prefix=keep)
    return sum(1 for x in f if x[5])


async def _save(db: AsyncSession, findings: list[tuple], keep_prefix: tuple = ()) -> None:
    """Upsert this run's findings; Okta's earlier ones not found again are resolved (except keep_prefix ones)."""
    from api.models.identity import PostureFinding
    now = datetime.now(timezone.utc)
    have = {p.external_id: p for p in (await db.execute(select(PostureFinding).where(PostureFinding.source == SOURCE))).scalars()}
    keep = set()
    for kind, ext, sev, title, desc, count in findings:
        if not count:
            continue
        p = have.get(ext) or PostureFinding(source=SOURCE, external_id=ext, detected_at=now)
        p.finding_type, p.severity, p.title, p.description = kind, sev, title[:512], desc[:4000]
        p.affected_count, p.is_resolved, p.resolved_at, p.app_name = count, False, None, "Okta"
        db.add(p)
        keep.add(ext)
    gone = [e for e in have if e not in keep and not (keep_prefix and e.startswith(keep_prefix))]
    if gone:
        await db.execute(update(PostureFinding).where(PostureFinding.source == SOURCE, PostureFinding.external_id.in_(gone),
                                                      PostureFinding.is_resolved.is_(False)).values(is_resolved=True, resolved_at=now))
    await db.commit()


def _mask(login: str | None) -> str | None:
    from api.integrations.grip import _mask_email
    if not login:
        return None
    return _mask_email(login) if "@" in login else "*" * max(0, len(login) - 2) + login[-2:]


def threat_row(e: dict) -> dict | None:
    """The fields CTEM keeps from one System Log event, or None for one we don't track."""
    kind = EVENTS.get(str(e.get("eventType")))
    if not kind or not e.get("uuid"):
        return None
    actor, targets = e.get("actor") or {}, [t for t in e.get("target") or [] if t.get("type") == "User"]
    # The person it's about: the account granted a role or reset, else whoever acted
    who = (targets[0] if targets and e["eventType"] in ("user.account.privilege.grant", "user.mfa.factor.reset_all",
                                                         "user.session.impersonation.initiate") else actor)
    login = who.get("alternateId") if who.get("type") == "User" else None
    client = e.get("client") or {}
    geo = client.get("geographicalContext") or {}
    sec = e.get("securityContext") or {}
    ip = str(client.get("ipAddress") or "")[:45] or None
    return {"external_id": str(e["uuid"])[:256], "threat_type": kind[0], "severity": kind[1], "mitre": kind[2],
            "title": str(e.get("displayMessage") or e["eventType"])[:512], "login": login, "ip": ip,
            "country": str(geo.get("country") or "")[:64] or None, "detected_at": when(e.get("published")),
            "raw": {"eventType": e["eventType"], "outcome": e.get("outcome"), "severity": e.get("severity"),
                    "zone": client.get("zone"), "userAgent": (client.get("userAgent") or {}).get("rawUserAgent"),
                    "risk": (sec.get("risk") or {}).get("level"), "isProxy": sec.get("isProxy"), "asOrg": sec.get("asOrg"),
                    "reason": (e.get("outcome") or {}).get("reason")}}


async def threats(conn, client, db: AsyncSession, people: People) -> int:
    """New System Log security events since the last sync (at most a week back), each saved once."""
    from api.core.encryption import search_hash
    from api.integrations.base import load_sync_state, save_sync_state
    from api.models.identity import IdentityThreat, ItdrAlertStatus, ItdrThreatType
    state = await load_sync_state(db, conn.integration_id)
    floor = datetime.now(timezone.utc) - LOOKBACK
    since = max(when(state.get("logs_since")) or floor, floor)
    filt = quote(" or ".join(f'eventType eq "{t}"' for t in EVENTS))
    url = f"/api/v1/logs?since={quote(since.strftime('%Y-%m-%dT%H:%M:%S.000Z'))}&limit=1000&sortOrder=ASCENDING&filter={filt}"
    rows, newest = [], since
    for _ in range(_MAX_LOG_PAGES):
        body, url = await conn.fetch(url, client)
        batch = [r for r in (threat_row(e) for e in body if isinstance(e, dict)) if r] if isinstance(body, list) else []
        rows.extend(batch)
        newest = max([newest, *(r["detected_at"] for r in batch if r["detected_at"])])
        if not body or not url:
            break   # Okta's log keeps handing out a next link to poll; an empty page means we're caught up
    have = set()
    ids = [r["external_id"] for r in rows]
    for i in range(0, len(ids), 500):
        have |= {x for (x,) in (await db.execute(select(IdentityThreat.external_id).where(
            IdentityThreat.source == SOURCE, IdentityThreat.external_id.in_(ids[i:i + 500])))).all()}
    n = 0
    for r in rows:
        if r["external_id"] in have or r["detected_at"] is None:
            continue
        have.add(r["external_id"])
        t = IdentityThreat(source=SOURCE, external_id=r["external_id"], threat_type=ItdrThreatType(r["threat_type"]),
                           severity=r["severity"], status=ItdrAlertStatus.active, title=r["title"],
                           mitre_technique_id=r["mitre"], source_ip=r["ip"], country=r["country"],
                           detected_at=r["detected_at"], app_name="Okta", raw=r["raw"])
        if r["login"]:
            t.user_email_hash, t.user_display = search_hash(r["login"].lower()), _mask(r["login"])[:256]
        db.add(t)
        n += 1
    await db.commit()
    await merge_repeats(db)
    await save_sync_state(db, conn.integration_id, {**state, "logs_since": newest.isoformat()})
    return n


REPEAT_GAP = timedelta(hours=24)   # repeats further apart than this are a new alert


async def merge_repeats(db: AsyncSession) -> int:
    """Okta ThreatInsight logs one event per request it blocks, so one password spray was dozens of alerts. Active
    alerts with no person, the same title, source IP and Okta's reason, each within REPEAT_GAP of the last, are one:
    the first keeps the count and the first and last time seen; the others are resolved with a pointer to it (kept,
    not deleted). Safe to run again: returns how many were folded in."""
    from api.models.identity import IdentityThreat, ItdrAlertStatus
    rows = (await db.execute(select(IdentityThreat).where(
        IdentityThreat.source == SOURCE, IdentityThreat.status == ItdrAlertStatus.active,
        IdentityThreat.user_email_hash.is_(None), IdentityThreat.source_ip.is_not(None))
        .order_by(IdentityThreat.detected_at))).scalars().all()
    groups: dict[tuple, list] = {}
    for t in rows:
        groups.setdefault((t.title, t.source_ip, str((t.raw or {}).get("reason") or "")), []).append(t)
    now, folded = datetime.now(timezone.utc), 0

    def aware(d):
        return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)
    for items in groups.values():
        keep = None
        for t in items:
            raw = dict(t.raw or {})
            last = aware(when((keep.raw or {}).get("last_seen"))) if keep is not None else None
            if keep is None or last is None or aware(t.detected_at) - last > REPEAT_GAP:
                keep = t   # the first of a new run
                if "count" not in raw:
                    raw.update(count=1, last_seen=aware(t.detected_at).isoformat())
                    t.raw = raw
                continue
            kr = dict(keep.raw or {})
            kr["count"] = int(kr.get("count") or 1) + int(raw.get("count") or 1)
            kr["last_seen"] = max(aware(when(kr.get("last_seen"))) or aware(keep.detected_at),
                                  aware(when(raw.get("last_seen"))) or aware(t.detected_at)).isoformat()
            keep.raw = kr
            t.status, t.resolved_at, t.raw = ItdrAlertStatus.resolved, now, {**raw, "merged_into": str(keep.id)}
            folded += 1
    if folded:
        await db.commit()
    return folded
