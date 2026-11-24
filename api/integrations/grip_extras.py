"""Grip reads added on top of api/integrations/grip.py (GET only, like everything from Grip):

  browser extensions   every extension in the organization with Grip's risk score and malicious flag; for the malicious and
                       high-risk ones, who has them installed (people's addresses kept only as keyed hashes and masks)
  desktop AI apps      AI desktop apps and the devices they are installed on, into CTEM's software inventory so each
                       device's Software tab shows them
  people               leaked, reused and weak passwords and MFA coverage per person (Grip's passwordPosture and
                       mfaStatusByApp), and their risky extensions, rolled into the identity risk score
  password apps        which apps hold those passwords: Grip counts them per app and per person, so the users of each app
                       with any are read and matched; where an app has fewer such accounts than people flagged in it, each
                       of them is marked "possibly" rather than certain
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.grip")
RISKY = ("High",)
MAX_DETAIL = 60   # extensions whose installs are read (one GET each), the riskiest first


def _when(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


async def sync_extensions(conn, db: AsyncSession) -> tuple[int, dict]:
    """Extensions as SaaS records (source grip_extension). Returns (count, {email hash: [risky extension names]})."""
    from api.core.encryption import search_hash
    from api.integrations.grip import _mask_email, _score_to_level
    from api.models.identity import SaasAppRecord
    exts = await conn._paginate(conn._root_url() + "/extensions")
    risky = sorted([e for e in exts if e.get("isMalicious") or e.get("riskLevel") in RISKY],
                   key=lambda e: (not e.get("isMalicious"), -(e.get("riskScore") or 0)))[:MAX_DETAIL]
    by_person: dict[str, list[str]] = defaultdict(list)
    installs: dict[str, list[dict]] = {}
    for e in risky:
        detail = await conn._get_json(conn._root_url() + f"/extensions/{e['extensionId']}")
        items = ((detail or {}).get("installations") or {}).get("items") or []
        installs[e["extensionId"]] = items
        for i in items:
            mail = str(i.get("identityEmail") or "").lower().strip()
            if mail and i.get("status", "enabled") == "enabled":
                by_person[search_hash(mail)].append(("malicious: " if e.get("isMalicious") else "") + str(e.get("name") or "")[:80])
    have = {r.external_id: r for r in (await db.execute(select(SaasAppRecord).where(SaasAppRecord.source == "grip_extension"))).scalars()}
    for e in exts:
        ext_id = str(e.get("extensionId") or "")[:256]
        if not ext_id:
            continue
        rec = have.get(ext_id) or SaasAppRecord(source="grip_extension", external_id=ext_id)
        score = int(e.get("riskScore") or 0)
        rec.app_name = str(e.get("name") or ext_id)[:256]
        rec.app_category = "browser_extension"
        rec.vendor = str(e.get("platform") or "")[:256] or None
        rec.is_shadow_ai = "AI" in (e.get("assets") or [])
        rec.is_sanctioned = str(e.get("sanctionState") or "").lower() == "sanctioned"
        rec.risk_score = float(score)
        rec.risk_level = "critical" if e.get("isMalicious") else _score_to_level(score)
        rec.user_count = int(e.get("activeInstances") or 0)
        rec.last_seen = _when(e.get("lastInstallTime") or e.get("firstDetectionTime"))
        who = installs.get(ext_id, [])
        rec.data_access_scopes = {
            "malicious": bool(e.get("isMalicious")), "malicious_reason": str(e.get("maliciousReason") or "")[:300] or None,
            "risk_level": e.get("riskLevel"), "permissions": [str(p)[:80] for p in (e.get("permissions") or [])][:30],
            "store_url": e.get("storeUrl"), "installed": int(e.get("totalInstances") or 0), "enabled": int(e.get("activeInstances") or 0),
            "people": [_mask_email(str(i.get("identityEmail") or "")) for i in who if i.get("identityEmail")][:25],
            "people_hashes": sorted({search_hash(str(i["identityEmail"]).lower()) for i in who if i.get("identityEmail")})[:200],
        }
        db.add(rec)
    await db.commit()
    log.info("Grip extensions: %d (%d malicious, %d high risk)", len(exts), sum(1 for e in exts if e.get("isMalicious")),
             sum(1 for e in exts if e.get("riskLevel") == "High"))
    return len(exts), dict(by_person)


async def sync_desktop_ai(conn, db: AsyncSession) -> int:
    """AI desktop apps on the devices Grip sees, into the software inventory (source grip)."""
    from api.core import software_ingest
    apps = await conn._paginate(conn._root_url() + "/desktop-ai-apps")
    items = []
    for app in apps[:500]:
        detail = await conn._get_json(conn._root_url() + f"/desktop-ai-apps/{app['id']}")
        by_version: dict[str, list[str]] = defaultdict(list)
        for i in ((detail or {}).get("installations") or {}).get("items") or []:
            if i.get("deviceName"):
                by_version[str(i.get("version") or "")[:128]].append(str(i["deviceName"])[:253])
        for version, hosts in by_version.items():
            items.append({"vendor": "", "product": str(app.get("name") or "")[:200], "version": version, "type": "AI desktop app",
                          "hosts": hosts})
    return await software_ingest.upsert(db, items, "grip") if items else 0


def person_scores(rec, gd: dict, risky_extensions: list[str]) -> None:
    """Leaked, reused and weak passwords, MFA coverage and risky extensions for one person, and the credential score
    they make (0-100): a leaked password counts most, then a malicious extension, a reused password, a risky extension
    and a weak password. Grip's password data needs its browser extension; none means unknown, not clean."""
    pw = gd.get("passwordPosture") or {}
    mfa = gd.get("mfaStatusByApp") or {}
    rec.leaked_password_accounts = int(pw.get("leakedPasswordAccounts") or 0)
    rec.reused_password_accounts = int(pw.get("reusedPasswordAccounts") or 0)
    rec.weak_password_accounts = int(pw.get("weakPasswordAccounts") or 0)
    cov = mfa.get("coveragePercentage")
    rec.mfa_coverage_pct = int(cov) if isinstance(cov, (int, float)) else None
    rec.risky_extensions = len(risky_extensions)
    malicious = sum(1 for n in risky_extensions if n.startswith("malicious: "))
    s = (rec.leaked_password_accounts * 25 + malicious * 40 + rec.reused_password_accounts * 8
         + (len(risky_extensions) - malicious) * 6 + rec.weak_password_accounts * 4)
    if rec.mfa_coverage_pct is not None and rec.mfa_coverage_pct < 50:
        s += 10
    rec.credential_score = float(min(100, s))


MAX_PASSWORD_APPS = 100   # apps whose users are read for password matching, most affected first
KINDS = (("leaked", "leakedPasswordAccounts"), ("reused", "reusedPasswordAccounts"), ("weak", "weakPasswordAccounts"))


async def password_apps(conn, apps: list[dict]) -> dict[str, list[dict]]:
    """{email hash: [{app, app_id, leaked, reused, weak, certain}]} for every app Grip counts weak, reused or leaked
    passwords in. Grip's per-user numbers cover the person, not the account, so a person counts for an app only where
    the app has that kind and so do they; "certain" when the app's count covers everyone flagged in it."""
    from api.core.encryption import search_hash

    def posture(gd) -> dict:
        return (gd or {}).get("passwordPosture") or {}
    hit = [a for a in apps if a.get("id") and any(int(posture(a.get("gripData")).get(f) or 0) for _, f in KINDS)]
    hit.sort(key=lambda a: [-int(posture(a.get("gripData")).get(f) or 0) for _, f in KINDS])
    out: dict[str, list[dict]] = defaultdict(list)
    for a in hit[:MAX_PASSWORD_APPS]:
        app_pw = posture(a.get("gripData"))
        rows = await conn._paginate(conn._root_url() + f"/saas/{a['id']}/users")
        per_kind: dict[str, list[str]] = {k: [] for k, _ in KINDS}
        for r in rows:
            u = r.get("user") or {}
            mail = str(u.get("mail") or "").strip().lower()
            mine = posture(u.get("gripData"))
            if not mail:
                continue
            for k, f in KINDS:
                if int(app_pw.get(f) or 0) and int(mine.get(f) or 0):
                    per_kind[k].append(search_hash(mail))
        people: dict[str, dict] = {}
        for k, f in KINDS:
            sure = len(per_kind[k]) <= int(app_pw.get(f) or 0)
            for h in per_kind[k]:
                e = people.setdefault(h, {"app": str(a.get("name") or "")[:120], "app_id": str(a["id"])[:64],
                                          "leaked": False, "reused": False, "weak": False, "certain": True})
                e[k] = True
                e["certain"] = e["certain"] and sure
        for h, e in people.items():
            out[h].append(e)
    log.info("Grip password apps: %d apps read, %d people tied to at least one", min(len(hit), MAX_PASSWORD_APPS), len(out))
    return dict(out)
