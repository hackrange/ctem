"""The built-in Threat Curated Rules (curated_pack.json): generic detections for common and current attacks (credential
theft, ransomware precursors, EDR tampering, RMM abuse, LOLBins, lateral movement, persistence, C2, exfiltration and
newer tradecraft such as paste-and-run and help desk vishing), drawn from MITRE ATT&CK, CISA advisories, public threat
reports and community hunt packs.

They are added on their own once a CrowdStrike integration is enabled (direct or through a shipper), and checked
the same way as any rule (api/hunt/curated.py). Each is tied to its pack key, so an admin's edits and disables are
kept, and one an admin deletes stays deleted. A rule the pack already has as a learned or manual rule is not added
twice."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from sqlalchemy import select

log = logging.getLogger("open-ctem.hunt.pack")
PACK = Path(__file__).with_name("curated_pack.json")
PREFIX = "Built in: "
REMOVED_KEY = "curated_pack_removed"


def load() -> dict:
    return json.loads(PACK.read_text())


def key_of(rule) -> str | None:
    lf = rule.learned_from or ""
    return lf[len(PREFIX):].split(".", 1)[0] if rule.status == "builtin" and lf.startswith(PREFIX) else None


async def _removed(db) -> list[str]:
    from api.models.settings import AppSetting
    row = (await db.execute(select(AppSetting).where(AppSetting.key == REMOVED_KEY))).scalar_one_or_none()
    try:
        out = json.loads(row.value) if row and row.value else []
    except ValueError:
        out = []
    return [k for k in out if isinstance(k, str)] if isinstance(out, list) else []


async def forget(db, rule) -> None:
    """An admin deleted a built-in rule: never add it back."""
    from api.models.settings import AppSetting
    key = key_of(rule)
    if not key:
        return
    gone = await _removed(db)
    if key not in gone:
        row = (await db.execute(select(AppSetting).where(AppSetting.key == REMOVED_KEY))).scalar_one_or_none()
        row = row or AppSetting(key=REMOVED_KEY, is_sensitive=False)
        row.value = json.dumps(sorted([*gone, key])[:500])
        db.add(row)


async def sync(db) -> int:
    """Add the pack's rules that aren't here yet, when CrowdStrike is enabled. Returns how many were added."""
    from api.hunt.curated import fingerprint, validate
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.threat_rule import ThreatRule
    on = (await db.execute(select(IntegrationConfig.id).where(IntegrationConfig.vendor == Vendor.crowdstrike,
                                                              IntegrationConfig.is_enabled.is_(True)).limit(1))).first()
    if on is None:
        return 0
    rows = (await db.execute(select(ThreatRule))).scalars().all()
    have_keys = {k for k in map(key_of, rows) if k}
    have_fps = {r.fingerprint for r in rows}
    skip = have_keys | set(await _removed(db))
    added = 0
    for r in load()["rules"]:
        if r["key"] in skip:
            continue
        try:
            match = validate(r["kind"], r["match"])
        except ValueError:
            log.warning("built-in rule %s doesn't validate; skipped", r["key"])
            continue
        fp = fingerprint(r["kind"], match)
        if fp in have_fps:
            continue
        refs = ", ".join(r.get("references") or [])
        db.add(ThreatRule(name=r["name"][:120], kind=r["kind"], match=match, fingerprint=fp, severity=r["severity"],
                          description=r["description"], what_to_do=r["what_to_do"][:6], attack=r["attack"][:10], enabled=True,
                          status="builtin", learned_from=f"{PREFIX}{r['key']}. Sources: {refs}"[:500], created_by="open-ctem"))
        have_fps.add(fp)
        added += 1
    if added:
        await db.commit()
        log.info("added %d built-in threat curated rules", added)
    return added
