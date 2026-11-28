"""Software controls: assets running software the organization marked unauthorized (Software > Mark unauthorized).

The inventory comes from the scanners and EDRs that report installed software (the InsightVM console through the
shipper today). With no inventory at all the check is an error, never a pass: no data is not compliance."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.device_scope_exempt import in_scope
from api.grc.checks import EDR, SCANNERS, Check, Outcome, Threshold, grade_low, register
from api.models.device import Device
from api.rules.apply import device_scope

MAX_ROWS = 50000
SOURCES = tuple(dict.fromkeys(SCANNERS + EDR))   # whoever reports installed software


async def _unauthorized(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    from api.core.software_ingest import STALE_DAYS
    from api.models.software import SoftwareInstall, SoftwareTitle
    live = SoftwareInstall.last_seen >= datetime.now(timezone.utc) - timedelta(days=STALE_DAYS)
    on_assets = [SoftwareInstall.device_id.in_(select(Device.id).where(device_scope(), in_scope()))]
    inventoried = (await db.execute(select(func.count(func.distinct(SoftwareInstall.device_id))).where(live, *on_assets))).scalar_one()
    if not inventoried:
        return Outcome("error", "No software inventory yet: no source has reported installed software")
    from api.core.software_status import exception_is, unauthorized_here
    bad = [live, *on_assets, unauthorized_here()]   # per asset: a title's own status, or that asset's exception
    n_assets, n_titles = (await db.execute(
        select(func.count(func.distinct(SoftwareInstall.device_id)), func.count(func.distinct(SoftwareInstall.title_id)))
        .join(SoftwareTitle, SoftwareTitle.id == SoftwareInstall.title_id).where(*bad))).one()
    marked = (await db.execute(select(func.count()).select_from(SoftwareTitle).where(SoftwareTitle.status == "unauthorized"))).scalar_one()
    unreviewed = (await db.execute(select(func.count(func.distinct(SoftwareInstall.title_id)))
                                   .join(SoftwareTitle, SoftwareTitle.id == SoftwareInstall.title_id)
                                   .where(live, *on_assets, SoftwareTitle.status == "unreviewed",
                                          SoftwareTitle.system == False))).scalar_one()  # noqa: E712
    allowed = (await db.execute(select(func.count()).select_from(SoftwareInstall).join(SoftwareTitle, SoftwareTitle.id == SoftwareInstall.title_id)
                                .where(live, *on_assets, SoftwareTitle.status == "unauthorized", exception_is("allowed")))).scalar_one()
    out = Outcome(grade_low(n_assets, 0, t["warn_max"]),
                  f"{n_assets:,} of {inventoried:,} inventoried assets run unauthorized software "
                  f"({n_titles:,} of the {marked:,} titles marked unauthorized); {unreviewed:,} third-party titles not reviewed yet",
                  {"inventoried_assets": inventoried, "assets_with_unauthorized": n_assets, "unauthorized_titles_found": n_titles,
                   "titles_marked_unauthorized": marked, "third_party_titles_unreviewed": unreviewed,
                   "allowed_by_exception": allowed})
    if detail:
        rows = (await db.execute(
            select(Device.id, Device.hostname, SoftwareTitle.title, SoftwareTitle.vendor, SoftwareInstall.version,
                   SoftwareInstall.last_seen, SoftwareTitle.status_note, SoftwareTitle.status)
            .join(SoftwareInstall, SoftwareInstall.device_id == Device.id)
            .join(SoftwareTitle, SoftwareTitle.id == SoftwareInstall.title_id).where(*bad)
            .order_by(Device.hostname, SoftwareTitle.title).limit(MAX_ROWS))).all()
        out.columns = ["hostname", "software", "vendor", "version", "last_reported", "why_unauthorized"]
        out.rows = [{"device_id": str(i), "hostname": h, "software": s, "vendor": v or "", "version": ver or "(unknown)",
                     "last_reported": ls.isoformat() if ls else "",
                     "why_unauthorized": (note or "") if st == "unauthorized" else "not allowed on this asset (exception)"}
                    for i, h, s, v, ver, ls, note, st in rows]
    return out


register(Check(
    "ctem_unauthorized_software", "Unauthorized software installed",
    "Assets running software marked unauthorized in the software inventory", 1, SOURCES,
    ("CIS 2.3", "CIS 2.5", "NIST 800-53 CM-7(4)", "NIST 800-53 CM-11", "ISO 27001 A.8.19", "PCI DSS 2.2.4", "NIST CSF PR.PS-02"),
    {"warn_max": Threshold(0, 0, 100000, "assets tolerated as a warning instead of a fail")}, _unauthorized, device_scoped=True))


# AI software, by its name: assistants, chat and agent apps, browser extensions, local model runners
AI_NAMES = re.compile(r"(?<![a-z0-9])(ai|a\.i\.|chat ?gpt|gpt(-?\d[\w.]*)?|openai|claude|anthropic|gemini|bard|copilot|deepseek|"
                      r"perplexity|grok|ollama|lm ?studio|llama|mistral|hugging ?face|midjourney|stable diffusion|"
                      r"character\.ai|poe)(?![a-z0-9])", re.I)


async def _ai_titles(db: AsyncSession) -> dict[str, str]:
    """{title id: title} of third-party software named like AI software (matched here, so every database agrees)."""
    from api.models.software import SoftwareTitle
    return {str(i): t for i, t in (await db.execute(select(SoftwareTitle.id, SoftwareTitle.title).where(
        SoftwareTitle.system == False))).all() if t and AI_NAMES.search(t)}  # noqa: E712


async def _ai_software(db: AsyncSession, t: dict, detail: bool) -> Outcome:
    """AI software on assets that isn't approved: marked unauthorized (fails), or not reviewed yet (warns: shadow AI
    nobody has decided on). Approved AI, and AI allowed on an asset by an exception, doesn't count."""
    from api.core.software_ingest import STALE_DAYS
    from api.core.software_status import exception_is, unauthorized_here
    from api.models.software import SoftwareInstall, SoftwareTitle
    live = SoftwareInstall.last_seen >= datetime.now(timezone.utc) - timedelta(days=STALE_DAYS)
    on_assets = [SoftwareInstall.device_id.in_(select(Device.id).where(device_scope(), in_scope()))]
    inventoried = (await db.execute(select(func.count(func.distinct(SoftwareInstall.device_id))).where(live, *on_assets))).scalar_one()
    if not inventoried:
        return Outcome("error", "No software inventory yet: no source has reported installed software")
    ai = list(await _ai_titles(db))
    ai_on = SoftwareInstall.title_id.in_(ai or ["-"])
    bad = [live, *on_assets, ai_on, unauthorized_here()]
    unreviewed = [live, *on_assets, ai_on, SoftwareTitle.status == "unreviewed", ~exception_is("allowed"),
                  ~exception_is("denied")]   # an asset's own "not allowed here" exception counts it as unauthorized above

    async def count(where):
        return (await db.execute(select(func.count(func.distinct(SoftwareInstall.device_id)), func.count(func.distinct(SoftwareInstall.title_id)))
                                 .join(SoftwareTitle, SoftwareTitle.id == SoftwareInstall.title_id).where(*where))).one()
    (n_bad, t_bad), (n_new, t_new) = await count(bad), await count(unreviewed)
    approved = (await db.execute(select(func.count(func.distinct(SoftwareInstall.title_id))).join(
        SoftwareTitle, SoftwareTitle.id == SoftwareInstall.title_id).where(live, *on_assets, ai_on, SoftwareTitle.status == "approved"))).scalar_one()
    status = "fail" if n_bad > t["warn_max"] else "warning" if n_bad or n_new else "pass"
    out = Outcome(status, f"{n_bad:,} of {inventoried:,} inventoried assets run unauthorized AI software ({t_bad:,} titles); "
                          f"{n_new:,} run AI software not reviewed yet ({t_new:,} titles); {approved:,} approved AI titles in use",
                  {"inventoried_assets": inventoried, "assets_with_unauthorized_ai": n_bad, "unauthorized_ai_titles": t_bad,
                   "assets_with_unreviewed_ai": n_new, "unreviewed_ai_titles": t_new, "approved_ai_titles_in_use": approved,
                   "ai_titles_known": len(ai)})
    if detail:
        rows = []
        for where, why in ((bad, None), (unreviewed, "not reviewed yet")):
            rows += (await db.execute(
                select(Device.id, Device.hostname, SoftwareTitle.title, SoftwareTitle.vendor, SoftwareInstall.version,
                       SoftwareInstall.last_seen, SoftwareTitle.status_note, SoftwareTitle.status, SoftwareInstall.source)
                .join(SoftwareInstall, SoftwareInstall.device_id == Device.id)
                .join(SoftwareTitle, SoftwareTitle.id == SoftwareInstall.title_id).where(*where)
                .order_by(Device.hostname, SoftwareTitle.title).limit(MAX_ROWS))).all()
        out.columns = ["hostname", "software", "vendor", "version", "status", "why", "reported_by", "last_reported"]
        seen, out.rows = set(), []
        for i, h, s, v, ver, ls, note, st, src in rows:
            if (i, s, ver) in seen:
                continue
            seen.add((i, s, ver))
            out.rows.append({"device_id": str(i), "hostname": h, "software": s, "vendor": v or "", "version": ver or "(unknown)",
                             "status": "unauthorized" if st == "unauthorized" else "not allowed here" if st != "unreviewed" else "unreviewed",
                             "why": (note or "") if st == "unauthorized" else ("an exception doesn't allow it here" if st != "unreviewed" else "not reviewed yet"),
                             "reported_by": src, "last_reported": ls.isoformat() if ls else ""})
        out.rows = out.rows[:MAX_ROWS]
    return out


register(Check(
    "ctem_unauthorized_ai_software", "Unauthorized AI software installed",
    "Assets running AI software (assistants, chat and agent apps, browser extensions, local model runners) that isn't "
    "approved: marked unauthorized fails, not reviewed yet warns", 1, SOURCES,
    ("CIS 2.3", "CIS 2.5", "NIST 800-53 CM-7(4)", "NIST 800-53 CM-11", "ISO 27001 A.8.19", "NIST CSF PR.PS-02"),
    {"warn_max": Threshold(0, 0, 100000, "assets with unauthorized AI software tolerated as a warning instead of a fail")},
    _ai_software, device_scoped=True))
