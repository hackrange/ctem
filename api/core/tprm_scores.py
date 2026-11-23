"""Supplier security score history (FairTPRM) and the score on any date.

FairTPRM's vendor percentage (SRSService::getCombinedScore) is the average of the parts that are set and above 0:
the UpGuard rating as a percentage of the configured maximum, the Shodan score (0-100) and the custom score (1-100),
rounded half up to a whole number. CTEM keeps each part's history (ThirdPartyScore) and recomputes that average as
of a date: each part's latest value on or before it. Before FairTPRM offers the history, CTEM records the current
combined percentage once a day ("combined"), which is what a date falls back to when it has no parts."""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

PARTS = ("upguard", "shodan", "custom")


def combined(values: list[float]) -> int | None:
    """FairTPRM's rounding: PHP round(), half away from zero (scores are never negative)."""
    vals = [v for v in values if v is not None and v > 0]
    return int(math.floor(sum(vals) / len(vals) + 0.5)) if vals else None


def score_at(points: list[tuple[str, float | None, datetime]], when: datetime) -> int | None:
    """points: (kind, score, at) for one supplier. The combined percentage as of `when`."""
    latest: dict[str, tuple[datetime, float | None]] = {}
    for kind, score, at in points:
        if at <= when and (kind not in latest or at >= latest[kind][0]):
            latest[kind] = (at, score)
    if any(k in latest for k in PARTS):
        return combined([latest[k][1] for k in PARTS if k in latest])
    return int(round(latest["combined"][1])) if "combined" in latest and latest["combined"][1] is not None else None


def _utc(text, tz) -> datetime | None:
    """A FairTPRM time ("2026-06-30 02:00:00", in its server's timezone) in UTC."""
    try:
        t = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return (t.replace(tzinfo=tz) if t.tzinfo is None else t).astimezone(timezone.utc)


def _zone(name):
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    try:
        return ZoneInfo(str(name)) if name else timezone.utc
    except (ZoneInfoNotFoundError, ValueError):
        return timezone.utc


def _num(v, low, high) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if low <= f <= high else None


async def ingest(db, page: dict, suppliers: dict) -> int:
    """One page of GET /vendors/score-history. suppliers: FairTPRM vendor id -> CTEM supplier id. Adds the points
    CTEM doesn't have yet; returns how many."""
    from api.models.risk import ThirdPartyScore
    tz, top = _zone(page.get("timezone")), _num(page.get("upguard_max_score"), 1, 100000) or 950.0
    n = 0
    for v in page.get("data") or []:
        sid = suppliers.get(str(v.get("id"))) if isinstance(v, dict) else None
        if sid is None:
            continue
        have = {(k, a) for k, a in (await db.execute(select(ThirdPartyScore.kind, ThirdPartyScore.at).where(
            ThirdPartyScore.supplier_id == sid, ThirdPartyScore.kind.in_(PARTS)))).all()}
        have = {(k, a.astimezone(timezone.utc) if a.tzinfo else a.replace(tzinfo=timezone.utc)) for k, a in have}
        rows = []
        for kind, key, scale in (("upguard", "scored_at", 100.0 / top), ("shodan", "scored_at", 1.0), ("custom", "changed_at", 1.0)):
            for p in (v.get(kind) or [])[:1000]:
                at = _utc(p.get(key), tz) if isinstance(p, dict) else None
                if at is None or (kind, at) in have:
                    continue
                raw = p.get("score")
                if raw is None and kind == "custom":
                    score = None        # cleared
                else:
                    score = _num(raw, 0, top if kind == "upguard" else 100)
                    if score is None:
                        continue
                    score = round(score * scale, 2)
                rows.append(ThirdPartyScore(supplier_id=sid, kind=kind, score=score, at=at))
                have.add((kind, at))
        db.add_all(rows)
        n += len(rows)
    await db.flush()
    return n


async def record_today(db, supplier_id: str, current: dict) -> bool:
    """The daily fallback: the supplier's combined percentage today, from its current parts (FairTPRM's vendor record:
    current_srs_score, current_shodan_score, custom_score) and the UpGuard maximum. Once per day."""
    from api.models.risk import ThirdPartyScore
    top = _num(current.get("upguard_max_score"), 1, 100000) or 950.0
    up = _num(current.get("current_srs_score"), 0, top)
    pct = combined([up * 100.0 / top if up else None, _num(current.get("current_shodan_score"), 0, 100),
                    _num(current.get("custom_score"), 0, 100)])
    if pct is None:
        return False
    day = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    if (await db.execute(select(ThirdPartyScore.id).where(ThirdPartyScore.supplier_id == supplier_id, ThirdPartyScore.kind == "combined",
                                                          ThirdPartyScore.at >= day, ThirdPartyScore.at < day + timedelta(days=1)))).first():
        return False
    db.add(ThirdPartyScore(supplier_id=supplier_id, kind="combined", score=float(pct), at=day))
    return True


async def points_for(db, supplier_ids: list[str], until: datetime) -> dict[str, list]:
    """supplier id -> its (kind, score, at) points up to `until`."""
    from api.models.risk import ThirdPartyScore
    out: dict[str, list] = {s: [] for s in supplier_ids}
    for i in range(0, len(supplier_ids), 500):
        for sid, kind, score, at in (await db.execute(select(ThirdPartyScore.supplier_id, ThirdPartyScore.kind, ThirdPartyScore.score,
                                                             ThirdPartyScore.at).where(
                ThirdPartyScore.supplier_id.in_(supplier_ids[i:i + 500]), ThirdPartyScore.at <= until))).all():
            out[sid].append((kind, score, at if at.tzinfo else at.replace(tzinfo=timezone.utc)))
    return out
