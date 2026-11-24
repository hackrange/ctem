"""How a cloud configuration finding (CSPM) is shown: where it is, why it scores what it does, and how to fix it."""
from __future__ import annotations

from sqlalchemy import select

from api.scoring import cloud_score

_WHERE = ("provider", "account", "account_id", "region", "resource_type", "resource", "arn")


def view(f, cvss: float | None) -> dict | None:
    """The finding's cloud details with the reasons for its score, or None for any other kind of finding."""
    if getattr(f, "domain", None) != "cloud":
        return None
    d = dict(f.details or {})
    d["score_why"] = cloud_score.score(f.details, cvss)[1]
    return d


async def with_fixes(db, pairs: list[tuple[dict, str | None]]) -> None:
    """Adds the fix (the tool's remediation steps) to each shown cloud finding, one query for the page."""
    from api.models.vuln import Fix
    keys = {k for row, k in pairs if k and row.get("domain") == "cloud" and row.get("details") is not None}
    if not keys:
        return
    found = {x.key: x for x in (await db.execute(select(Fix).where(Fix.key.in_(keys)))).scalars()}
    for row, k in pairs:
        fx = found.get(k or "")
        if fx is not None and row.get("details") is not None and row.get("domain") == "cloud":
            row["details"] = {**row["details"], "fix": fx.steps, "fix_title": fx.title,
                              "fix_links": [u for u in fx.links or [] if str(u).startswith("https://")][:10]}


async def where(db, device_id: str) -> dict | None:
    """A cloud resource's provider, account, region and type, from its newest cloud finding."""
    from api.models.vuln import Finding
    det = (await db.execute(select(Finding.details).where(Finding.device_id == device_id, Finding.domain == "cloud")
                            .order_by(Finding.last_seen.desc().nulls_last()).limit(1))).scalar_one_or_none()
    out = {k: (det or {}).get(k) for k in _WHERE if (det or {}).get(k)}
    return out or None
