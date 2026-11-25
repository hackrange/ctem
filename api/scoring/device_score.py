"""Device risk score calculator. Returns 0-100 and an A-F grade."""
from __future__ import annotations

from datetime import datetime, timezone

from api.scoring.compensating import ControlContext, apply_multipliers


def _days_since(dt: datetime | None) -> int:
    if dt is None:
        return 9999
    return (datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc if dt.tzinfo is None else dt.tzinfo)).days


def score_finding(
    cvss_base: float,
    epss_score: float,
    is_kev: bool,
    asset_criticality: float,  # 0.0-1.0
    is_reachable: bool | None,
    ctx: ControlContext,
) -> tuple[float, list[str]]:
    """
    Composite score for a single finding on a device.
    Returns (score_0_100, list_of_reasons). The risk-based model (api/scoring/risk_model.py) when it's on, the
    classic CVE-weighted one otherwise.
    """
    from api.scoring import risk_model
    cfg = risk_model.current()
    if cfg["enabled"]:
        return risk_model.score(cvss_base, epss_score, is_kev, asset_criticality, ctx, ctx.device_type or "", cfg,
                                is_reachable=is_reachable)
    # Normalize CVSS 0-10 to 0-100
    cvss_norm = (cvss_base / 10.0) * 100.0

    base = (
        cvss_norm        * 0.25 +
        epss_score * 100 * 0.30 +
        (100.0 if is_kev else 0.0) * 0.20 +
        asset_criticality * 100 * 0.15 +
        (_reachability_score(is_reachable)) * 0.10
    )

    # Hard override: KEV always at least 75
    if is_kev:
        base = max(base, 75.0)

    score, reasons = apply_multipliers(base, ctx)
    return round(score, 1), reasons


def _reachability_score(is_reachable: bool | None) -> float:
    if is_reachable is True:
        return 100.0
    if is_reachable is False:
        return 10.0
    return 50.0  # unknown -- assume partially reachable


def device_grade(score: float) -> str:
    if score <= 20:
        return "A"
    if score <= 40:
        return "B"
    if score <= 60:
        return "C"
    if score <= 80:
        return "D"
    return "F"


def compute_device_score(findings_data: list[dict]) -> tuple[float, str]:
    """
    Roll up all findings on a device into a single device score.
    Uses the 90th percentile of finding scores (not max, to avoid one rogue vuln dominating).
    findings_data: list of dicts with keys matching score_finding() params.
    """
    if not findings_data:
        return 0.0, "A"

    scores = []
    for f in findings_data:
        if "cloud" in f:   # a cloud configuration check, already scored on its own terms
            scores.append(f["cloud"][0])
            continue
        s, _ = score_finding(
            cvss_base=f.get("cvss_base", 0.0),
            epss_score=f.get("epss_score", 0.0),
            is_kev=f.get("is_kev", False),
            asset_criticality=f.get("asset_criticality", 0.5),
            is_reachable=f.get("is_reachable"),
            ctx=f.get("control_context", ControlContext()),
        )
        scores.append(s)

    scores.sort(reverse=True)
    # p90: take average of top 10% of findings
    top_n = max(1, len(scores) // 10)
    device_score = sum(scores[:top_n]) / top_n
    device_score = round(min(100.0, device_score), 1)
    return device_score, device_grade(device_score)
