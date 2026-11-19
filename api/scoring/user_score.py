"""User risk score. Identity blast radius matters as much as device scores."""
from __future__ import annotations


_PRIVILEGED_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "backup operators", "account operators",
    "server operators", "group policy creator owners",
}

_NO_MFA_PENALTY = 20.0          # added to base if MFA not enabled
_PRIVILEGED_GROUP_PENALTY = 25.0 # added per privileged group membership
_EXCESSIVE_PERM_PENALTY = 10.0  # added if user has way too many group memberships


def _is_privileged_group(group_name: str) -> bool:
    return group_name.lower().strip() in _PRIVILEGED_GROUPS


def compute_user_score(
    device_scores: list[float],
    ad_groups: list[str],
    mfa_enabled: bool,
    is_service_account: bool,
    last_login_days_ago: int,
    saas_risk_score: float | None = None,
) -> tuple[float, str, dict]:
    """
    Returns (score_0_100, grade, breakdown_dict).
    Service accounts get a flat +30 for the blast radius they represent.
    """
    breakdown: dict[str, float] = {}

    # Base: average of assigned device scores (capped at 60 for identity component)
    if device_scores:
        device_avg = sum(device_scores) / len(device_scores)
        base = min(60.0, device_avg * 0.6)
    else:
        base = 0.0
    breakdown["device_component"] = round(base, 1)

    # MFA
    if not mfa_enabled:
        base += _NO_MFA_PENALTY
        breakdown["no_mfa_penalty"] = _NO_MFA_PENALTY

    # Privileged group memberships
    priv_groups = [g for g in ad_groups if _is_privileged_group(g)]
    if priv_groups:
        penalty = min(_PRIVILEGED_GROUP_PENALTY * len(priv_groups), 40.0)
        base += penalty
        breakdown["privileged_group_penalty"] = penalty

    # Excessive permissions (heuristic: > 50 group memberships)
    if len(ad_groups) > 50:
        base += _EXCESSIVE_PERM_PENALTY
        breakdown["excessive_permissions_penalty"] = _EXCESSIVE_PERM_PENALTY

    # Service account blast radius
    if is_service_account:
        base += 30.0
        breakdown["service_account_penalty"] = 30.0

    # SaaS exposure from Grip
    if saas_risk_score is not None:
        saas_component = saas_risk_score * 20.0  # scale 0-5 to 0-100, weight 0.2
        base += saas_component * 0.2
        breakdown["saas_component"] = round(saas_component * 0.2, 1)

    # Stale account: last login > 90 days reduces urgency slightly
    if last_login_days_ago > 90:
        base *= 0.8
        breakdown["stale_account_modifier"] = -0.2

    score = round(min(100.0, max(0.0, base)), 1)
    grade = _user_grade(score)
    breakdown["final"] = score
    return score, grade, breakdown


def _user_grade(score: float) -> str:
    if score <= 20:
        return "A"
    if score <= 40:
        return "B"
    if score <= 60:
        return "C"
    if score <= 80:
        return "D"
    return "F"
