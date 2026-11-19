"""Unit tests for the risk scoring engine."""
import pytest

from api.scoring.compensating import ControlContext, apply_multipliers
from api.scoring.device_score import compute_device_score, device_grade, score_finding
from api.scoring.user_score import compute_user_score
from api.scoring.chain import detect_chains, chain_score


# ── score_finding ──────────────────────────────────────────────────────────────

def test_score_finding_kev_floor():
    """KEV finding must score at least 75 regardless of CVSS."""
    score = score_finding(
        cvss_base=2.0, epss_score=0.001, is_kev=True,
        asset_criticality=1, is_reachable=False, ctx=ControlContext(),
    )
    assert score >= 75


def test_score_finding_no_kev_low_cvss():
    score = score_finding(
        cvss_base=2.0, epss_score=0.001, is_kev=False,
        asset_criticality=1, is_reachable=False, ctx=ControlContext(),
    )
    assert score < 30


def test_score_finding_high_epss_boosts():
    low = score_finding(2.0, 0.01, False, 3, True, ControlContext())
    high = score_finding(2.0, 0.90, False, 3, True, ControlContext())
    assert high > low


def test_score_finding_capped_at_100():
    score = score_finding(
        cvss_base=10.0, epss_score=1.0, is_kev=True,
        asset_criticality=5, is_reachable=True,
        ctx=ControlContext(nodezero_confirmed=True, internet_exposed=True),
    )
    assert score <= 100


# ── compensating controls ──────────────────────────────────────────────────────

def test_nodezero_not_exploitable_reduces():
    base = 60.0
    ctx = ControlContext(nodezero_not_exploitable=True)
    result, reasons = apply_multipliers(base, ctx)
    assert result < base
    assert any("not exploitable" in r.lower() for r in reasons)


def test_nodezero_confirmed_increases():
    base = 50.0
    ctx = ControlContext(nodezero_confirmed=True)
    result, _ = apply_multipliers(base, ctx)
    assert result > base


def test_edr_active_reduces():
    base = 60.0
    ctx = ControlContext(edr_active=True)
    result, _ = apply_multipliers(base, ctx)
    assert result < base


def test_contradictory_controls_net_applied():
    # Both confirmed exploitable AND EDR active -- net result depends on order
    ctx = ControlContext(nodezero_confirmed=True, edr_active=True)
    base = 50.0
    result, reasons = apply_multipliers(base, ctx)
    assert 0 < result <= 100  # still bounded
    assert len(reasons) >= 2


# ── device grade ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("score,expected", [
    (5, "A"), (25, "B"), (45, "C"), (65, "D"), (85, "F"),
])
def test_device_grade(score, expected):
    assert device_grade(score) == expected


# ── compute_device_score ──────────────────────────────────────────────────────

def test_compute_device_score_empty():
    score = compute_device_score([])
    assert score == 0.0


def test_compute_device_score_uses_p90():
    # p90 means top 10% of findings; a single high score should dominate
    findings = [
        {"cvss_base": 9.5, "epss_score": 0.9, "is_kev": True, "asset_criticality": 5,
         "is_reachable": True, "compensating": {}},
        *[{"cvss_base": 1.0, "epss_score": 0.001, "is_kev": False, "asset_criticality": 1,
           "is_reachable": False, "compensating": {}} for _ in range(9)],
    ]
    score = compute_device_score(findings)
    assert score > 50  # dominated by the critical finding


# ── user score ────────────────────────────────────────────────────────────────

def test_user_score_no_mfa_penalty():
    score, grade, breakdown = compute_user_score(
        device_scores=[30.0], ad_groups=[], mfa_enabled=False,
        is_service_account=False, last_login_days_ago=1, saas_risk_score=0,
    )
    assert breakdown.get("no_mfa", 0) > 0


def test_user_score_privileged_group_penalty():
    score, _, breakdown = compute_user_score(
        device_scores=[30.0], ad_groups=["Domain Admins"], mfa_enabled=True,
        is_service_account=False, last_login_days_ago=1, saas_risk_score=0,
    )
    assert breakdown.get("privileged_groups", 0) > 0


def test_user_score_service_account_penalty():
    score, _, breakdown = compute_user_score(
        device_scores=[], ad_groups=[], mfa_enabled=False,
        is_service_account=True, last_login_days_ago=1, saas_risk_score=0,
    )
    assert breakdown.get("service_account", 0) > 0


def test_user_score_capped_at_100():
    score, _, _ = compute_user_score(
        device_scores=[100.0, 100.0],
        ad_groups=["Domain Admins", "Enterprise Admins", "Schema Admins"],
        mfa_enabled=False, is_service_account=True,
        last_login_days_ago=400, saas_risk_score=100,
    )
    assert score <= 100


# ── CVE chaining ──────────────────────────────────────────────────────────────

def test_detect_chains_empty():
    assert detect_chains([]) == []


def test_chain_score_pentest_confirmed_higher():
    class FakeNode:
        technique_id = "T1059"
        cvss_base = 8.0

    n = FakeNode()
    base = chain_score(([n, n]), pentest_confirmed=False)
    confirmed = chain_score(([n, n]), pentest_confirmed=True)
    assert confirmed > base
