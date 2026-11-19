"""Compensating control modifiers for the risk score."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ControlContext:
    """Everything we know about the compensating controls for a finding."""
    edr_active: bool = False                # CrowdStrike / SentinelOne / Defender running
    edr_vendor: str | None = None
    host_firewall_blocks_vector: bool = False  # host FW rule blocks the attack port
    network_segmentation_blocks: bool = False  # Guardicore / NGFW policy blocks path
    nodezero_confirmed_exploitable: bool = False
    nodezero_confirmed_not_exploitable: bool = False
    is_internet_exposed: bool = False
    holds_privileged_creds: bool = False    # domain admin, service account with high priv
    device_offline_days: int = 0            # how long since last seen


def apply_multipliers(base_score: float, ctx: ControlContext) -> tuple[float, list[str]]:
    """
    Apply all multipliers in order. Returns (adjusted_score, list_of_applied_reasons).
    Clamps final score to 0-100.
    """
    score = base_score
    reasons: list[str] = []

    # --- Positive risk (raises score) ----------------------------------------
    if ctx.nodezero_confirmed_exploitable:
        score *= 2.0
        reasons.append("NodeZero confirmed exploitable chain (+100%)")
    if ctx.is_internet_exposed:
        score *= 1.5
        reasons.append("Internet-exposed asset (+50%)")
    if ctx.holds_privileged_creds:
        score *= 1.4
        reasons.append("Asset holds privileged credentials (+40%)")
    if not ctx.edr_active:
        score *= 1.3
        reasons.append("No EDR installed on asset (+30%)")

    # --- Negative risk (lowers score) ----------------------------------------
    if ctx.nodezero_confirmed_not_exploitable:
        score *= 0.3
        reasons.append("NodeZero confirmed NOT exploitable (-70%)")
    if ctx.host_firewall_blocks_vector:
        score *= 0.5
        reasons.append("Host firewall blocks attack vector (-50%)")
    if ctx.network_segmentation_blocks:
        score *= 0.6
        reasons.append("Network segmentation blocks path (-40%)")
    if ctx.edr_active:
        score *= 0.7
        reasons.append("EDR active response mode (-30%)")
    if ctx.device_offline_days > 30:
        score *= 0.7
        reasons.append(f"Device offline {ctx.device_offline_days}d (-30%)")

    return max(0.0, min(100.0, score)), reasons
