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
    # Reachability facts for this finding
    attack_vector: str | None = None        # CVSS: network, adjacent, local, physical
    exposure: str | None = None             # scanner: "listening" (on a network service) or "local" (local check)
    ports: str | None = None                # the listening ports, for the reason text


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
    factor, why = reachability(ctx)
    if factor != 1.0 or why:
        score *= factor
        reasons.append(why)
    if ctx.device_offline_days > 30:
        score *= 0.7
        reasons.append(f"Device offline {ctx.device_offline_days}d (-30%)")

    return max(0.0, min(100.0, score)), reasons


# Reachability from facts only: what the CVSS vector requires, and where the scanner found it.
# One factor per finding, the strongest that applies (they describe the same thing, so they don't stack).
_AV_FACTOR = {"physical": (0.3, "Needs physical access (CVSS AV:P) (-70%)"),
              "local": (0.5, "Needs local access first (CVSS AV:L) (-50%)"),
              "adjacent": (0.8, "Needs the same network segment (CVSS AV:A) (-20%)")}
LOCAL_CHECK = (0.75, "Found by a local check; no listening service tied to it (-25%)")


def reach_view(finding, contained: bool = False, attack_vector: str | None = None) -> dict:
    """What the finding lists show about reachability, from the same facts the score uses.
    attack_vector comes from the caller's vulnerability row, so nothing is lazy-loaded here."""
    av = attack_vector
    if contained:
        return {"exposure": finding.exposure, "ports": finding.ports, "attack_vector": av,
                "reach": "Contained or not in scope: not reachable"}
    _, why = reachability(ControlContext(attack_vector=av, exposure=finding.exposure, ports=finding.ports,
                                         nodezero_confirmed_exploitable=bool(
                                             finding.is_reachable and finding.reachability_source == "horizon3")))
    return {"exposure": finding.exposure, "ports": finding.ports, "attack_vector": av, "reach": why or None}


def reachability(ctx: ControlContext) -> tuple[float, str]:
    """(multiplier, reason). A finding confirmed exploitable by NodeZero is never discounted."""
    if ctx.nodezero_confirmed_exploitable:
        return 1.0, ""
    av = (ctx.attack_vector or "").lower()
    if av in _AV_FACTOR:
        return _AV_FACTOR[av]
    if ctx.exposure == "local":
        return LOCAL_CHECK
    if ctx.exposure == "listening":
        return 1.0, f"Listening service {ctx.ports}" if ctx.ports else "Listening service"
    return 1.0, ""
