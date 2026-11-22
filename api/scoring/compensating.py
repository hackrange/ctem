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
    cloud_ports: list | None = None         # the instance's cloud firewall openings (api/cloud), None = not a cloud instance
    # What the EDR's policies do on this host (api/scoring/edr_controls.py); None = not reported
    edr_prevention: dict | None = None      # {blocking: [...], exploit: [...], name}
    usb_blocked: bool | None = None
    memory_flaw: bool = False               # the flaw is memory corruption (what exploit mitigations target)
    host_firewall: tuple | None = None      # (factor, reason) for this finding's ports
    threat_actors: list | None = None       # adversaries the EDR's threat intel ties to this flaw


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
    if ctx.threat_actors:
        score *= 1.2
        names = ", ".join(ctx.threat_actors[:3]) + (" and others" if len(ctx.threat_actors) > 3 else "")
        reasons.append(f"Exploited by adversaries threat intel tracks: {names} (+20%)")

    # --- Negative risk (lowers score) ----------------------------------------
    if ctx.nodezero_confirmed_not_exploitable:
        score *= 0.3
        reasons.append("NodeZero confirmed NOT exploitable (-70%)")
    if ctx.host_firewall:
        score *= ctx.host_firewall[0]
        reasons.append(ctx.host_firewall[1])
    elif ctx.host_firewall_blocks_vector:
        score *= 0.5
        reasons.append("Host firewall blocks attack vector (-50%)")
    if ctx.network_segmentation_blocks:
        score *= 0.6
        reasons.append("Network segmentation blocks path (-40%)")
    if ctx.edr_active:
        score, why = _edr(score, ctx)
        reasons.extend(why)
    factor, why = reachability(ctx)
    if factor != 1.0 or why:
        score *= factor
        reasons.append(why)
    if ctx.device_offline_days > 30:
        score *= 0.7
        reasons.append(f"Device offline {ctx.device_offline_days}d (-30%)")

    return max(0.0, min(100.0, score)), reasons


def _edr(score: float, ctx: ControlContext) -> tuple[float, list[str]]:
    """The EDR's discount, from what its policy on this host does; the flat one when the policy isn't reported."""
    from api.scoring.edr_controls import VENDOR
    who = VENDOR.get(ctx.edr_vendor or "", "EDR")
    p, why = ctx.edr_prevention, []
    if p is None:
        return score * 0.7, ["EDR active response mode (-30%)"]
    if p["blocking"]:
        score *= 0.7
        why.append(f"{who} prevention blocks malicious files and behavior: {', '.join(p['blocking'][:4])}"
                   f"{' and more' if len(p['blocking']) > 4 else ''} (-30%)")
    else:
        score *= 0.9
        why.append(f"{who} is running but its policy only detects; nothing is set to block (-10%)")
    if p["exploit"] and ctx.memory_flaw:
        score *= 0.8
        why.append(f"{who} exploit mitigations ({', '.join(p['exploit'][:4])}) make this memory corruption flaw "
                   "harder to exploit (-20%)")
    if ctx.usb_blocked and (ctx.attack_vector or "").lower() == "physical":
        score *= 0.5
        why.append(f"{who} device control blocks USB storage, the usual way in for a physical-access flaw (-50%)")
    return score, why


# Reachability from facts only: what the CVSS vector requires, and where the scanner found it.
# One factor per finding, the strongest that applies (they describe the same thing, so they don't stack).
_AV_FACTOR = {"physical": (0.3, "Needs physical access (CVSS AV:P) (-70%)"),
              "local": (0.5, "Needs local access first (CVSS AV:L) (-50%)"),
              "adjacent": (0.8, "Needs the same network segment (CVSS AV:A) (-20%)")}
LOCAL_CHECK = (0.75, "Found by a local check; no listening service tied to it (-25%)")


def reach_view(finding, contained: bool = False, attack_vector: str | None = None, cloud_ports: list | None = None) -> dict:
    """What the finding lists show about reachability, from the same facts the score uses.
    attack_vector comes from the caller's vulnerability row, so nothing is lazy-loaded here."""
    av = attack_vector
    if contained:
        return {"exposure": finding.exposure, "ports": finding.ports, "attack_vector": av,
                "reach": "Contained or not in scope: not reachable"}
    _, why = reachability(ControlContext(attack_vector=av, exposure=finding.exposure, ports=finding.ports, cloud_ports=cloud_ports,
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
    if ctx.exposure == "listening" and ctx.ports and ctx.cloud_ports is not None:
        return _cloud_reach(ctx.ports, ctx.cloud_ports)
    if ctx.exposure == "local":
        return LOCAL_CHECK
    if ctx.exposure == "listening":
        return 1.0, f"Listening service {ctx.ports}" if ctx.ports else "Listening service"
    return 1.0, ""


def _cloud_reach(ports: str, cloud_ports: list) -> tuple[float, str]:
    """A listening finding on a cloud instance: what its security groups / NSGs / security lists let reach the port."""
    from api.cloud.exposure import RANK, describe_port, reach_of
    best, rule, which = "closed", None, None
    for spec in ports.split():
        num, _, pr = spec.partition("/")
        if not num.isdigit():
            continue
        r, why = reach_of(cloud_ports, int(num), pr or "tcp")
        if which is None or RANK.get(r, 0) > RANK.get(best, 0):
            best, rule, which = r, why, spec
    via = f" ({rule['via']})" if rule else ""
    if best == "internet":
        return 1.0, f"Open to the internet on {which}{via}"
    if best == "any_internal":
        return 1.0, f"Open to any address on {which}, but the instance has no public IP{via}"
    if best == "restricted":
        src = ", ".join(rule.get("sources", [])[:3]) if rule else ""
        return 0.6, f"Reachable on {describe_port(rule)} only from {src}{via} (-40%)"
    return 0.4, f"No cloud firewall rule allows {ports} (-60%)"
