"""CVE chain detection. Score the path, not individual nodes."""
from __future__ import annotations

from dataclasses import dataclass

# MITRE ATT&CK technique correlations for common chain patterns.
# (technique_initial, technique_next) means these two techniques commonly chain.
_MITRE_CHAINS = {
    ("T1190", "T1078"),   # exploit public-facing app -> valid accounts
    ("T1190", "T1068"),   # exploit public-facing app -> exploitation for privilege escalation
    ("T1078", "T1021"),   # valid accounts -> remote services
    ("T1021", "T1550"),   # remote services -> use alternate auth material
    ("T1068", "T1134"),   # priv escalation -> access token manipulation
    ("T1134", "T1484"),   # access token -> domain policy modification
}

_CHAIN_MULTIPLIER = 1.8
_PENTEST_CHAIN_MULTIPLIER = 2.5


@dataclass
class VulnNode:
    vuln_id: str
    cve_id: str | None
    cvss_base: float
    attack_vector: str           # network, adjacent, local, physical
    mitre_technique: str | None  # e.g., "T1190"
    post_exploit_access: str     # what access this gives: code_exec, priv_esc, lateral


def detect_chains(nodes: list[VulnNode]) -> list[list[VulnNode]]:
    """
    Find CVE chains within a set of vulns on the same asset.
    Returns a list of chains (each chain is an ordered list of VulnNodes).
    Dead simple graph walk -- not trying to be perfect, just useful.
    """
    chains: list[list[VulnNode]] = []
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            if a.vuln_id == b.vuln_id:
                continue
            if _can_chain(a, b):
                chains.append([a, b])
            elif _can_chain(b, a):
                chains.append([b, a])
    return _deduplicate(chains)


def _can_chain(a: VulnNode, b: VulnNode) -> bool:
    # NodeZero-style reasoning: a network-accessible exploit that
    # results in code execution can feed into a local priv-esc vuln
    if a.attack_vector == "network" and b.attack_vector == "local":
        if a.post_exploit_access in ("code_exec", "priv_esc"):
            return True
    # MITRE technique correlation
    if a.mitre_technique and b.mitre_technique:
        return (a.mitre_technique, b.mitre_technique) in _MITRE_CHAINS
    return False


def _deduplicate(chains: list[list[VulnNode]]) -> list[list[VulnNode]]:
    seen: set[frozenset] = set()
    unique = []
    for chain in chains:
        key = frozenset(n.vuln_id for n in chain)
        if key not in seen:
            seen.add(key)
            unique.append(chain)
    return unique


def chain_score(chain: list[VulnNode], pentest_confirmed: bool = False) -> float:
    """Score a chain: take the max individual CVSS and apply the chain multiplier."""
    base = max((n.cvss_base for n in chain), default=0.0)
    mult = _PENTEST_CHAIN_MULTIPLIER if pentest_confirmed else _CHAIN_MULTIPLIER
    return min(100.0, (base / 10.0) * 100.0 * mult)
