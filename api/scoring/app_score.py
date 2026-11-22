"""Risk for Code (repositories) and Web apps (sites), which are not computers.

The host formula leans on EPSS (only CVEs have it), EDR and "last seen", none of which mean anything for a repository
or a site. Here a finding's score is how bad it is, scaled by where it lives:

  how bad      the geometric mean of severity (CVSS, or the tool's severity) and exploitability, so it is only bad
               when both are (nothing harmful to exploit scores nothing). Exploitability is the strongest of known exploited
               (KEV), EPSS, the tool's likelihood, a secret confirmed live, a scanner's proof, a package the code
               reaches (and much lower when it doesn't)
  where        x (0.5 + 0.3 x impact + 0.2 x exposure), so 0.5 to 1.0:
               impact: a criticality tag, else data held (PII, payment, customer data, logins), else the environment
               exposure: a live internet-facing site, or code running behind one, or code that isn't exposed

Context scales a finding rather than adding to it, so a minor finding stays minor on a production site (a changed
server banner is not a C because the site is live), while a critical, exploitable one on a sensitive live site is an F.
When the tool rated the finding itself (GitHub Code Review's 0-100 risk for code, its risk level for site scans),
the two are averaged. A known-exploited finding is never below 80. An asset scores its worst finding, plus a point
for each further serious one (at most 10), so ten critical findings rank above one. Every score keeps its reasons."""
from __future__ import annotations

CONTEXT_FLOOR, IMPACT_WEIGHT, EXPOSURE_WEIGHT = 0.5, 0.3, 0.2   # where: scales "how bad" by 0.5 to 1.0
TOOL_RISK = {"critical": 90.0, "high": 75.0, "medium": 50.0, "low": 25.0, "info": 10.0, "informational": 10.0, "none": 5.0}
LIKELIHOOD = {"certain": 95, "almost certain": 95, "very likely": 90, "likely": 80, "possible": 55,
              "unlikely": 25, "rare": 10, "remote": 10}
CRITICALITY = {"very high": 1.0, "critical": 1.0, "high": 0.85, "medium": 0.6, "low": 0.35, "very low": 0.2}
SENSITIVE = ("pci", "pii", "phi", "hipaa", "sox", "cui", "customer data", "payment", "login", "credential", "secret")
NON_PROD = ("dev", "qa", "test", "stg", "stage", "staging", "sandbox", "uat", "clone", "demo")
SERIOUS = 70.0


def impact(criticality: str | None, holds: list[str], env: list[str]) -> tuple[float, str]:
    """0-1 and why: an explicit criticality wins, then what the asset holds, then where it runs."""
    c = (criticality or "").strip().lower()
    if c in CRITICALITY:
        return CRITICALITY[c], f"criticality {criticality}"
    sensitive = [h for h in holds if any(s in h.lower() for s in SENSITIVE)]
    if sensitive:
        return 0.9, f"holds {', '.join(sensitive[:3])}"
    envs = [e.lower() for e in env]
    if envs and all(any(n in e for n in NON_PROD) for e in envs):
        return 0.4, f"non-production ({', '.join(env[:2])})"
    if any("prod" in e for e in envs):
        return 0.8, "production"
    if holds and all("public" in h.lower() for h in holds):
        return 0.35, "public data only"
    return 0.6, "no data classification yet"


def exposure(kind: str, live: bool) -> tuple[float, str]:
    if kind == "web":
        return (100.0, "live on the internet") if live else (40.0, "not reachable from the internet")
    return (80.0, "runs behind a live public site") if live else (40.0, "not known to run behind a public site")


def exploitability(cvss: float, epss: float, kev: bool, details: dict) -> tuple[float, str]:
    """0-100 and why: the strongest evidence the finding has."""
    x = details or {}
    best, why = 50.0, "no exploitation evidence either way"
    cands = []
    if kev:
        cands.append((100.0, "known exploited (KEV)"))
    if epss:
        cands.append((round(epss * 100, 1), f"EPSS {epss * 100:.1f}%"))
    lik = str(((x.get("gcr_risk") or {}).get("likelihood")) or x.get("likelihood") or "").lower()
    if lik in LIKELIHOOD:
        cands.append((float(LIKELIHOOD[lik]), f"the tool rates it {lik}"))
    sec = x.get("secret")
    if sec:
        cands.append((100.0, "secret confirmed live") if sec.get("verified") else (65.0, "a committed secret, not confirmed live"))
    if x.get("proof") or x.get("attack_value"):
        cands.append((85.0, "the scanner proved it"))
    reach = (x.get("reachability") or {}).get("verdict")
    if reach == "reachable":
        cands.append((80.0, "the code reaches it"))
    if cands:
        best, why = max(cands, key=lambda c: c[0])
    if reach == "unlikely" and not kev and best <= 80:
        best, why = min(best, 30.0), "the code is unlikely to reach it"
    return best, why


def score_finding(cvss: float, epss: float, kev: bool, details: dict, kind: str, crit: tuple[float, str],
                  expo: tuple[float, str]) -> tuple[float, list[str]]:
    sev = max(0.0, min(10.0, cvss or 0.0)) * 10
    exp, exp_why = exploitability(cvss, epss, kev, details)
    bad = (sev * exp) ** 0.5   # both must be high for a finding to be bad
    context = CONTEXT_FLOOR + IMPACT_WEIGHT * crit[0] + EXPOSURE_WEIGHT * expo[0] / 100
    score = bad * context
    reasons = [f"severity {cvss:.1f}", exp_why, f"impact: {crit[1]}", f"exposure: {expo[1]}",
               f"{bad:.1f} x context {context:.2f} = {score:.1f}"]
    tool = (details or {}).get("gcr_risk") or {}
    level = str((details or {}).get("risk") or "").lower()
    if isinstance(tool.get("score"), (int, float)):
        score = (score + float(tool["score"])) / 2
        reasons.append(f"averaged with the tool's own risk {tool['score']}")
    elif level in TOOL_RISK:   # a site scan's risk level (GCR weighs likelihood and impact for each site finding)
        score = (score + TOOL_RISK[level]) / 2
        reasons.append(f"averaged with the tool's risk level {level} ({TOOL_RISK[level]:g})")
    if kev:
        score = max(score, 80.0)
    return round(max(0.0, min(100.0, score)), 1), reasons


def roll_up(scores: list[float]) -> tuple[float, str]:
    """The worst finding, plus 1 point for each further serious one (at most 10)."""
    if not scores:
        return 0.0, "no open findings"
    worst = max(scores)
    more = max(0, sum(1 for s in scores if s >= SERIOUS) - 1)
    bonus = min(10.0, float(more))
    return round(min(100.0, worst + bonus), 1), (f"worst finding {worst}" + (f", plus {bonus:g} for {more} more serious ones" if more else ""))
