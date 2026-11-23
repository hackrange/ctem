"""GitHub Code Review's newer finding fields: why it has its grade, triage, waiver or exclusion, advisory details."""
from __future__ import annotations

from datetime import date, datetime, timezone

SEVERITIES = ("critical", "high", "medium", "low", "info")
# What set the grade GCR shows; anything else is shown as GCR sent it
GRADE_SOURCE = {"engine": "the scanner", "custom": "a person's regrade", "org_rule": "an organization severity rule",
                "kev_raise": "known exploited (raised)", "reach_unlikely": "unlikely to be reachable (lowered)",
                "base_image": "fixed by a base image upgrade (lowered)", "not_applicable": "triaged not applicable",
                "expired_secret": "an expired secret",  # nosec B105 -- a label for a grade source, not a password
                "ai_validation": "AI validation", "learned_rule": "a learned rule"}
AV = {"n": "network", "a": "adjacent", "l": "local", "p": "physical"}


def _t(v, n: int) -> str | None:
    v = " ".join(str(v or "").split())
    return v[:n] or None


def _sev(v) -> str | None:
    v = str(v or "").lower()
    return v if v in SEVERITIES else None


def _key(v) -> str | None:
    v = str(v or "").strip().lower()
    return v[:40] if v and v.replace("_", "").isalnum() else None


def details(f: dict) -> dict:
    """The extra facts for a finding's details, only those GCR sent."""
    out: dict = {}
    g = f.get("grade") if isinstance(f.get("grade"), dict) else {}
    if _sev(g.get("severity")):
        src = _key(g.get("source"))
        out["grade"] = {k: v for k, v in {
            "severity": _sev(g.get("severity")), "engine_severity": _sev(g.get("engine_severity")),
            "source": src, "source_label": GRADE_SOURCE.get(src or "", (src or "").replace("_", " ") or None),
            "by": _t(g.get("by"), 120), "at": _t(g.get("at"), 40), "reason": _t(g.get("reason"), 1500)}.items() if v}
        val = g.get("validation") if isinstance(g.get("validation"), dict) else {}
        if val.get("rating"):
            out["grade"]["validation"] = {"rating": _t(val["rating"], 20), "confidence": _t(val.get("confidence"), 20)}
    tr = f.get("triage") if isinstance(f.get("triage"), dict) else {}
    if tr.get("state") or tr.get("reason"):
        out["triage"] = {k: v for k, v in {"state": _key(tr.get("state")), "reason": _t(tr.get("reason"), 800)}.items() if v}
    if _key(f.get("confidence")):
        out["confidence"] = _key(f.get("confidence"))
    engines = [e for e in (_t(x, 40) for x in (f.get("engines") or [])[:6]) if e]
    if engines:
        out["engines"] = engines
    if f.get("corroborated"):
        out["corroborated"] = True
    if f.get("out_of_scope"):
        out["out_of_scope"] = True
    exc = f.get("exception") if isinstance(f.get("exception"), dict) else {}
    source = _key(f.get("exception_source"))
    if source or exc:
        out["gcr_exception"] = {k: v for k, v in {
            "source": source or ("waiver" if exc else None), "status": _key(exc.get("status")),
            "category": _key(exc.get("category")), "reason": _t(f.get("exception_reason") or exc.get("reason"), 600),
            "by": _t(f.get("exception_by") or exc.get("decided_by") or exc.get("requested_by"), 120),
            "expires": _t(f.get("exception_expires_at") or exc.get("expires_at"), 40)}.items() if v}
    return out


def ended(f: dict) -> bool:
    """An approved waiver (or excepted finding) past its end date: GCR doesn't reopen it, so it counts as open."""
    exc = f.get("exception") if isinstance(f.get("exception"), dict) else {}
    end = f.get("exception_expires_at") or (exc.get("expires_at") if exc.get("status") == "approved" else None)
    if not end:
        return False
    try:
        at = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
    except ValueError:
        return False
    return (at if at.tzinfo else at.replace(tzinfo=timezone.utc)) <= datetime.now(timezone.utc)


def advisory(v, info: dict) -> None:
    """The advisory's CVSS vector, attack vector and CISA KEV date, onto the vulnerability (when GCR has them)."""
    vec = _t(info.get("cvss_vector"), 256)
    if vec and all(c.isalnum() or c in ":/._" for c in vec):
        v.cvss_vector = vec
    av = str(info.get("attack_vector") or "").strip().lower()
    if not av and vec and "AV:" in vec:
        av = vec.split("AV:", 1)[1][:1].lower()
    av = AV.get(av, av)
    if av in AV.values():
        v.attack_vector = av
    kev = str(info.get("kev_added") or "")[:10]
    try:
        v.kev_added_date = date.fromisoformat(kev) if kev else v.kev_added_date
    except ValueError:
        pass
