"""What kind of work a finding is, by who fixes it:

  infra  hosts, network devices and cloud instances (InsightVM, Qualys, Tenable, Defender...): IT and operations
  code   repositories: SAST, open-source packages, secrets, infrastructure as code (Snyk, GitHub, GCR...): developers
  web    web applications: DAST and web application scanning (Rapid7 AppSec, GCR's external sites...): app owners

Connectors that know set it as they write (GCR splits by asset: a repository's findings are code, a site's are
web). Anything else takes its source's type when inserted, and fill() brings existing rows in line."""
from __future__ import annotations

import logging

from sqlalchemy import case, select, update

log = logging.getLogger("open-ctem.finding_domain")
DOMAINS = ("infra", "code", "web")
LABELS = {"infra": "Infrastructure", "code": "Code", "web": "Web apps"}
# Sources whose findings are always one type. A source missing here is infrastructure, except mixed ones below.
CODE_SOURCES = ("snyk", "github_advanced", "forgerepo")
WEB_SOURCES = ("rapid7_appsec",)
MIXED_SOURCES = ("github_code_review",)   # sets the type per finding


def for_source(source: str | None) -> str:
    return "code" if source in CODE_SOURCES else "web" if source in WEB_SOURCES else "infra"


def sources_by_domain(sources) -> dict[str, list[str]]:
    """Which of these sources can produce each type (a mixed one appears under code and web)."""
    out = {d: [] for d in DOMAINS}
    for s in sources:
        if s in MIXED_SOURCES:
            out["code"].append(s)
            out["web"].append(s)
        else:
            out[for_source(s)].append(s)
    return out


def set_default(target) -> None:
    """Before a finding or vulnerability is inserted: a type the connector set stays; otherwise its source's."""
    if not getattr(target, "domain", None):
        target.domain = for_source(getattr(target, "source", None))


async def fill(db) -> int:
    """Bring existing rows in line: vulnerabilities by source (GCR: DAST keys are web, the rest code), then each
    finding from its vulnerability. Touches only rows still marked infrastructure that shouldn't be."""
    from api.models.vuln import Finding, Vulnerability
    n = 0
    gcr = case((Vulnerability.source_vuln_id.like("dast:%"), "web"), else_="code")
    for cond, value in ((Vulnerability.source.in_(CODE_SOURCES), "code"), (Vulnerability.source.in_(WEB_SOURCES), "web"),
                        (Vulnerability.source.in_(MIXED_SOURCES), gcr)):
        r = await db.execute(update(Vulnerability).where(cond, Vulnerability.domain == "infra").values(domain=value)
                             .execution_options(synchronize_session=False))
        n += r.rowcount or 0
    for d in ("code", "web"):   # through the vuln_id index: only the few non-infrastructure vulnerabilities
        ids = select(Vulnerability.id).where(Vulnerability.domain == d)
        r = await db.execute(update(Finding).where(Finding.vuln_id.in_(ids), Finding.domain != d).values(domain=d)
                             .execution_options(synchronize_session=False))
        n += r.rowcount or 0
    await db.commit()
    if n:
        log.info("finding types set on %d rows", n)
    return n
