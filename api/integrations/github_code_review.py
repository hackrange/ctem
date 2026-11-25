"""GitHub Code Review (GCR) connector: SAST and DAST telemetry.

What comes in:
  - every repository GCR scans, as a code_repository asset with its application, owners and visibility as tags
  - code, dependency (CVE, KEV, EPSS, reachability), credential and misconfiguration findings on those repositories
  - with the external scope: every external site as a website asset (telemetry, owners, environment, the
    repositories behind it) with the findings of its latest dynamic (DAST) scan
  - links: a repository behind a live site is internet exposed (its code can be reached), and a site whose IP
    belongs to a device CTEM already knows marks that device internet exposed

Findings GCR no longer reports are marked remediated, but only after a complete read. Exceptions approved in
GCR arrive as risk accepted. Exceptions approved in CTEM are written back by gcr_writeback.py."""
from __future__ import annotations

import fnmatch
import logging
import re

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.integrations import gcr_fields
from api.integrations.base import BaseConnector, register
from api.integrations.gcr_client import Gcr, GcrError, floor
from api.integrations.rapid7_common import parse_dt
from api.models.integration import IntegrationConfig, Vendor
from api.core import fixes

log = logging.getLogger("open-ctem.gcr")
SRC = "github_code_review"
CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _band(cvss: float) -> str:
    """The grade a CVSS score falls in."""
    return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low" if cvss > 0 else "info"
# GCR's repositories and sites are this connector's own assets, so it sets all of their tags: what GCR says
# (in CTEM's neutral forms, which Admin > Tag mapping reads) plus the tag map below. Tag them through the map.
MANAGED = ("",)
MAX_RULES = 200


def tag_map(raw) -> list[tuple[str, set[str]]]:
    """'acme/claims-portal* = app:Claims Portal, exec_owner:Jane Doe' per line -> [(pattern, tags)].
    Patterns match a repository's full name or a site's host (* and ?, any case). Raises ValueError with
    a sentence to show."""
    rules = []
    for n, line in enumerate(str(raw or "").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if len(rules) >= MAX_RULES:
            raise ValueError(f"use at most {MAX_RULES} lines")
        if "=" not in line:
            raise ValueError(f"line {n}: write it as pattern = tags")
        pat, tags = (x.strip() for x in line.split("=", 1))
        if not pat or len(pat) > 200 or any(c in pat for c in "<>\x00"):
            raise ValueError(f"line {n}: the pattern is empty or too long")
        wanted = {" ".join(t.split()) for t in tags.split(",") if t.strip()}
        if not wanted or any(len(t) > 128 or ":" not in t or any(c in t for c in "<>") for t in wanted):
            raise ValueError(f"line {n}: tags look like app:Claims Portal, separated by commas")
        rules.append((pat.lower(), wanted))
    return rules


def mapped(name: str, rules) -> set[str]:
    return set().union(*[t for p, t in rules if fnmatch.fnmatchcase((name or "").lower(), p)]) if rules else set()


def _status(state: str | None, excepted: bool, fd: dict | None = None):
    """GCR doesn't reopen a finding when its waiver runs out, so a waiver past its end date counts as open."""
    from api.models.vuln import FindingStatus
    if gcr_fields.ended(fd or {}):
        return FindingStatus.remediated if state == "fixed" else FindingStatus.open
    if excepted or state == "waived":
        return FindingStatus.risk_accepted
    return FindingStatus.remediated if state == "fixed" else FindingStatus.open


def _utc(dt):
    from datetime import timezone
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _tags(**kv) -> set[str]:
    out = set()
    for prefix, values in kv.items():
        for v in values if isinstance(values, (list, tuple, set)) else [values]:
            v = " ".join(str(v or "").split())[:100]
            if v and "<" not in v and ">" not in v:
                out.add(f"{prefix}:{v}")
    return out


def _people(raw) -> list[str]:
    return [p.strip() for p in str(raw or "").replace(";", ",").split(",") if p.strip()][:5]


KIND = {"code": "SAST", "dependency": "Open-source package", "credential": "Secret", "misconfiguration": "Infrastructure as code"}


def _https(u) -> str | None:
    u = str(u or "")
    return u[:600] if u.startswith("https://") else None


def _text(v, n: int) -> str | None:
    v = str(v or "").strip()
    return v[:n] or None


def code_details(f: dict, base: str) -> dict:
    """Everything GCR says about one code finding, so it reads the same here as on GCR's own page: where it is,
    GCR's risk and the reasons, the AI validation, supply-chain and reachability facts, what the repository holds,
    and links to the file and commit. Never a secret value or an author's email."""
    pkg, info, rev = f.get("package") or {}, f.get("vulnerability") or {}, f.get("ai_review") or {}
    cred, weak, risk, asset = f.get("credential") or {}, f.get("weakness") or {}, f.get("risk") or {}, f.get("asset") or {}
    out = {"kind": KIND.get(f.get("kind"), f.get("kind")), "repository": f.get("repository"), "branch": f.get("branch"),
           "branches": [str(b)[:100] for b in (f.get("branches") or [])][:10],
           "file": (f.get("file") or "")[:300] or None, "line": f.get("line") or None, "rule": (f.get("rule") or "")[:200] or None,
           "description": _text(f.get("description"), 2000),
           "cwe": list(weak.get("cwe") or [])[:5], "owasp": list(weak.get("owasp") or [])[:5],
           "commit": (f.get("commit") or "")[:40] or None, "commit_url": _https(f.get("commit_url")), "file_url": _https(f.get("url")),
           "author": _text((f.get("author") or {}).get("name"), 120), "committed_at": (f.get("author") or {}).get("committed_at") or None,
           "fix": _text(rev.get("fix"), 3000),
           "gcr_id": f.get("vuln_id"), "link": f"{base}/findings/{int(f['id'])}" if base and str(f.get("id", "")).isdigit() else None,
           "gcr_risk": {"score": risk.get("score"), "evidence": risk.get("evidence"), "impact": risk.get("impact"),
                        "impact_reason": _text(risk.get("impact_reason"), 400), "likelihood": risk.get("likelihood"),
                        "likelihood_reason": _text(risk.get("likelihood_reason"), 400)} if risk.get("score") else None,
           "asset": {"application": _text(asset.get("application"), 200), "holds": [str(h)[:40] for h in (asset.get("holds") or [])][:10],
                     "visibility": _text(asset.get("visibility"), 40)} if asset else None}
    if rev:
        out["validation"] = {"source": rev.get("source"), "rating": rev.get("rating"), "confidence": rev.get("confidence"),
                             "reviewed_at": rev.get("reviewed_at"), "summary": _text(rev.get("summary"), 3000),
                             "why": _text(rev.get("why"), 3000), "what_to_check": _text(rev.get("what_to_check"), 3000),
                             "compensating_controls": _text(rev.get("compensating_controls"), 2000)}
    if pkg:
        out["package"] = {"name": pkg.get("name"), "version": pkg.get("version"), "fixed_in": pkg.get("fixed_in") or None,
                          "ecosystem": pkg.get("ecosystem"), "declared_in": pkg.get("declared_in") or None,
                          "image": pkg.get("image") or None, "scope": pkg.get("scope") or None}
        out["advisory"] = info.get("id") or None
        # the advisory's own numbers, since the grade here can differ
        if isinstance(info.get("cvss_score"), (int, float)):
            out["advisory_cvss"] = float(info["cvss_score"])
        if isinstance(info.get("epss_score"), (int, float)):
            out["epss"] = float(info["epss_score"])
        if info.get("known_exploited"):
            out["kev"] = True
        if pkg.get("malicious") or f.get("malicious"):
            m = f.get("malicious") or {}
            out["supply_chain"] = {"signal": _text(m.get("signal") or pkg.get("malicious"), 120), "reason": _text(m.get("reason"), 600)}
        if not out["fix"] and pkg.get("fixed_in"):
            out["fix"] = f"Upgrade {pkg.get('name')} to {pkg['fixed_in']} or later."
    if (f.get("reachability") or {}).get("verdict"):
        r = f["reachability"]
        out["reachability"] = {"verdict": r["verdict"], "why": (r.get("reason") or "")[:300],
                               "direct": r.get("direct"), "scope": r.get("scope")}
    if cred:
        out["secret"] = {"verified": bool(cred.get("verified")), "status": cred.get("verification_status"), "exposure": cred.get("exposure") or None}
        out["fix"] = out["fix"] or "Revoke and rotate the credential, then remove it from the repository history."
    out.update(gcr_fields.details(f))
    return {k: v for k, v in out.items() if v not in (None, [], "", {})}


def decided(x: dict, sev: str):
    """A DAST finding's decision in GCR: false positive, an exception until a date, or a new severity.
    Returns (status, severity that counts)."""
    from datetime import date

    from api.models.vuln import FindingStatus
    d = x.get("decision") or {}
    kind = d.get("kind")
    if kind == "false_positive":
        return FindingStatus.false_positive, sev
    if kind == "exception":
        ends = str(d.get("expires") or "")[:10]
        if not ends or ends >= date.today().isoformat():
            return FindingStatus.risk_accepted, sev
    if kind == "severity" and str(d.get("severity") or "").lower() in CVSS:
        return FindingStatus.open, str(d["severity"]).lower()
    return FindingStatus.open, sev


def web_details(x: dict, site: dict, scan: dict, base: str) -> dict:
    d = x.get("decision") or {}
    out = {"kind": "DAST", "url": (x.get("url") or "")[:500] or None, "method": x.get("method") or None,
           "urls": [str(u)[:300] for u in (x.get("urls") or [])][:20], "references": [r.strip() for r in str(x.get("reference") or "").split(",") if r.strip().startswith("https://")][:10],
           "risk": x.get("risk") or None, "risk_basis": (str(x.get("risk_basis") or ""))[:800] or None,
           "likelihood": x.get("likelihood_label") or None, "impact": x.get("breachability_label") or None,
           "tool": ", ".join(x.get("tools") or ([x["tool"]] if x.get("tool") else [])) or None,
           "decision": {"kind": d.get("kind_name") or d.get("kind"), "reason": (str(d.get("reason") or ""))[:500], "by": d.get("by"),
                        "at": d.get("at"), "expires": d.get("expires")} if d.get("kind") else None,
           "parameter": x.get("parameter") or x.get("param") or None, "cwe": x.get("cwe") or None,
           "evidence": (str(x.get("evidence") or ""))[:600] or None, "fix": (str(x.get("remediation") or ""))[:1500] or None,
           "site": site.get("host"), "scanned_at": scan.get("scanned_at"), "engine": scan.get("server"),
           "link": f"{base}/external/{int(site['id'])}" if base and str(site.get("id", "")).isdigit() else None,
           "key": str(x.get("key") or "")[:64] or None, "site_id": site.get("id"), "scan_id": scan.get("id")}
    return {k: v for k, v in out.items() if v not in (None, [], "")}


_SCOPED = re.compile(r"^[a-z_]+:[0-9a-f-]{36}:")


def scoped_key(key: str, iid: str | None) -> str:
    """code:123 -> code:<integration id>:123 (the kind stays first, so "dast:%" still finds web findings)."""
    if not iid or _SCOPED.match(key):
        return key
    kind, rest = key.split(":", 1)
    return f"{kind}:{iid}:{rest}"


def plain_key(key: str) -> str:
    """code:<integration id>:123 -> code:123."""
    return re.sub(r"^([a-z_]+:)[0-9a-f-]{36}:", r"\1", key)


def vuln_key(f: dict) -> tuple[str, str, str | None]:
    """(source id, title, CVE): one vulnerability per CVE or advisory for packages, one per GCR issue otherwise."""
    kind = f.get("kind") or "code"
    v = f.get("vulnerability") or {}
    if kind == "dependency" and v.get("id"):
        pkg = (f.get("package") or {}).get("name") or ""
        cve = v["id"] if str(v["id"]).upper().startswith("CVE-") else None
        return f"pkg:{v['id']}", f"{v['id']} in {pkg}".strip()[:512], cve
    where = f"{f.get('file') or ''}:{f.get('line') or ''}".strip(":")
    title = f"{f.get('title') or f.get('rule') or kind}" + (f" ({where})" if where else "")
    return f"{kind}:{f.get('vuln_id') or f.get('id')}", title[:512], None


@register(Vendor.github_code_review)
class GitHubCodeReviewConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with Gcr(self.config) as g:
                await g.get("/ping")
            return True
        except Exception as e:  # noqa: BLE001 -- the reason is logged by type, never echoed
            log.warning("GCR test failed: %s", type(e).__name__)
            return False

    async def sync(self, db: AsyncSession) -> int:
        keep = set(floor(self.config))
        tag_map(self.config.get("tag_map"))   # a bad map stops the sync with a clear reason
        async with Gcr(self.config) as g:
            repos = await g.repositories()
            found = [f for f in await g.findings("open") + await g.findings("waived") if (f.get("severity") or "info") in keep]
            sites = await g.sites() if self.config.get("include_dast", True) not in (False, "false", "0") else None
            scans = {}
            for s in (sites or [])[:2000]:
                if s.get("id") is not None and (s.get("last_dast") or {}).get("scanned_at"):
                    scans[s["id"]] = await g.latest_scan(s["id"])
        return await self.store(db, repos, found, sites, scans, keep)

    # ── writing ───────────────────────────────────────────────────────────────
    async def store(self, db: AsyncSession, repos: list, found: list, sites: list | None, scans: dict, keep: set) -> int:
        from api.core.device_match import add_source
        from api.core.device_tags import sync_tags
        from api.core.encryption import search_hash
        from api.models.device import Device, DeviceType
        from api.models.vuln import Finding, FindingStatus, Vulnerability

        rules = tag_map(self.config.get("tag_map"))
        base = (str(self.config.get("base_url") or "").strip().rstrip("/")) if str(self.config.get("base_url") or "").startswith("https://") else ""
        site_by_id = {s.get("id"): s for s in sites or []}
        # Each integration's assets are its own (site ids are small numbers, repo names repeat across GCRs): its tags
        # grant access, so another GCR integration must never land on, or retag, them. Older unscoped rows are
        # claimed only when this is the sole GCR integration.
        iid = str(self.integration_id) if self.integration_id else ""
        pref = f"{iid}:" if iid else ""
        mine, legacy = {}, {}
        for d in (await db.execute(select(Device).where(Device.source == SRC))).scalars():
            sid0 = d.source_id or ""
            if pref and sid0.startswith(pref):
                mine[sid0[len(pref):]] = d
            elif sid0.startswith(("repo:", "site:")):
                legacy[sid0] = d
        sole = not iid or (await db.execute(select(func.count()).select_from(IntegrationConfig)
                                            .where(IntegrationConfig.vendor == Vendor.github_code_review))).scalar_one() <= 1
        cache: dict = {}

        async def asset(sid: str, name: str, kind) -> Device:
            d = mine.get(sid)
            if d is None and sole:
                d = legacy.pop(sid, None)
                if d is not None:
                    d.source_id = pref + sid   # claimed for this integration
            if d is None:
                d = Device(hostname=name[:253], device_type=kind, source=SRC, source_id=pref + sid)
                db.add(d)
                await db.flush()
            mine[sid] = d
            d.hostname = name[:253]
            add_source(d, SRC)
            return d

        # repositories, with what each finding says about them (application, owners, visibility)
        facts: dict[str, dict] = {}
        for f in found:
            if f.get("repository"):
                facts.setdefault(f["repository"], f.get("asset") or {})
        repo_dev: dict[str, Device] = {}
        for r in repos:
            name = r.get("full_name")
            if not name or (r.get("archived") and not self.config.get("include_archived")):
                continue
            repo_dev[name] = await asset(f"repo:{name}", name, DeviceType.code_repository)
        for name in facts:
            if name not in repo_dev:
                repo_dev[name] = await asset(f"repo:{name}", name, DeviceType.code_repository)

        # external sites, their telemetry, and the repositories behind them
        site_dev: dict = {}
        behind_live: set[str] = set()
        for s in sites or []:
            host = s.get("host")
            if not host or s.get("id") is None:
                continue
            d = await asset(f"site:{s['id']}", host, DeviceType.website)
            site_dev[s["id"]] = d
            t = s.get("telemetry") or {}
            live = t.get("category") == "live" or bool(t.get("status_code"))
            d.is_internet_exposed = live and s.get("status") != "obsolete"
            ip = t.get("ip")
            if ip:
                d.ip, d.ip_hash = ip, search_hash(ip)
            linked = [x.get("full_name") for x in s.get("repositories") or [] if x.get("full_name") and x.get("linked", True)]
            if d.is_internet_exposed:
                behind_live.update(linked)
            await sync_tags(db, d.id, _tags(app=s.get("application"), env=s.get("environment"),
                                            exec_owner=_people(s.get("executive_owner")),
                                            tech_owner=_people(s.get("technical_owner")),
                                            gcr=[*(s.get("tags") or []), f"grade {t['grade']}" if t.get("grade") else ""],
                                            repo=linked[:10]) | mapped(host, rules), MANAGED, SRC, cache)
            if ip and d.is_internet_exposed:   # a device CTEM already knows answers on this public address
                for other in (await db.execute(select(Device).where(Device.ip_hash == search_hash(ip),
                                                                    Device.source != SRC))).scalars():
                    other.is_internet_exposed = True
        for name, d in repo_dev.items():
            a = facts.get(name) or {}
            d.is_internet_exposed = name in behind_live
            sites_for = [s.get("host") for s in sites or [] if any(x.get("full_name") == name for x in s.get("repositories") or [])]
            await sync_tags(db, d.id, _tags(app=a.get("application"), tech_owner=_people(a.get("technical_owner")),
                                            app_owner=_people(a.get("business_owner")),
                                            gcr=[a.get("visibility") or "", *(a.get("holds") or [])], site=sites_for[:10])
                            | mapped(name, rules), MANAGED, SRC, cache)

        # vulnerabilities and findings
        vulns = {v.source_vuln_id: v for v in (await db.execute(select(Vulnerability).where(Vulnerability.source == SRC))).scalars()}
        iid = str(self.integration_id) if self.integration_id else None
        mine_q = select(Finding).where(Finding.source == SRC)
        if iid:   # this integration's findings and untagged older ones; never another GCR integration's
            mine_q = mine_q.where(or_(Finding.integration_id == iid, Finding.integration_id.is_(None)))
        have = {(f.device_id, f.vuln_id): f for f in (await db.execute(mine_q)).scalars()}
        seen: set = set()
        # Each repo keeps its own grade ("pkg:GHSA-x@info"); a regraded finding moves rows instead of closing
        key_of = {v.id: plain_key(k) for k, v in vulns.items()}
        family: dict = {}
        for (dev_id, vid), f in have.items():
            k = key_of.get(vid)
            if k and k.startswith("pkg:"):
                family.setdefault((dev_id, k.split("@", 1)[0]), []).append(f)

        # Issue numbers and titles are each GCR's own: a vulnerability row is this integration's ("code:<id>:123"),
        # so another GCR can't rewrite its title, score or KEV flag. An older unscoped row is taken over only when
        # every finding on it is this integration's (or untagged), so nothing is closed and reopened.
        legacy = {k: v for k, v in vulns.items() if not _SCOPED.match(k)}
        blocked = {vid for vid, owner in (await db.execute(
            select(Finding.vuln_id, Finding.integration_id).where(Finding.vuln_id.in_([v.id for v in legacy.values()] or ["-"]))
            .distinct())).all() if iid and owner not in (None, iid)}

        def vuln(key: str, title: str, cve: str | None, sev: str) -> Vulnerability:
            sk = scoped_key(key, iid)
            v = vulns.get(sk)
            if v is None and key in legacy and legacy[key].id not in blocked:
                v = legacy.pop(key)
                v.source_vuln_id = sk[:256]
            if v is None:
                v = Vulnerability(source=SRC, source_vuln_id=sk[:256], title=title)
                db.add(v)
            vulns[sk] = vulns[key] = v   # the plain key only names it within this run
            v.title, v.cve_id = title, cve or v.cve_id
            v.domain = "web" if key.startswith("dast:") else "code"   # DAST findings are web apps, the rest code
            if v.cvss_base is None or sev:
                v.cvss_base = CVSS.get(sev, 5.0)
            return v

        async def finding(dev: Device, v: Vulnerability, gid, status, first, last, details=None, fam=None) -> Finding:
            if v.id is None:
                await db.flush()
            f = have.get((dev.id, v.id))
            if f is None and fam:   # the same advisory on this repository under another grade: move it here
                f = next((x for x in family.get((dev.id, fam), []) if x.vuln_id != v.id and (dev.id, x.vuln_id) not in seen
                          and have.get((dev.id, x.vuln_id)) is x), None)
                if f is not None:
                    del have[(dev.id, f.vuln_id)]
                    f.vuln_id = v.id
                    have[(dev.id, v.id)] = f
            if f is None:
                f = Finding(device_id=dev.id, vuln_id=v.id, source=SRC, source_id=str(gid)[:256])
                db.add(f)
                have[(dev.id, v.id)] = f
            if iid:
                f.integration_id = iid   # claims an untagged row; others' rows were never loaded
            f.domain = "web" if dev.device_type == DeviceType.website else "code"
            if details and ((dev.id, v.id) not in seen or status == FindingStatus.open):
                sent = (f.details or {}).get("tool_exception")   # what CTEM told GCR about this finding stays
                f.details = {**details, **({"tool_exception": sent} if sent else {})}
                fk, fx = fixes.package_fix(SRC, details.get("package"))   # one upgrade resolves all its advisories
                f.fix_key = fk
                if fk and (fk not in upgrades or fixes._ver(fx["version"]) > fixes._ver(upgrades[fk]["version"])):
                    upgrades[fk] = fx
            before = f.status
            if (dev.id, v.id) not in seen or status == FindingStatus.open:   # an open copy on any branch wins
                f.status = status
            if f.exception_id and f.status == FindingStatus.open:   # an exception or false positive made in CTEM holds
                f.status = before if before in (FindingStatus.risk_accepted, FindingStatus.false_positive) else FindingStatus.risk_accepted
            f.first_detected = min([x for x in (_utc(f.first_detected), first) if x], default=None)
            f.last_seen = max([x for x in (_utc(f.last_seen), last) if x], default=None)
            seen.add((dev.id, v.id))
            return f

        count, upgrades = 0, {}
        graded: dict[str, tuple[str, float | None]] = {}   # key -> (highest current grade, the advisory's CVSS)
        for fd in found:
            dev = repo_dev.get(fd.get("repository"))
            if dev is None:
                continue
            key, title, cve = vuln_key(fd)
            sev = str(fd.get("severity") or "medium").lower()   # GCR's current grade (after regrades), not as first found
            info = fd.get("vulnerability") or {}
            adv = float(info["cvss_score"]) if isinstance(info.get("cvss_score"), (int, float)) else None
            fam = key if key.startswith("pkg:") else None
            if fam and sev in CVSS and sev != (_band(adv) if adv is not None else "medium"):
                key, title = f"{fam}@{sev}", f"{title} (graded {sev} here)"[:512]
            v = vuln(key, title, cve, sev)
            gcr_fields.advisory(v, info)
            was = graded.get(key)
            if was is None or _RANK.get(sev, 2) > _RANK.get(was[0], 2):
                graded[key] = (sev, adv if adv is not None else (was[1] if was else None))
            v.is_kev = bool(info.get("known_exploited")) or v.is_kev
            v.exploit_available = v.is_kev or v.exploit_available
            if info.get("epss_score") is not None:
                v.epss_score = float(info["epss_score"])
            review = fd.get("ai_review") or {}
            v.description = "\n".join(x for x in (fd.get("description") or "", f"Fix: {review['fix']}" if review.get("fix") else "",
                                                  fd.get("url") or "") if x)[:4000] or None
            f = await finding(dev, v, fd.get("id"), _status(fd.get("state"), bool(fd.get("excepted")), fd),
                              parse_dt(fd.get("first_found")), parse_dt(fd.get("last_found")), code_details(fd, base), fam)
            verdict = (fd.get("reachability") or {}).get("verdict")
            if verdict in ("reachable", "unlikely"):
                f.is_reachable, f.reachability_source = verdict == "reachable", SRC
            count += 1
        for key, (sev, adv) in graded.items():   # the score follows the current grade; the advisory's CVSS when it agrees
            v = vulns[key]
            v.cvss_base = adv if adv is not None and _band(adv) == sev else CVSS.get(sev, 5.0)
            if adv is not None and _band(adv) != sev and v.description and "Advisory CVSS" not in v.description:
                v.description = f"Advisory CVSS {adv:g}; Code Review grades it {sev}.\n{v.description}"[:4000]

        for site_id, scan in scans.items():
            dev = site_dev.get(site_id)
            if dev is None or not scan:
                continue
            at = parse_dt(scan.get("scanned_at"))
            for x in scan.get("findings") or []:
                found_as = (x.get("severity_found") or x.get("severity") or "medium").lower()
                status, sev = decided(x, (x.get("severity") or "medium").lower())
                if not x.get("title") or found_as not in keep:
                    continue
                if sev not in keep:   # GCR lowered it below what this integration brings in: no longer counted here
                    status = FindingStatus.risk_accepted
                v = vuln(f"dast:{x['title'][:200].lower()}", f"{x['title']}"[:512], None, sev)
                v.attack_vector = "network"
                if x.get("remediation") and not v.description:
                    v.description = str(x["remediation"])[:4000]
                await finding(dev, v, f"{site_id}:{scan.get('id')}", status, at, at,
                              web_details(x, site_by_id.get(site_id, {}), scan, base))
                count += 1

        # what GCR no longer reports is fixed; only for assets this read covered completely
        covered = {d.id for d in repo_dev.values()} | {site_dev[s].id for s in scans if scans[s] and s in site_dev}
        for (dev_id, vid), f in have.items():
            if dev_id in covered and (dev_id, vid) not in seen and f.status in (FindingStatus.open, FindingStatus.in_progress):
                f.status = FindingStatus.remediated
        await fixes.save(db, upgrades)
        await db.commit()
        log.info("GCR: %d repositories, %d sites, %d findings", len(repo_dev), len(site_dev), count)
        return count


__all__ = ["GitHubCodeReviewConnector", "GcrError"]
