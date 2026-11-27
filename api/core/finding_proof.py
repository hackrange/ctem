"""Proof for one finding: fetched live from the scanner when someone asks (nothing is stored), plus the evidence an
agent such as Tanium reported with its own finding for the same CVE on the same host (stored with that finding).

Rapid7 returns the evidence for each instance of a vulnerability on an asset: what it found and where (for
example "Vulnerable software installed: PHP 8.5.1 (C:\\...\\php.exe)"), the port, and the fix. The proof is
scanner HTML, so it is turned into plain text here and the page only ever shows text.
"""
from __future__ import annotations

import html
import logging
from html.parser import HTMLParser

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("open-ctem.proof")

MAX_TEXT = 20_000
MAX_INSTANCES = 50
_BLOCK = {"p", "div", "ul", "ol", "table", "tr", "br", "pre"}


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "li":
            self.out.append("\n- ")
        elif tag in _BLOCK:
            self.out.append("\n")
        elif tag in ("td", "th"):
            self.out.append("  ")

    def handle_endtag(self, tag):
        if tag in _BLOCK or tag == "li":
            self.out.append("\n")

    def handle_data(self, data):
        self.out.append(data)


def as_text(markup) -> str | None:
    """Scanner HTML to readable plain text: lists become '- ' lines, tags and scripts are dropped."""
    if not isinstance(markup, str) or not markup.strip():
        return None
    p = _Text()
    try:
        p.feed(markup[:200_000])
        p.close()
        text = "".join(p.out)
    except Exception:  # noqa: BLE001 -- malformed markup: fall back to unescaped text without tags
        text = html.unescape(markup)
    text = "".join(ch if ch in "\n\t" or ord(ch) >= 32 else " " for ch in text)
    lines = [ln.rstrip() for ln in text.splitlines()]
    out, blank = [], False
    for ln in lines:
        if not ln.strip():
            if out and not blank:
                out.append("")
            blank = True
            continue
        out.append(ln)
        blank = False
    return "\n".join(out).strip()[:MAX_TEXT] or None


async def _rapid7(db: AsyncSession):
    from api.integrations.base import get_connector
    from api.models.integration import IntegrationConfig, Vendor
    rows = (await db.execute(select(IntegrationConfig).where(
        IntegrationConfig.vendor == Vendor.rapid7_insightvm, IntegrationConfig.is_enabled == True))).scalars().all()  # noqa: E712
    for cfg in rows:
        conn = get_connector("rapid7_insightvm", cfg.config or {})
        if getattr(conn, "_cloud", False) and (cfg.config or {}).get("api_key"):
            return conn
    return None


def agent_instance(p) -> dict | None:
    """An agent's stored proof (what it found against the vulnerable range) as one instance of the proof dialog."""
    tests = [t for t in (p or {}).get("tests") or [] if isinstance(t, dict) and t.get("found")]
    if not tests:
        return None
    lines = [f"Detected: {', '.join(str(x) for x in p.get('products') or [])}"] if p.get("products") else []
    for t in tests:
        lines.append(f"Found: {t['found']}" + (f"\nVulnerable: {t['expected']}" if t.get("expected") else ""))
    s = lambda v: str(v)[:40] if v else None  # noqa: E731
    return {"tool": str(p.get("tool") or "Agent")[:40], "proof": "\n\n".join(lines)[:MAX_TEXT], "port": None,
            "protocol": None, "solution": str(p.get("remediation") or "")[:2000] or None, "fix": None,
            "first_found": s(p.get("first_found")), "last_found": s(p.get("last_found"))}


async def _agents(db: AsyncSession, finding) -> list[dict]:
    """The proof of agent findings merged into this scanner finding (same host, same CVE, still reported)."""
    from api.integrations.scanner_merge import AGENT_SOURCES
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    cve = finding.vuln.cve_id if finding.vuln else None
    if not cve:
        return []
    rows = (await db.execute(select(Finding.details).join(Vulnerability, Vulnerability.id == Finding.vuln_id).where(
        Finding.device_id == finding.device_id, Vulnerability.cve_id == cve, Finding.source.in_(AGENT_SOURCES),
        Finding.status == FindingStatus.merged, Finding.closed_at.is_(None)).limit(5))).scalars().all()
    return [x for x in (agent_instance((d or {}).get("proof")) for d in rows) if x]


async def fetch(db: AsyncSession, finding) -> dict:
    """{'available': bool, 'reason'?: str, 'instances': [...]} for one finding: the scanner's, then any agent's."""
    from api.integrations.scanner_merge import AGENT_SOURCES
    if finding.source in AGENT_SOURCES:
        one = agent_instance((finding.details or {}).get("proof"))
        return {"available": True, "instances": [one]} if one else \
            {"available": False, "reason": "The agent reported no evidence with this finding.", "instances": []}
    if finding.source != "rapid7_insightvm":
        return {"available": False, "reason": "Proof is only available for Rapid7 InsightVM and Tanium findings so far.",
                "instances": []}
    out = await _scanner(db, finding)
    agents = await _agents(db, finding)
    if not agents:
        return out
    if not out["available"]:
        return {"available": True, "note": out.get("reason"), "instances": agents}
    return {**out, "instances": out["instances"] + agents}


async def _scanner(db: AsyncSession, finding) -> dict:
    from api.integrations import rapid7_common as r7
    aid, _, vid = (finding.source_id or "").partition(":")
    if not (r7.safe_id(aid) and r7.safe_id(vid)):
        return {"available": False, "reason": "This finding has no Rapid7 reference to look up.", "instances": []}
    conn = await _rapid7(db)
    if conn is None:
        return {"available": False, "reason": "Showing proof needs the Rapid7 InsightVM cloud integration.",
                "instances": []}
    from api.core.ssrf import safe_client
    try:
        async with safe_client(timeout=20.0) as client:
            resp = await client.post(f"{conn._v4}/assets", headers=r7.headers(conn.config),
                                     params={"size": 1, "includeSame": "true"},
                                     json={"asset": f"asset.id = '{aid}'", "vulnerability": f"vulnerability.id = '{vid}'"})
        resp.raise_for_status()
        assets = (resp.json() or {}).get("data") or []
    except Exception as exc:  # noqa: BLE001 -- logged; the person sees a plain reason
        log.warning("proof lookup failed: %s", type(exc).__name__)
        return {"available": False, "reason": "Rapid7 didn't answer just now. Try again in a minute.", "instances": []}
    out = []
    for a in assets[:1]:
        for f in (a.get("same") or []) + (a.get("new") or []):
            if not isinstance(f, dict) or f.get("vulnerability_id") != vid:
                continue
            port = f.get("port")
            out.append({"tool": "Rapid7 InsightVM", "proof": as_text(f.get("proof")),
                        "port": port if isinstance(port, int) and 0 <= port <= 65535 else None,
                        "protocol": str(f.get("protocol") or "")[:16] or None,
                        "solution": as_text(f.get("solution_summary")),
                        "fix": as_text(f.get("solution_fix")),
                        "first_found": str(f.get("first_found") or "")[:40] or None,
                        "last_found": str(f.get("last_found") or "")[:40] or None})
            if len(out) >= MAX_INSTANCES:
                break
    if not out:
        return {"available": False, "reason": "Rapid7 has no current proof for this finding; it may have been fixed "
                                              "since the last scan.", "instances": []}
    return {"available": True, "instances": out}
