"""Fixes: the patch, upgrade or rollup a source recommends, shared by every finding it resolves.

4 million findings are too many to reason about; a few hundred fixes are not. Scanners already say which fix resolves
each finding (InsightVM's solution, with "rollup" for one that supersedes many older patches; a package scanner's
fixed version), so findings carry fix_key and the catalog keeps one row per fix. Steps are kept as plain text with
their http(s) links: the source's HTML is never stored or served."""
from __future__ import annotations

import logging
import re
from html.parser import HTMLParser

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)
_ID = re.compile(r"^[A-Za-z0-9._:@/+\-]{1,120}$")


def key(source: str, solution_id) -> str | None:
    """'<source>:<id>', or None for an id that isn't a plain identifier."""
    sid = str(solution_id or "").strip()
    return f"{source}:{sid}"[:160] if _ID.match(sid) else None


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.links = [], []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href") or ""
            if href.lower().startswith(("https://", "http://")) and len(href) <= 500 and href not in self.links:
                self.links.append(href)
        if tag in ("p", "br", "li", "div", "tr"):
            self.parts.append("\n")

    def handle_data(self, data):
        self.parts.append(data)


def plain(html: str | None, limit: int = 4000) -> tuple[str | None, list[str]]:
    """Text and http(s) links from a source's HTML steps."""
    if not html:
        return None, []
    p = _Text()
    try:
        p.feed(str(html)[:20000])
    except Exception:  # noqa: BLE001 -- malformed markup: keep what parsed
        log.debug("fix steps only partly parsed")
    text = re.sub(r"[ \t]+", " ", "".join(p.parts))
    text = re.sub(r"\n\s*\n+", "\n", text).strip()
    return (text[:limit] or None), p.links[:10]


def _ver(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else -1 for x in re.split(r"[.\-+]", str(v or ""))[:6])


def package_fix(source: str, pkg: dict | None) -> tuple[str | None, dict | None]:
    """For an open-source package finding: one fix per package (upgrading it resolves all its advisories)."""
    pkg = pkg or {}
    name, fixed = str(pkg.get("name") or "").strip(), str(pkg.get("fixed_in") or "").strip()
    eco = str(pkg.get("ecosystem") or "").strip().lower()
    k = key(source, f"pkg:{eco + ':' if eco else ''}{name}") if name and fixed else None
    if not k:
        return None, None
    return k, {"source": source, "title": f"Upgrade {name} to {fixed} or later"[:512], "kind": "upgrade",
               "version": fixed, "steps": None, "links": []}


async def save(db: AsyncSession, found: dict[str, dict]) -> None:
    """Upsert catalog rows: {key: {source, title, kind, steps, links, version?}}. For package upgrades the highest
    fixed version wins, so the title names the version that resolves every advisory."""
    from api.models.vuln import Fix
    if not found:
        return
    have = {f.key: f for f in (await db.execute(select(Fix).where(Fix.key.in_(list(found))))).scalars()}
    for k, v in found.items():
        row = have.get(k)
        if row is None:
            db.add(Fix(key=k, source=v["source"], title=v["title"][:512], kind=v.get("kind"), steps=v.get("steps"),
                       links=v.get("links") or None))
            continue
        if v.get("version"):
            old = re.search(r" to (\S+) or later$", row.title or "")
            if old and _ver(old.group(1)) >= _ver(v["version"]):
                continue
        row.title, row.kind = v["title"][:512], v.get("kind") or row.kind
        row.steps, row.links = v.get("steps") or row.steps, v.get("links") or row.links
