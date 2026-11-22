"""
Page-level access control.

Each page has a set of tags and a minimum role requirement.
Access is granted when ANY of these match for the requesting user:
  - User has admin or cyber role (always gets everything)
  - User's role is in the page's allowed_roles
  - User has at least one tag that intersects the page's tags (ABAC)

Tags are free-form strings assigned to users by admins (e.g. "identity", "vuln", "grc").
They let orgs give business stakeholders or IT users targeted access without
granting a full analyst role.

Returns 404 on denied -- no enumeration oracle (consistent with BOLA policy).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── Page registry ─────────────────────────────────────────────────────────────

@dataclass
class PagePolicy:
    slug: str
    tags: list[str] = field(default_factory=list)
    allowed_roles: list[str] = field(default_factory=list)
    min_role: str | None = None  # kept for future strict ordering; unused today


# slug -> policy
_PAGES: dict[str, PagePolicy] = {p.slug: p for p in [
    PagePolicy("/",                allowed_roles=["admin","cyber","it_user","business_stakeholder","read_only"],
                                   tags=["dashboard"]),
    PagePolicy("/devices",         allowed_roles=["admin","cyber","it_user","read_only"],
                                   tags=["devices","cmdb"]),
    PagePolicy("/users",           allowed_roles=["admin","cyber","it_user","read_only"],
                                   tags=["users","devices","identity"]),
    PagePolicy("/software",        allowed_roles=["admin","cyber","it_user","read_only","inventory"],   # their own assets
                                   tags=["devices","cmdb"]),
    PagePolicy("/vulns",           allowed_roles=["admin","cyber","it_user","read_only"],   # IT users: their own assets
                                   tags=["vuln","cve"]),
    PagePolicy("/dashboards",      allowed_roles=["admin","cyber","grc","it_user","read_only","inventory","business_stakeholder"],
                                   tags=["dashboard"]),
    PagePolicy("/exceptions",      allowed_roles=["admin","cyber","it_user"],
                                   tags=["vuln"]),
    PagePolicy("/threat",          allowed_roles=["admin","cyber"],
                                   tags=["threat","soc"]),
    PagePolicy("/identity",        allowed_roles=["admin","cyber"],
                                   tags=["identity","itdr","saas"]),
    PagePolicy("/hunt",            allowed_roles=["admin","cyber"],
                                   tags=["threat","hunt","soc"]),
    PagePolicy("/attack-paths",    allowed_roles=["admin","cyber"],
                                   tags=["threat","vuln"]),
    PagePolicy("/grc",             allowed_roles=["admin","cyber","business_stakeholder","read_only"],
                                   tags=["grc","risk","compliance"]),
    PagePolicy("/cloud",           allowed_roles=["admin","cyber"]),   # matches the API: the whole estate's exposure
    PagePolicy("/cmdb",            allowed_roles=["admin","cyber","it_user","read_only"],
                                   tags=["cmdb","devices"]),
    PagePolicy("/settings/integrations", allowed_roles=["admin"],
                                         tags=["admin"]),
    PagePolicy("/settings/sso",    allowed_roles=["admin"],
                                   tags=["admin"]),
    PagePolicy("/settings/shippers", allowed_roles=["admin"],
                                     tags=["admin"]),
    PagePolicy("/settings/tokens", allowed_roles=["admin"],
                                   tags=["admin"]),
    PagePolicy("/admin",           allowed_roles=["admin"],
                                   tags=["admin"]),
]}

_ALWAYS_ALLOW = {"admin", "cyber"}


def can_access_page(slug: str, user_roles: list[str], user_tags: list[str]) -> bool:
    """
    Returns True if the user may view this page.
    Caller should 404 on False -- never 403 (no info leakage).
    """
    if any(r in _ALWAYS_ALLOW for r in user_roles):
        return True

    policy = _PAGES.get(slug)
    if policy is None:
        return True  # unknown pages are open (404 from template loader anyway)

    if any(r in policy.allowed_roles for r in user_roles):
        return True

    if any(t in policy.tags for t in (user_tags or [])):
        return True

    return False


def page_tags_for(slug: str) -> list[str]:
    """Return the tags associated with a page (for display in admin UI)."""
    p = _PAGES.get(slug)
    return p.tags if p else []


def all_pages() -> list[dict]:
    """Serializable list of all pages with their policies -- for the admin UI."""
    return [
        {"slug": p.slug, "tags": p.tags, "allowed_roles": p.allowed_roles}
        for p in _PAGES.values()
    ]
