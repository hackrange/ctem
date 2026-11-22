"""Reading GitHub Code Review (GCR), a SAST and DAST platform, over its token API (/api/v1).

Two scopes are used, both read-only here:
  reports   findings (code, dependency, credential, misconfiguration) and the repository list
  external  external sites, their telemetry and dynamic (DAST) scans: an administrator's token, optional

Only the configured host is called, through the SSRF-safe client; paging is bounded."""
from __future__ import annotations

import logging
from urllib.parse import urlsplit

from api.core.ssrf import safe_client

log = logging.getLogger("open-ctem.gcr")
PAGE = 1000            # the API's largest page
MAX_PAGES = 500        # 500,000 findings is far past any estate; stop rather than loop forever
SEVERITIES = ("critical", "high", "medium", "low", "info")


class GcrError(Exception):
    """A fixed, user-safe reason (never the server's text)."""


def base_url(config: dict) -> str:
    raw = str(config.get("base_url") or "").strip().rstrip("/")
    p = urlsplit(raw)
    if p.scheme != "https" or not p.hostname:
        raise GcrError("The GitHub Code Review URL must start with https://")
    return f"https://{p.netloc}"


def floor(config: dict) -> tuple[str, ...]:
    """Severities to bring in, from the configured minimum (default medium)."""
    m = str(config.get("min_severity") or "medium").lower()
    return SEVERITIES[: SEVERITIES.index(m) + 1] if m in SEVERITIES else SEVERITIES[:3]


class Gcr:
    def __init__(self, config: dict):
        self.base = base_url(config) + "/api/v1"
        token = str(config.get("api_token") or "")
        if not token:
            raise GcrError("Add an API token (Settings > API tokens in GitHub Code Review)")
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        self.client = None

    async def __aenter__(self):
        self.client = safe_client(timeout=120.0)   # a 1,000-finding page from a large estate can be slow   # the safe client handles redirects itself (re-checking each hop)
        await self.client.__aenter__()
        return self

    async def __aexit__(self, *exc):
        await self.client.__aexit__(*exc)

    async def get(self, path: str, params: dict | None = None, allow_forbidden: bool = False):
        r = await self._get(path, params or {})
        if r.status_code in (401, 403) and allow_forbidden:
            return None
        if r.status_code == 401:
            raise GcrError("GitHub Code Review refused the token: check it hasn't expired or been revoked")
        if r.status_code == 403:
            raise GcrError("The token is missing a scope: it needs reports (and external for DAST)")
        if r.status_code >= 400:
            raise GcrError(f"GitHub Code Review answered {r.status_code}")
        return r.json()

    async def _get(self, path: str, params: dict, tries: int = 3):
        """GET with retries: a timeout or a dropped connection on one page shouldn't fail a whole sync."""
        import asyncio

        import httpx
        for attempt in range(tries):
            try:
                r = await self.client.get(self.base + path, headers=self.headers, params=params)
                if r.status_code in (502, 503, 504) and attempt < tries - 1:   # the load balancer or GCR is busy
                    await asyncio.sleep(3 * (attempt + 1))
                    continue
                return r
            except (httpx.TimeoutException, httpx.TransportError) as e:
                if attempt == tries - 1:
                    where = f"{path}" + (f", page {int(params.get('offset', 0)) // PAGE + 1}" if "offset" in params else "")
                    what = "didn't answer in time" if isinstance(e, httpx.TimeoutException) else "dropped the connection"
                    raise GcrError(f"GitHub Code Review {what} ({where}) after {tries} tries") from e
                await asyncio.sleep(3 * (attempt + 1))

    async def post(self, path: str, body: dict) -> tuple[int, dict]:
        """A write (only exception requests, approvals and decisions use this). Returns (status, body)."""
        r = await self.client.post(self.base + path, headers={**self.headers, "Content-Type": "application/json"}, json=body)
        try:
            data = r.json()
        except ValueError:
            data = {}
        return r.status_code, data if isinstance(data, dict) else {}

    async def pages(self, path: str, key: str, params: dict | None = None, allow_forbidden: bool = False) -> list | None:
        """Every row of a paged list. None when the token may not read it (allow_forbidden)."""
        out, offset = [], 0
        for _ in range(MAX_PAGES):
            body = await self.get(path, {**(params or {}), "limit": PAGE, "offset": offset}, allow_forbidden)
            if body is None:
                return None
            rows = body.get(key) or []
            out.extend(rows)
            offset += len(rows)
            if not rows or offset >= int(body.get("total") or 0):
                return out
        log.warning("GCR %s stopped after %d pages", path, MAX_PAGES)
        return out

    async def findings(self, state: str) -> list[dict]:
        """Every finding in a state, including the backlog and excepted ones (CTEM tracks exceptions itself)."""
        return await self.pages("/findings", "findings", {"state": state, "baseline": "any", "exception": "any",
                                                          "triage": "work", "reach": "any"}) or []

    async def repositories(self) -> list[dict]:
        return await self.pages("/repositories", "repositories") or []

    async def sites(self) -> list[dict] | None:
        """External sites, or None when the token has no external scope (DAST is then skipped)."""
        return await self.pages("/external/assets", "assets", allow_forbidden=True)

    async def latest_scan(self, asset_id: int) -> dict | None:
        """The newest finished dynamic scan of a site, with its findings."""
        listing = await self.get(f"/external/assets/{int(asset_id)}/scans", {"limit": 10}, allow_forbidden=True)
        for s in (listing or {}).get("scans") or []:
            if s.get("status") == "done" and s.get("id") is not None:
                return await self.get(f"/external/assets/{int(asset_id)}/scans/{int(s['id'])}", allow_forbidden=True)
        return None
