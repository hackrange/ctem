"""Okta (identity provider), read only.

What it reads, with GETs on an allow-list of paths and nothing else:
  Users          each person's account state, sign-in name (UPN), phones, title and department
  Devices        every device registered with Okta Verify and the people signed in on it, so a workstation with no
                 EDR still gets its user (api/integrations/okta_ingest.py)
  MFA factors    which factors each person has enrolled, and the phone their SMS factor sends codes to: a phone the
                 person proved they hold, which beats a directory field for reaching them
  System Log     security events: ThreatInsight, denied pushes (MFA fatigue), lockouts, suspicious-activity reports,
                 breached credentials and admin role grants (api/integrations/okta_signals.py)

Give the API token to a read-only admin (Okta's Read-Only Administrator role): that keeps it read-only on Okta's side.
The allow-list here is CTEM's own guarantee on top of it. Okta's rate limits are shared with everything else in the
org, so CTEM backs off well before a bucket runs dry (see _pace)."""
from __future__ import annotations

import asyncio
import logging
import re
import time
from urllib.parse import urlsplit

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.okta")
_HOST = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_ID = r"[A-Za-z0-9]{10,40}"
# The only paths CTEM reads. Anything that resets, unlocks, suspends or sends a code is POST on Okta, and GET alone
# can't change a tenant, but keep the list tight anyway: no app secrets, no API tokens, no IdP keys.
ALLOWED = (
    re.compile(r"^/api/v1/users$"),
    re.compile(rf"^/api/v1/users/{_ID}/factors$"),
    re.compile(rf"^/api/v1/users/{_ID}/appLinks$"),
    re.compile(r"^/api/v1/devices$"),
    re.compile(r"^/api/v1/logs$"),
)
RESERVE = 0.5          # leave at least half of each rate-limit bucket for the org's own admins and apps
_MAX_WAIT = 65.0       # Okta buckets reset every minute
_RETRY = (500, 502, 503, 504)
_BACKOFF = (3.0, 10.0, 30.0)


class OktaError(RuntimeError):
    pass


def org_host(config: dict) -> str:
    """acme.okta.com from "https://acme.okta.com", "acme.okta.com/api/v1/" or the like."""
    raw = str(config.get("base_url") or config.get("domain") or "").strip().lower()
    host = urlsplit(raw if "//" in raw else "https://" + raw).hostname or ""
    if not _HOST.match(host):
        raise ValueError("The Okta domain should look like acme.okta.com")
    return host


def allowed(method: str, url: str, host: str) -> bool:
    """CTEM's read-only guard: GET, https, the org's own host, an allow-listed path."""
    if method != "GET":
        return False
    p = urlsplit(url)
    if p.scheme != "https" or p.hostname != host or p.port not in (None, 443) or p.username or p.password:
        return False
    return any(r.match(p.path) for r in ALLOWED)


def next_link(link: str | None) -> str | None:
    """The rel="next" URL from Okta's Link header."""
    for part in (link or "").split(","):
        m = re.match(r'\s*<([^>]+)>\s*;\s*rel="next"', part)
        if m:
            return m.group(1)
    return None


@register(Vendor.okta)
class OktaConnector(BaseConnector):
    """Config: base_url (https://acme.okta.com), api_token (an SSWS token of a read-only admin), create_devices
    (add Okta-registered computers CTEM has never seen), factor_budget (MFA lookups per sync, default 3000),
    device_interval_days (how often the slow device pull runs, default 7; 0 = every sync), app_budget (people whose
    app list is read per sync, default 3000; each person's list is refreshed weekly)."""

    def __init__(self, config: dict) -> None:
        super().__init__(config)
        self.warnings: list[str] = []
        self.calls = 0

    @property
    def host(self) -> str:
        return org_host(self.config)

    async def _pace(self, resp) -> None:
        """Sleep until the bucket resets once we've used our share of it, so the org's own traffic never starves."""
        try:
            limit = int(resp.headers.get("x-rate-limit-limit") or 0)
            left = int(resp.headers.get("x-rate-limit-remaining") or 0)
            reset = float(resp.headers.get("x-rate-limit-reset") or 0)
        except ValueError:
            return
        if limit and left < limit * RESERVE:
            await asyncio.sleep(min(_MAX_WAIT, max(1.0, reset - time.time() + 1)))

    async def fetch(self, url: str, client) -> tuple[list | dict, str | None]:
        """One GET: (body, next page URL). Every URL, including Okta's own next links, passes the allow-list first."""
        if not url.startswith("https://"):
            url = f"https://{self.host}{url}"
        if not allowed("GET", url, self.host):
            raise OktaError(f"CTEM never calls {urlsplit(url).path}")
        headers = {"Authorization": f"SSWS {self.config['api_token']}", "Accept": "application/json"}
        for attempt in range(4):
            resp = await client.get(url, headers=headers)
            self.calls += 1
            if resp.status_code == 429 and attempt < 3:
                await self._pace_429(resp)
                continue
            if resp.status_code in _RETRY and attempt < 3:   # Okta's 500s come and go on the same page
                await asyncio.sleep(_BACKOFF[attempt])
                continue
            break
        if resp.status_code in (401, 403):
            raise OktaError(f"Okta refused the API token (HTTP {resp.status_code}); check it and the admin role it belongs to")
        if resp.status_code != 200:
            raise OktaError(f"Okta answered HTTP {resp.status_code} for {urlsplit(url).path}")
        await self._pace(resp)
        nxt = next_link(resp.headers.get("link"))
        if nxt and not allowed("GET", nxt, self.host):
            raise OktaError("Okta's next-page link points somewhere CTEM doesn't call")
        return resp.json(), nxt

    async def _pace_429(self, resp) -> None:
        try:
            reset = float(resp.headers.get("x-rate-limit-reset") or 0)
        except ValueError:
            reset = 0
        await asyncio.sleep(min(_MAX_WAIT, max(2.0, reset - time.time() + 1)))

    async def pages(self, path: str, client, max_pages: int = 2000):
        """Every item across Okta's cursor pages."""
        url: str | None = path
        for _ in range(max_pages):
            body, url = await self.fetch(url, client)
            for item in body if isinstance(body, list) else []:
                yield item
            if not url:
                return
        self.warnings.append(f"{urlsplit(path).path} stopped after {max_pages} pages")

    def client(self):
        c = safe_client(timeout=60.0)
        c.follow_redirects = False   # a redirect would skip the allow-list; Okta's API never needs one
        return c

    async def test_connection(self) -> bool:
        try:
            async with self.client() as client:
                await self.fetch("/api/v1/users?limit=1", client)
            return True
        except Exception as e:  # noqa: BLE001 -- the card shows it failed; the log has why
            log.warning("Okta test failed: %s", type(e).__name__)
            return False

    def device_days(self) -> int:
        try:
            return max(0, min(90, int(self.config.get("device_interval_days", 7))))
        except (TypeError, ValueError):
            return 7

    async def devices_due(self, db: AsyncSession) -> bool:
        """The device pull is slow (Okta pages devices 20 at a time), so it runs on its own interval, weekly by
        default; 0 means every sync."""
        from datetime import datetime, timedelta, timezone

        from api.integrations.base import load_sync_state
        from api.integrations.okta_ingest import when
        last = when((await load_sync_state(db, self.integration_id)).get("devices_at"))
        return last is None or datetime.now(timezone.utc) - last >= timedelta(days=self.device_days()) - timedelta(hours=1)

    async def _devices_done(self, db: AsyncSession) -> None:
        from datetime import datetime, timezone

        from api.integrations.base import load_sync_state, save_sync_state
        state = await load_sync_state(db, self.integration_id)
        await save_sync_state(db, self.integration_id, {**state, "devices_at": datetime.now(timezone.utc).isoformat()})

    async def sync(self, db: AsyncSession) -> int:
        from api.integrations import okta_apps, okta_ingest, okta_signals
        self.warnings = []
        async with self.client() as client:
            people = await okta_ingest.users(self, client, db)
            n = len(people.by_okta)
            pulled = False
            if await self.devices_due(db):
                try:
                    n += await okta_ingest.devices(self, client, db, people)
                    await self._devices_done(db)
                    pulled = True
                except OktaError as e:   # the rest of the sync still runs; the pull retries next sync
                    await db.rollback()
                    self.warnings.append(f"device pull stopped ({e}); it runs again next sync")
                    log.warning("Okta device pull failed: %s", e)
            if not pulled:
                await okta_ingest.device_owners(db, people)   # who's on a computer, from the last device pull
            n += await okta_ingest.factors(self, client, db, people)
            n += await okta_apps.assignments(self, client, db, people)
            n += await okta_apps.sign_ins(self, client, db, people)
            n += await okta_signals.posture(self, db, people)
            n += await okta_signals.threats(self, client, db, people)
        log.info("Okta sync: %d records, %d API calls", n, self.calls)
        return n
