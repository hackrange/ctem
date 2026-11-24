"""Zscaler through OneAPI (ZIdentity OAuth), read only.

What it reads (one token POST, then GETs on an allow-list of paths; nothing else can be sent):
  Client Connector   every device running Zscaler's agent and how healthy it is, matched to CTEM's devices, so the
                     devices with no Zscaler or an unhealthy one show up (api/integrations/zscaler_posture.py)
  ZIA policy         URL filtering, SSL inspection, firewall and DLP rules, and admin accounts, checked for weaknesses
  ZDX                which devices report digital experience data

Keep the API client's roles view-only in each Zscaler product: that is what makes the token read-only on Zscaler's side.
This allow-list is CTEM's own guarantee on top of it. Web and firewall traffic logs and DLP incidents are not in the
REST API (they need Cloud NSS or Workflow Automation)."""
from __future__ import annotations

import logging
import re
import time

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.zscaler")
API = "https://api.zsapi.net"
_VANITY = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
# The only paths CTEM reads (prefix match). Client Connector's getOtp and getPasswords return secrets: never.
ALLOWED = ("/zcc/papi/public/v1/getDevices", "/zia/api/v1/urlFilteringRules", "/zia/api/v1/sslInspectionRules",
           "/zia/api/v1/firewallFilteringRules", "/zia/api/v1/webDlpRules", "/zia/api/v1/adminUsers", "/zia/api/v1/adminRoles",
           "/zia/api/v1/urlCategories", "/zdx/v1/devices")
FORBIDDEN = re.compile(r"getOtp|getPasswords|/deeptraces?|/submit|/discan|/activate", re.I)


def allowed(method: str, url: str, vanity: str) -> bool:
    """CTEM's own read-only guard: the token POST to the tenant's ZIdentity, and GETs on the allow-list only."""
    if method == "POST":
        return url == f"https://{vanity}.zslogin.net/oauth2/v1/token"
    if method != "GET" or not url.startswith(API + "/"):
        return False
    path = url[len(API):].split("?", 1)[0]
    return any(path == p or path.startswith(p + "/") for p in ALLOWED) and not FORBIDDEN.search(path)


@register(Vendor.zscaler)
class ZscalerConnector(BaseConnector):
    """Config: vanity_domain (the part before .zslogin.net), client_id, client_secret."""

    _token: str | None = None
    _born: float = 0.0

    def __init__(self, config: dict) -> None:
        super().__init__(config)
        self.notes: list[str] = []

    def _vanity(self) -> str:
        v = str(self.config.get("vanity_domain") or "").strip().lower()
        v = v.split("//")[-1].split(".zslogin.net")[0].split(".")[0]
        if not _VANITY.match(v):
            raise ValueError("The ZIdentity vanity domain should look like acme (from acme.zslogin.net)")
        return v

    async def _get_token(self) -> str:
        if self._token and time.time() - self._born < 240:
            return self._token
        url = f"https://{self._vanity()}.zslogin.net/oauth2/v1/token"
        if not allowed("POST", url, self._vanity()):
            raise RuntimeError("refused")
        async with safe_client() as client:
            resp = await client.post(url, data={"grant_type": "client_credentials", "client_id": self.config["client_id"],
                                                "client_secret": self.config["client_secret"], "audience": "https://api.zscaler.com"},
                                     headers={"Accept": "application/json"})
        if resp.status_code != 200:
            raise RuntimeError(f"Zscaler refused the API client (HTTP {resp.status_code}); check the Client ID, secret and vanity domain")
        self._token, self._born = resp.json()["access_token"], time.time()
        return self._token

    async def get(self, path: str, params: dict | None = None, optional: bool = True):
        """One GET on an allowed path; None when the product or role refuses it (the rest of the sync carries on)."""
        url = API + path
        if not allowed("GET", url, self._vanity()):
            raise RuntimeError(f"CTEM never calls {path.split('?')[0]}")
        async with safe_client() as client:
            resp = await client.get(url, params=params, headers={"Authorization": f"Bearer {await self._get_token()}",
                                                                 "Accept": "application/json"})
        if resp.status_code in (401, 403, 404) and optional:
            log.info("Zscaler %s: HTTP %s (not licensed or not in the API client's role)", path.split("?")[0], resp.status_code)
            self.notes.append(f"{path.split('?')[0].rsplit('/', 1)[-1]}: HTTP {resp.status_code}, not in the API client's role or not licensed")
            return None
        resp.raise_for_status()
        return resp.json()

    async def test_connection(self) -> bool:
        try:
            return bool(await self._get_token())
        except Exception as e:  # noqa: BLE001 -- the card shows it failed; the log has why
            log.warning("Zscaler test failed: %s", type(e).__name__)
            return False

    async def sync(self, db: AsyncSession) -> int:
        from api.integrations import zscaler_posture
        self.notes = []
        n = await zscaler_posture.devices(self, db)
        n += await zscaler_posture.policy(self, db)
        if self.notes:
            log.info("Zscaler notes: %s", "; ".join(self.notes[:8]))
        return n
