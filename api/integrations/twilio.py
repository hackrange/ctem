"""Twilio: the text message that carries an identity verification link to a person (the service desk's IDV
requests, api/routes/idv_desk.py). Two calls only, both on an allow-list: send one message, and read that message's
delivery status. Use a Restricted API key with Messaging > Messages Create and Read and nothing else; the account's
auth token is never needed. Nothing is synced, so a sync does nothing."""
from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.twilio")
HOST = "api.twilio.com"
_AC = r"AC[0-9a-f]{32}"
_SM = r"(SM|MM)[0-9a-f]{32}"
SEND = re.compile(rf"^/2010-04-01/Accounts/{_AC}/Messages\.json$")
READ = re.compile(rf"^/2010-04-01/Accounts/{_AC}/Messages/{_SM}\.json$")
_E164 = re.compile(r"^\+[1-9][0-9]{7,14}$")


class TwilioError(RuntimeError):
    pass


def allowed(method: str, url: str, account: str) -> bool:
    p = urlsplit(url)
    if p.scheme != "https" or p.hostname != HOST or p.port not in (None, 443) or p.username or p.password:
        return False
    if f"/Accounts/{account}/" not in p.path:
        return False
    return bool((method == "POST" and SEND.match(p.path)) or (method == "GET" and READ.match(p.path)))


@register(Vendor.twilio)
class TwilioConnector(BaseConnector):
    """Config: account_sid (AC...), api_key_sid (SK...), api_key_secret, from_number (+1...)."""

    def client(self):
        c = safe_client(timeout=20.0)
        c.follow_redirects = False
        return c

    @property
    def account(self) -> str:
        a = str(self.config.get("account_sid") or "")
        if not re.fullmatch(_AC, a):
            raise TwilioError("not a Twilio Account SID")
        return a

    async def _call(self, method: str, path: str, data: dict | None = None) -> tuple[int, dict]:
        url = f"https://{HOST}{path}"
        if not allowed(method, url, self.account):
            raise TwilioError(f"CTEM never calls {method} {urlsplit(url).path}")
        auth = (str(self.config.get("api_key_sid") or ""), str(self.config.get("api_key_secret") or ""))
        async with self.client() as c:
            r = await c.request(method, url, auth=auth, data=data, headers={"Accept": "application/json"})
        try:
            body = r.json()
        except ValueError:
            body = {}
        return r.status_code, body if isinstance(body, dict) else {}

    async def send(self, to: str, text: str) -> dict:
        """One SMS. Returns {"sid", "status"}; raises TwilioError when Twilio refuses it."""
        frm = str(self.config.get("from_number") or "")
        if not _E164.match(to or "") or not _E164.match(frm):
            raise TwilioError("phone numbers must be in international form")
        status, body = await self._call("POST", f"/2010-04-01/Accounts/{self.account}/Messages.json",
                                        {"To": to, "From": frm, "Body": text[:600]})
        if status not in (200, 201):
            raise TwilioError(f"Twilio refused the message (HTTP {status}, code {body.get('code')})")
        sid = str(body.get("sid") or "")
        return {"sid": sid if re.fullmatch(_SM, sid) else None, "status": str(body.get("status") or "")[:20]}

    async def status(self, sid: str) -> str | None:
        """Where one message stands: queued, sent, delivered, undelivered or failed."""
        if not re.fullmatch(_SM, sid or ""):
            return None
        code, body = await self._call("GET", f"/2010-04-01/Accounts/{self.account}/Messages/{sid}.json")
        return str(body.get("status") or "")[:20] if code == 200 else None

    async def test_connection(self) -> bool:
        """A made-up message id: 404 means the key got in and may read messages; 401 means it didn't."""
        try:
            code, _ = await self._call("GET", f"/2010-04-01/Accounts/{self.account}/Messages/SM{'0' * 32}.json")
            return code == 404
        except Exception as e:  # noqa: BLE001 -- the card shows it failed; the log has why
            log.warning("Twilio test failed: %s", type(e).__name__)
            return False

    async def sync(self, db: AsyncSession) -> int:
        return 0
