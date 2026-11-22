"""Email (Settings > Integrations > Email): SMTP or Microsoft 365. Nothing to sync; Test signs in without sending
anything, and "Send test email" sends one (api/routes/email_test.py)."""
from __future__ import annotations

import logging

from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.email")


@register(Vendor.email)
class EmailConnector(BaseConnector):

    async def test_connection(self) -> bool:
        from api.core.email import EmailClient, EmailConfig
        try:
            await EmailClient(config=EmailConfig.from_integration(self.config or {})).check()
            return True
        except Exception as e:  # noqa: BLE001 -- the reason is logged, not returned
            log.warning("email test failed: %s", type(e).__name__)
            return False

    async def sync(self, db) -> int:
        return 0
