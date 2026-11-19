"""Email service -- SMTP and Microsoft 365 Graph API."""
from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import lru_cache

log = logging.getLogger("open-ctem.email")


class EmailClient:
    """
    Send email via SMTP (plain/TLS/STARTTLS) or MS365 Graph API.
    Mode is set by EMAIL_MODE in settings: smtp | ms365 | disabled.
    """

    def __init__(self, settings):
        self._s = settings

    async def send(
        self,
        to: str | list[str],
        subject: str,
        body_text: str,
        body_html: str | None = None,
        reply_to: str | None = None,
    ) -> bool:
        mode = getattr(self._s, "email_mode", "disabled")
        if mode == "disabled":
            log.info("Email disabled -- would have sent: %s", subject)
            return False
        if isinstance(to, str):
            to = [to]
        try:
            if mode == "smtp":
                return await self._send_smtp(to, subject, body_text, body_html, reply_to)
            if mode == "ms365":
                return await self._send_ms365(to, subject, body_text, body_html, reply_to)
            log.warning("Unknown EMAIL_MODE: %s", mode)
            return False
        except Exception as exc:
            log.error("Failed to send email '%s': %s", subject, exc)
            return False

    # ── SMTP ──────────────────────────────────────────────────────────────────

    async def _send_smtp(
        self, to: list[str], subject: str,
        body_text: str, body_html: str | None, reply_to: str | None,
    ) -> bool:
        msg = _build_mime(self._s.smtp_from, to, subject, body_text, body_html, reply_to)
        host = self._s.smtp_host
        port = int(getattr(self._s, "smtp_port", 587))
        user = getattr(self._s, "smtp_username", None)
        password = getattr(self._s, "smtp_password", None)
        use_tls = getattr(self._s, "smtp_tls", True)

        def _send():
            ctx = ssl.create_default_context()
            if port == 465 or use_tls is True:
                # Implicit TLS (SMTPS)
                with smtplib.SMTP_SSL(host, port, context=ctx) as server:
                    if user and password:
                        server.login(user, password)
                    server.sendmail(self._s.smtp_from, to, msg.as_string())
            else:
                # STARTTLS
                with smtplib.SMTP(host, port) as server:
                    server.ehlo()
                    if use_tls is not False:
                        server.starttls(context=ctx)
                    if user and password:
                        server.login(user, password)
                    server.sendmail(self._s.smtp_from, to, msg.as_string())

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _send)
        log.info("SMTP email sent: %s -> %s", subject, to)
        return True

    # ── Microsoft 365 Graph API ───────────────────────────────────────────────

    async def _send_ms365(
        self, to: list[str], subject: str,
        body_text: str, body_html: str | None, reply_to: str | None,
    ) -> bool:
        from api.core.ssrf import safe_client

        token = await self._ms365_token()
        from_addr = self._s.ms365_from_address

        body_content = body_html or body_text
        content_type = "HTML" if body_html else "Text"

        payload = {
            "message": {
                "subject": subject,
                "body": {"contentType": content_type, "content": body_content},
                "toRecipients": [{"emailAddress": {"address": a}} for a in to],
            },
            "saveToSentItems": "false",
        }
        if reply_to:
            payload["message"]["replyTo"] = [{"emailAddress": {"address": reply_to}}]

        async with safe_client() as client:
            resp = await client.post(
                f"https://graph.microsoft.com/v1.0/users/{from_addr}/sendMail",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=payload,
            )
        resp.raise_for_status()
        log.info("MS365 Graph email sent: %s -> %s", subject, to)
        return True

    async def _ms365_token(self) -> str:
        from api.core.ssrf import safe_client
        tenant = self._s.ms365_tenant_id
        async with safe_client() as client:
            resp = await client.post(
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._s.ms365_client_id,
                    "client_secret": self._s.ms365_client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
        resp.raise_for_status()
        return resp.json()["access_token"]


def _build_mime(
    from_addr: str, to: list[str], subject: str,
    body_text: str, body_html: str | None, reply_to: str | None,
) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to)
    if reply_to:
        msg["Reply-To"] = reply_to
    msg.attach(MIMEText(body_text, "plain"))
    if body_html:
        msg.attach(MIMEText(body_html, "html"))
    return msg


@lru_cache(maxsize=1)
def get_email_client() -> EmailClient:
    from api.core.config import get_settings
    return EmailClient(get_settings())
