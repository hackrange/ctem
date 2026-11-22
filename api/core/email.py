"""Email service: SMTP (STARTTLS, SSL/TLS or none) or Microsoft 365 through the Graph API.

Configured in Settings > Integrations > Email (encrypted with the other integrations); the server's EMAIL_MODE /
SMTP_* / MS365_* settings are the fallback when no Email integration is enabled."""
from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import lru_cache
from urllib.parse import quote

log = logging.getLogger("open-ctem.email")


@dataclass
class EmailConfig:
    mode: str = "disabled"               # smtp | ms365 | disabled
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_security: str = "starttls"      # starttls | ssl | none
    smtp_username: str | None = None
    smtp_password: str | None = None
    from_address: str | None = None
    ms365_tenant_id: str | None = None
    ms365_client_id: str | None = None
    ms365_client_secret: str | None = None

    @classmethod
    def from_integration(cls, c: dict) -> "EmailConfig":
        port = int(c.get("smtp_port") or 587)
        return cls(mode=c.get("mode") or "smtp", smtp_host=c.get("smtp_host"), smtp_port=port,
                   smtp_security=c.get("smtp_security") or ("ssl" if port == 465 else "starttls"),
                   smtp_username=c.get("smtp_username") or None, smtp_password=c.get("smtp_password") or None,
                   from_address=c.get("from_address"), ms365_tenant_id=c.get("ms365_tenant_id"),
                   ms365_client_id=c.get("ms365_client_id"), ms365_client_secret=c.get("ms365_client_secret"))

    @classmethod
    def from_settings(cls, s) -> "EmailConfig":
        port = int(getattr(s, "smtp_port", 587) or 587)
        tls = getattr(s, "smtp_tls", True)
        sec = "ssl" if port == 465 else ("starttls" if tls is not False else "none")
        mode = getattr(s, "email_mode", "disabled")
        return cls(mode=mode, smtp_host=getattr(s, "smtp_host", None), smtp_port=port, smtp_security=sec,
                   smtp_username=getattr(s, "smtp_username", None), smtp_password=getattr(s, "smtp_password", None),
                   from_address=getattr(s, "ms365_from_address", None) if mode == "ms365" else getattr(s, "smtp_from", None),
                   ms365_tenant_id=getattr(s, "ms365_tenant_id", None), ms365_client_id=getattr(s, "ms365_client_id", None),
                   ms365_client_secret=getattr(s, "ms365_client_secret", None))


async def effective_config() -> EmailConfig:
    """The enabled Email integration's settings, else the server's."""
    try:
        from sqlalchemy import select

        import api.core.db as dbm
        from api.models.integration import IntegrationConfig, Vendor
        if dbm._session_factory is not None:
            async with dbm._session_factory() as db:
                cfg = (await db.execute(select(IntegrationConfig).where(IntegrationConfig.vendor == Vendor.email,
                                                                        IntegrationConfig.is_enabled.is_(True)))).scalars().first()
                if cfg is not None:
                    return EmailConfig.from_integration(cfg.config or {})
    except Exception:  # noqa: BLE001 -- no database here (a script, a test): the server's settings still work
        log.debug("email integration not read; using the server settings")
    from api.core.config import get_settings
    return EmailConfig.from_settings(get_settings())


async def configured() -> bool:
    c = await effective_config()
    return c.mode in ("smtp", "ms365") and bool(c.from_address) and bool(c.smtp_host if c.mode == "smtp" else c.ms365_tenant_id)


class EmailClient:
    """Send email with the effective configuration (looked up on each send, so a change in Settings applies at once)."""

    def __init__(self, settings=None, config: EmailConfig | None = None):
        self._s, self._fixed = settings, config

    async def _config(self) -> EmailConfig:
        return self._fixed or await effective_config()

    async def send(self, to: str | list[str], subject: str, body_text: str, body_html: str | None = None,
                   reply_to: str | None = None) -> bool:
        c = await self._config()
        if c.mode not in ("smtp", "ms365"):
            log.info("Email disabled -- would have sent: %s", subject)
            return False
        to = [to] if isinstance(to, str) else to
        try:
            if c.mode == "smtp":
                return await asyncio.get_running_loop().run_in_executor(None, _smtp_send, c, to, subject, body_text, body_html, reply_to)
            return await _graph_send(c, to, subject, body_text, body_html, reply_to)
        except Exception as exc:  # noqa: BLE001 -- callers report "not sent"; the reason is logged, never returned
            log.error("Failed to send email '%s': %s", subject, type(exc).__name__)
            return False

    async def check(self) -> None:
        """Sign in without sending anything (Settings > Integrations > Test). Raises on failure."""
        c = await self._config()
        if c.mode == "smtp":
            await asyncio.get_running_loop().run_in_executor(None, _smtp_login, c)
        elif c.mode == "ms365":
            await _graph_token(c)
        else:
            raise ValueError("email is turned off")


def _smtp_open(c: EmailConfig):
    ctx = ssl.create_default_context()
    if c.smtp_security == "ssl":
        server = smtplib.SMTP_SSL(c.smtp_host, c.smtp_port, context=ctx, timeout=30)
    else:
        server = smtplib.SMTP(c.smtp_host, c.smtp_port, timeout=30)
        server.ehlo()
        if c.smtp_security == "starttls":
            server.starttls(context=ctx)
            server.ehlo()
    if c.smtp_username and c.smtp_password:
        server.login(c.smtp_username, c.smtp_password)
    return server


def _smtp_login(c: EmailConfig) -> None:
    with _smtp_open(c):
        pass


def _smtp_send(c, to, subject, body_text, body_html, reply_to) -> bool:
    msg = _build_mime(c.from_address, to, subject, body_text, body_html, reply_to)
    with _smtp_open(c) as server:
        server.sendmail(c.from_address, to, msg.as_string())
    return True


async def _graph_token(c: EmailConfig) -> str:
    from api.core.ssrf import safe_client
    async with safe_client(timeout=30.0) as client:
        resp = await client.post(f"https://login.microsoftonline.com/{quote(c.ms365_tenant_id or '', safe='')}/oauth2/v2.0/token",
                                 data={"grant_type": "client_credentials", "client_id": c.ms365_client_id,
                                       "client_secret": c.ms365_client_secret, "scope": "https://graph.microsoft.com/.default"})
    resp.raise_for_status()
    return resp.json()["access_token"]


async def _graph_send(c, to, subject, body_text, body_html, reply_to) -> bool:
    """Graph sendMail as the configured mailbox (needs the Mail.Send application permission)."""
    from api.core.ssrf import safe_client
    token = await _graph_token(c)
    message = {"subject": subject, "body": {"contentType": "HTML" if body_html else "Text", "content": body_html or body_text},
               "toRecipients": [{"emailAddress": {"address": a}} for a in to]}
    if reply_to:
        message["replyTo"] = [{"emailAddress": {"address": reply_to}}]
    async with safe_client(timeout=30.0) as client:
        resp = await client.post(f"https://graph.microsoft.com/v1.0/users/{quote(c.from_address or '', safe='@')}/sendMail",
                                 headers={"Authorization": f"Bearer {token}"}, json={"message": message, "saveToSentItems": False})
    resp.raise_for_status()
    return True


def _build_mime(from_addr, to, subject, body_text, body_html=None, reply_to=None) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["Subject"], msg["From"], msg["To"] = subject, from_addr, ", ".join(to)
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
