"""Email: the integration's settings win over the server's, SMTP security modes, Graph sendMail, and the test send."""
from __future__ import annotations

import pytest

from api.core import email as em


def test_config_from_integration_and_server_settings():
    c = em.EmailConfig.from_integration({"mode": "smtp", "smtp_host": "smtp.acme.example", "smtp_port": 465, "from_address": "ctem@acme.example"})
    assert c.smtp_security == "ssl" and c.smtp_port == 465
    s = type("S", (), {"email_mode": "smtp", "smtp_host": "relay.acme.example", "smtp_port": 587, "smtp_tls": True, "smtp_from": "a@acme.example"})()
    assert em.EmailConfig.from_settings(s).smtp_security == "starttls"      # port 587: STARTTLS (it used to try implicit TLS)


@pytest.mark.parametrize("security,ssl_used,starttls", [("ssl", True, False), ("starttls", False, True), ("none", False, False)])
def test_smtp_security_modes(monkeypatch, security, ssl_used, starttls):
    calls = []

    class Fake:
        def __init__(self, host, port, **k):
            calls.append(("open", type(self).__name__, host, port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            pass

        def starttls(self, context=None):
            calls.append(("starttls",))

        def login(self, u, p):
            calls.append(("login", u))

        def sendmail(self, frm, to, msg):
            calls.append(("send", frm, tuple(to)))

    class SSL(Fake):
        pass
    monkeypatch.setattr(em.smtplib, "SMTP", Fake)
    monkeypatch.setattr(em.smtplib, "SMTP_SSL", SSL)
    c = em.EmailConfig(mode="smtp", smtp_host="smtp.acme.example", smtp_port=587, smtp_security=security, smtp_username="u",
                       smtp_password="p", from_address="ctem@acme.example")
    assert em._smtp_send(c, ["you@acme.example"], "s", "body", None, None)
    assert calls[0][1] == ("SSL" if ssl_used else "Fake") and (("starttls",) in calls) == starttls
    assert ("login", "u") in calls and ("send", "ctem@acme.example", ("you@acme.example",)) in calls


@pytest.mark.asyncio
async def test_graph_send_and_disabled(monkeypatch):
    sent = []

    class Resp:
        def __init__(self, body=None):
            self._b = body or {}

        def raise_for_status(self):
            pass

        def json(self):
            return self._b

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, **k):
            sent.append((url, k))
            return Resp({"access_token": "t"}) if "oauth2" in url else Resp()
    monkeypatch.setattr("api.core.ssrf.safe_client", lambda **k: Client())
    c = em.EmailConfig(mode="ms365", ms365_tenant_id="tid", ms365_client_id="cid", ms365_client_secret="sec", from_address="ctem@acme.example")
    assert await em.EmailClient(config=c).send("you@acme.example", "Hello", "body")
    assert sent[1][0] == "https://graph.microsoft.com/v1.0/users/ctem@acme.example/sendMail"
    assert sent[1][1]["json"]["message"]["toRecipients"][0]["emailAddress"]["address"] == "you@acme.example"
    assert await em.EmailClient(config=em.EmailConfig(mode="disabled")).send("x@acme.example", "s", "b") is False


@pytest.mark.asyncio
async def test_email_integration_test_send_is_admin_only(db, client_admin, client_cyber, monkeypatch):
    import api.integrations  # noqa: F401
    from api.integrations.base import get_connector
    from api.models.integration import IntegrationConfig, Vendor
    assert type(get_connector("email", {})).__name__ == "EmailConnector"
    cfg = IntegrationConfig(vendor=Vendor.email, name="ACME mail", is_enabled=True, config={"mode": "smtp", "smtp_host": "smtp.acme.example",
                                                                                          "from_address": "ctem@acme.example"})
    db.add(cfg)
    await db.commit()

    async def fake_send(self, **k):
        return True
    monkeypatch.setattr(em.EmailClient, "send", fake_send)
    url = f"/api/v1/integrations/{cfg.id}/email-test"
    assert (await client_cyber.post(url, json={"to": "you@acme.example"})).status_code == 403
    assert (await client_admin.post(url, json={"to": "not an address"})).status_code == 422
    assert (await client_admin.post(url, json={"to": "you@acme.example"})).json()["ok"]

    async def eff():
        return em.EmailConfig.from_integration(cfg_data)
    cfg_data = {"mode": "smtp", "smtp_host": "smtp.acme.example", "from_address": "ctem@acme.example"}
    monkeypatch.setattr(em, "effective_config", eff)
    assert await em.configured()                                              # an enabled integration counts as set up
    cfg_data = {"mode": "smtp", "from_address": "ctem@acme.example"}
    assert not await em.configured()                                          # no host: not set up
