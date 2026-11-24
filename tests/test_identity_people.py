"""Identity > a person: the directory person behind a Grip identity (same keyed email hash), the apps holding their
weak, reused or leaked passwords, and the password-change notice (no links, Cyber or Admin, once a day, audited)."""
from __future__ import annotations

import uuid

import pytest


class _Conn:
    def __init__(self, users_by_app):
        self.users_by_app, self.calls = users_by_app, []

    def _root_url(self):
        return "https://acme.example/public"

    async def _paginate(self, url):
        self.calls.append(url)
        return self.users_by_app[url.rsplit("/saas/", 1)[1].split("/")[0]]


def _u(mail, leaked=0, reused=0, weak=0):
    return {"user": {"mail": mail, "gripData": {"passwordPosture": {"leakedPasswordAccounts": leaked, "reusedPasswordAccounts": reused,
                                                                    "weakPasswordAccounts": weak}}}}


@pytest.mark.asyncio
async def test_passwords_are_tied_to_apps_and_unsure_ones_say_so():
    from api.core.encryption import search_hash
    from api.integrations.grip_extras import password_apps
    pw = lambda leaked=0, reused=0, weak=0: {"gripData": {"passwordPosture": {"leakedPasswordAccounts": leaked, "reusedPasswordAccounts": reused,
                                                                             "weakPasswordAccounts": weak}}}
    apps = [{"id": "big", "name": "Big App", **pw(leaked=1)}, {"id": "small", "name": "Small App", **pw(leaked=1, weak=1)},
            {"id": "clean", "name": "Clean", **pw()}]
    conn = _Conn({"big": [_u("a@x.example", leaked=1), _u("b@x.example", leaked=1), _u("c@x.example")],
                  "small": [_u("a@x.example", leaked=1, weak=2)]})
    out = await password_apps(conn, apps)
    assert len(conn.calls) == 2                                   # an app with nothing at risk is never read
    a, b = out[search_hash("a@x.example")], out[search_hash("b@x.example")]
    assert {e["app"]: e["certain"] for e in a} == {"Big App": False, "Small App": True}   # 1 leaked account, 2 people flagged
    small = next(e for e in a if e["app"] == "Small App")
    assert small["leaked"] and small["weak"] and not small["reused"]
    assert [e["app"] for e in b] == ["Big App"] and search_hash("c@x.example") not in out


async def _setup(db, tag, apps):
    from api.core.encryption import search_hash
    from api.models.identity import IdentityRiskScore
    from api.models.user import User
    mail = f"pat.{tag}@acme.example"
    db.add(User(username=f"pat{tag}", email=mail, email_hash=search_hash(mail), display_name="Pat Doe", is_local=False, is_active=True))
    rec = IdentityRiskScore(user_email_hash=search_hash(mail), user_display="pa…@acme.example", leaked_password_accounts=1,
                            credential_apps=apps)
    db.add(rec)
    await db.commit()
    return rec, mail


@pytest.mark.asyncio
async def test_the_person_and_the_notice(db, client_cyber, client_read_only, monkeypatch):
    from api.core import email
    from api.models.settings import AuditLog
    from sqlalchemy import select
    tag = uuid.uuid4().hex[:8]
    rec, mail = await _setup(db, tag, [{"app": "Big App", "app_id": "big", "leaked": True, "reused": False, "weak": False, "certain": False},
                                       {"app": "Small App", "app_id": "small", "leaked": True, "reused": False, "weak": True, "certain": True}])
    url = f"/api/v1/identity/people/{rec.id}"
    assert (await client_read_only.get(url)).status_code == 403
    d = (await client_cyber.get(url)).json()
    assert d["person"]["name"] == "Pat Doe" and d["person"]["email"] == mail and len(d["credentials"]["apps"]) == 2
    n = d["notice"]
    assert n["to"] == mail and "Big App" in n["subject"] and "Small App" in n["body"] and "may be found in a known breach list" in n["body"]
    assert "http" not in n["body"].lower() and "www." not in n["body"].lower()
    scores = (await client_cyber.get("/api/v1/identity/scores", params={"limit": 200})).json()["scores"]
    assert any(s["person"] and s["person"]["email"] == mail and s["credential_apps"] == 2 for s in scores)

    notify = f"{url}/notify"
    assert (await client_read_only.post(notify, json={"confirm": True})).status_code == 403
    assert (await client_cyber.post(notify, json={"confirm": False})).status_code == 400
    r = await client_cyber.post(notify, json={"confirm": True})
    assert r.status_code == 409 and "turned off" in r.json()["detail"]
    sent = []

    async def on():
        return True

    async def send(self, to, subject, body_text, body_html=None, reply_to=None):
        sent.append((to, subject, body_text))
        return True
    monkeypatch.setattr(email, "configured", on)
    monkeypatch.setattr(email.EmailClient, "send", send)
    assert (await client_cyber.post(notify, json={"confirm": True})).json()["sent"] is True
    assert sent and sent[0][0] == mail and "Small App" in sent[0][2]
    again = await client_cyber.post(notify, json={"confirm": True})
    assert again.status_code == 409 and "24 hours" in again.json()["detail"] and len(sent) == 1
    logged = (await db.execute(select(AuditLog).where(AuditLog.action == "identity.password_notice", AuditLog.resource_id == str(rec.id)))).scalars().all()
    assert len(logged) == 1 and mail not in (logged[0].detail or "")
    assert (await client_cyber.get(f"/api/v1/identity/people/{uuid.uuid4()}")).status_code == 404


@pytest.mark.asyncio
async def test_findings_and_apps_open_in_full(db, client_cyber, client_read_only):
    from api.models.identity import PostureFinding, SaasAppRecord
    tag = uuid.uuid4().hex[:8]
    f = PostureFinding(source="grip", external_id=f"pf-{tag}", finding_type="mfa_gap", severity="high", title="No MFA", description="Long text " * 30)
    a = SaasAppRecord(source="grip", external_id=f"app-{tag}", app_name="ChatThing", risk_level="high", user_count=4,
                      oauth_scopes={"high": 2, "high_scopes": ["mail.read"]})
    db.add_all([f, a])
    await db.commit()
    d = (await client_cyber.get(f"/api/v1/identity/posture/{f.id}")).json()
    assert d["description"].startswith("Long text") and d["severity"] == "high"
    assert (await client_cyber.get(f"/api/v1/identity/saas-apps/{a.id}")).json()["oauth_scopes"]["high_scopes"] == ["mail.read"]
    assert (await client_read_only.get(f"/api/v1/identity/saas-apps/{a.id}")).status_code == 403
    assert (await client_cyber.get(f"/api/v1/identity/posture/{uuid.uuid4()}")).status_code == 404
    page = await client_cyber.get("/identity/person", params={"id": str(uuid.uuid4())})
    assert page.status_code == 200 and "identity_person.js" in page.text
