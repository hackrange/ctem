"""Curated rules with account overrides: one idle period for everyone, another for accounts matching a name."""
from __future__ import annotations

import contextlib
import os
import tempfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.grc.checks import REGISTRY, evaluate
from api.models.base import Base
from api.rules.doc import RuleDoc

NOW = datetime.now(timezone.utc)
CHECK = REGISTRY["ctem_dormant_accounts"]


@pytest_asyncio.fixture
async def gdb():
    path = tempfile.mktemp(prefix="ctem_acct_", suffix=".db")
    eng = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with async_sessionmaker(eng, expire_on_commit=False)() as s:
        yield s
    await eng.dispose()
    with contextlib.suppress(OSError):
        os.unlink(path)


async def _seed(db):
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    from api.models.user import User
    cfg = IntegrationConfig(vendor=Vendor("ldap"), name="ldap", is_enabled=True, config={})
    db.add(cfg)
    await db.flush()
    db.add(SyncJob(integration_id=str(cfg.id), vendor="ldap", status=SyncStatus.success, started_at=NOW, finished_at=NOW))
    for name, days in (("pat", 200), ("lee", 100), ("svc_backup", 200), ("SVC_old", 400), ("svc-batch", 200)):
        db.add(User(username=name, ad_username=name, is_local=False, ad_dn=f"CN={name},DC=acme,DC=example",
                    ad_last_logon=NOW - timedelta(days=days), created_at=(NOW - timedelta(days=900)).replace(tzinfo=None)))
    await db.commit()


def _rule(**kw):
    doc = {"schema": "open-ctem/curated-rule@1", "name": "Dormant: 180 days, svc_ 365", "check": "ctem_dormant_accounts",
           "thresholds": {"idle_days": 180}, "account_overrides": [{"name_patterns": ["svc_*"], "thresholds": {"idle_days": 365}}], **kw}
    return RuleDoc.model_validate(doc)


@pytest.mark.asyncio
async def test_svc_accounts_get_their_own_idle_period(gdb):
    await _seed(gdb)
    row = SimpleNamespace(id="r1", name="Dormant: 180 days, svc_ 365", version=1)
    body, out = await evaluate(gdb, CHECK, {}, detail=True, rules=[(row, _rule())])
    d = body["details"]
    # pat (200 > 180) and svc-batch (a dash, so not svc_*: 200 > 180) and SVC_old (400 > 365); not svc_backup (200 < 365)
    assert {r["account"] for r in out.rows} == {"pat", "svc-batch", "SVC_old"}
    assert d["dormant"] == 3 and d["by_account_group"]["svc_*"] == {"idle_days": 365, "dormant": 1, "never_logged_on": 0}
    assert d["by_account_group"]["other accounts"]["idle_days"] == 180
    assert "svc_* over 365 days" in body["summary"] and "other accounts over 180 days" in body["summary"]
    assert {r["account"]: r["idle_limit_days"] for r in out.rows}["SVC_old"] == 365
    # without the override everything over 180 counts
    plain = RuleDoc.model_validate({"schema": "open-ctem/curated-rule@1", "name": "Dormant 180", "check": "ctem_dormant_accounts",
                                    "thresholds": {"idle_days": 180}})
    body, _ = await evaluate(gdb, CHECK, {}, rules=[(row, plain)])
    assert body["details"]["dormant"] == 4 and "by_account_group" not in body["details"]


def test_overrides_are_checked():
    with pytest.raises(ValidationError, match="can't have account overrides"):
        RuleDoc.model_validate({"schema": "open-ctem/curated-rule@1", "name": "EDR x", "check": "ctem_edr_coverage",
                                "account_overrides": [{"name_patterns": ["svc_*"], "thresholds": {"pass_at": 90}}]})
    with pytest.raises(ValidationError, match="between"):
        _rule(account_overrides=[{"name_patterns": ["svc_*"], "thresholds": {"idle_days": 5000}}])
    with pytest.raises(ValidationError):
        _rule(account_overrides=[{"name_patterns": ["svc_'; drop table users;--"], "thresholds": {"idle_days": 365}}])
    with pytest.raises(ValueError, match="unknown parameter"):   # a caller can't slip overrides in as a parameter
        CHECK.parse({"_account_overrides": "x"})
    # an override alone is a valid rule
    assert _rule(thresholds={}).account_overrides[0].name_patterns == ["svc_*"]


ADMIN = REGISTRY["ctem_admin_local_logons"]


async def _computers(db):
    from api.models.device import Device, DeviceType
    from api.models.integration import IntegrationConfig, SyncJob, SyncStatus, Vendor
    cfg = IntegrationConfig(vendor=Vendor("crowdstrike"), name="cs", is_enabled=True, config={})
    db.add(cfg)
    await db.flush()
    db.add(SyncJob(integration_id=str(cfg.id), vendor="crowdstrike", status=SyncStatus.success, started_at=NOW, finished_at=NOW))
    rows = [("WS-01", DeviceType.workstation, "ACME\\adm.pat", ["ACME\\adm.pat", "pat"]),
            ("WS-02", DeviceType.workstation, "lee", ["lee", "svc_backup@acme.example"]),
            ("WS-03", DeviceType.workstation, "kim", ["kim"]),
            ("JUMP-01", DeviceType.server, "SULOCAL_ops", []),
            ("SRV-02", DeviceType.server, "Administrator", None)]
    for host, dt, last, recent in rows:
        db.add(Device(hostname=host, device_type=dt, last_login_user=last, recent_logins=recent, edr_last_seen=NOW, last_seen=NOW))
    await db.commit()


def test_account_names_match_without_their_domain():
    from api.grc.checks.admin_logons import matches
    p = ("adm*", "svc_*", "sulocal_*")
    assert matches("ACME\\ADM.Pat", p) == "adm*" and matches("svc_backup@acme.example", p) == "svc_*"
    assert matches("SULOCAL_ops", p) == "sulocal_*" and matches("Administrator", p) == "adm*"
    assert matches("svc-batch", p) is None and matches("pat", p) is None and matches("", p) is None


@pytest.mark.asyncio
async def test_admin_accounts_signing_in_to_computers(gdb):
    await _computers(gdb)
    body, out = await evaluate(gdb, ADMIN, {}, detail=True)
    d = body["details"]
    assert body["result"] == "fail" and d["computers"] == 5 and d["computers_with_admin_logons"] == 4
    assert {r["hostname"] for r in out.rows} == {"WS-01", "WS-02", "JUMP-01", "SRV-02"}
    assert next(r for r in out.rows if r["hostname"] == "WS-01")["last_sign_in"] == "ACME\\adm.pat"
    assert d["sign_ins_by_pattern"] == {"adm*": 2, "svc_*": 1, "sulocal_*": 1}
    # workstations only
    assert (await evaluate(gdb, ADMIN, {"include_servers": "0"}))[0]["details"]["computers_with_admin_logons"] == 2
    # a rule: leave the jump server out, and look only for svc_ and sulocal_ accounts
    row = SimpleNamespace(id="r2", name="Admin sign-ins: not on jump servers", version=1)
    doc = RuleDoc.model_validate({"schema": "open-ctem/curated-rule@1", "name": "Admin sign-ins: not on jump servers",
                                  "check": "ctem_admin_local_logons", "account_patterns": ["svc_*", "sulocal_*"],
                                  "scope": {"exclude": {"hostname_patterns": ["JUMP-*"]}}})
    body, out = await evaluate(gdb, ADMIN, {}, detail=True, rules=[(row, doc)])
    assert {r["hostname"] for r in out.rows} == {"WS-02"} and body["details"]["patterns"] == ["svc_*", "sulocal_*"]
    with pytest.raises(ValidationError, match="can't take account_patterns"):
        RuleDoc.model_validate({"schema": "open-ctem/curated-rule@1", "name": "EDR x", "check": "ctem_edr_coverage",
                                "account_patterns": ["svc_*"]})
