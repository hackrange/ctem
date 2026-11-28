"""An admin signing in interactively raises a host's risk: on a workstation any admin sign-in counts in full (runas or
sudo instead); on a server a privileged-group account counts in full, an admin-named one less, and a jump server the
admin sign-in check's rules leave out doesn't count. The reason names it."""
from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from api.models.device import DeviceType


def _dev(kind, last=None, recent=None):
    return SimpleNamespace(id=str(uuid.uuid4()), device_type=kind, last_login_user=last, recent_logins=recent or [])


CTX = {"privileged": {"da.wile"}, "patterns": ("adm*", "svc_*", "sulocal_*", "administrator", "root"), "exempt": set()}


def test_the_tiers_by_host_and_account():
    from api.scoring.admin_signin import factor
    ws, srv = DeviceType.workstation, DeviceType.server
    assert factor(_dev(ws, "ACME\\da.wile"), CTX)[0] == 1.4                 # a domain admin, anywhere: in full
    assert factor(_dev(srv, "da.wile@acme.example"), CTX)[0] == 1.4
    assert factor(_dev(ws, "ACME\\adm.pat"), CTX)[0] == 1.4                 # any admin on a workstation: in full
    assert factor(_dev(srv, "ACME\\adm.pat"), CTX)[0] == 1.25               # on a server, an admin-named account: less
    assert factor(_dev(ws, "Administrator"), CTX)[0] == 1.4 and factor(_dev(srv, "root"), CTX)[0] == 1.25   # built-in
    assert factor(_dev(ws, "jdoe", ["ACME\\adm.pat", "jdoe"]), CTX)[0] == 1.25   # recent only: cached credentials
    assert factor(_dev(srv, "jdoe", ["root"]), CTX)[0] == 1.1
    assert factor(_dev(ws, "jdoe", ["jdoe"]), CTX) is None
    assert factor(_dev(DeviceType.network_device, "admin"), CTX) is None
    jump = _dev(srv, "ACME\\da.wile")
    assert factor(jump, {**CTX, "exempt": {jump.id}}) is None                 # a jump server: expected there
    ws_dev = _dev(ws, "ACME\\da.wile")
    assert factor(ws_dev, {**CTX, "exempt": {ws_dev.id}})[0] == 1.4           # never a workstation
    why = factor(_dev(ws, "ACME\\adm.pat"), CTX)[1]
    assert "runas or sudo" in why and "(+40%)" in why


@pytest.mark.asyncio
async def test_a_host_an_admin_signs_in_to_scores_higher_and_says_why(db):
    from datetime import datetime, timezone

    from api.models.device import Device
    from api.models.user import User
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    from api.scoring import admin_signin
    from api.scoring.engine import recalculate_device
    n = uuid.uuid4().hex[:6]
    da = User(username=f"da.coyote{n}", ad_username=f"da.coyote{n}", is_local=False,
              ad_groups=["CN=Domain Admins,CN=Users,DC=acme,DC=example"])
    v = Vulnerability(source="t_adm", source_vuln_id=f"v-{n}", title="Acme flaw", cvss_base=8.0, epss_score=0.3)
    a = Device(hostname=f"ws-a-{n}", device_type=DeviceType.workstation, edr_active=True, last_login_user=f"ACME\\da.coyote{n}",
               last_seen=datetime.now(timezone.utc))
    b = Device(hostname=f"ws-b-{n}", device_type=DeviceType.workstation, edr_active=True, last_login_user="ACME\\jdoe",
               last_seen=datetime.now(timezone.utc))
    db.add_all([da, v, a, b])
    await db.flush()
    db.add_all([Finding(device_id=a.id, vuln_id=v.id, source="t_adm", status=FindingStatus.open),
                Finding(device_id=b.id, vuln_id=v.id, source="t_adm", status=FindingStatus.open)])
    await db.commit()
    admin_signin.forget()
    ra, rb = await recalculate_device(a, db), await recalculate_device(b, db)
    assert ra.score > rb.score
    assert "privileged account" in (ra.score_breakdown or "") and "privileged account" not in (rb.score_breakdown or "")
    admin_signin.forget()
