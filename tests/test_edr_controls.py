"""EDR policies: what they do to a finding's score (with reasons), the Firewall and USB tabs, and who sees them."""
from __future__ import annotations

import uuid
from types import SimpleNamespace as NS

import pytest

from api.scoring import edr_controls as ec
from api.scoring.compensating import ControlContext, apply_multipliers


def _prev(settings, enabled=True):
    return NS(enabled=enabled, name="Workstations", body={"settings": settings})


def test_prevention_blocks_detects_and_exploit_mitigations():
    p = ec.prevention(_prev({
        "CloudAntiMalware": {"name": "Cloud Anti-malware", "category": "Machine Learning", "value": "MODERATE"},
        "ForceDEP": {"name": "Force DEP", "category": "Exploit Mitigation", "value": True},
        "PreventSuspiciousProcesses": {"name": "Suspicious Processes", "category": "Execution Blocking", "value": True},
        "AdwarePUP": {"name": "Adware & PUP", "category": "Machine Learning", "value": "DISABLED"},
        "EnhancedVisibility": {"name": "Enhanced Visibility", "category": "Visibility", "value": True}}))
    assert p["exploit"] == ["Force DEP"]
    assert "Cloud Anti-malware (moderate)" in p["blocking"] and "Suspicious Processes" in p["blocking"]
    assert not any("Adware" in b or "Visibility" in b for b in p["blocking"])
    detect = ec.prevention(_prev({"CloudAntiMalware": {"name": "Cloud Anti-malware", "category": "Machine Learning",
                                                       "value": "detect:MODERATE"}}))
    assert detect["blocking"] == [] and ec.prevention(None) is None


def test_scores_drop_with_reasons_only_for_what_applies():
    blocking = {"blocking": ["Cloud Anti-malware (moderate)"], "exploit": ["Force DEP", "Force ASLR"], "name": "W"}
    base = ControlContext(edr_active=True, edr_vendor="crowdstrike")
    flat, why = apply_multipliers(50.0, base)
    assert flat == 35.0 and why == ["EDR active response mode (-30%)"]            # no policy reported: as before
    mem, why = apply_multipliers(50.0, ControlContext(edr_active=True, edr_vendor="crowdstrike", edr_prevention=blocking, memory_flaw=True))
    assert mem == pytest.approx(28.0) and any("Falcon prevention blocks" in w for w in why) and any("Force DEP" in w for w in why)
    other, _ = apply_multipliers(50.0, ControlContext(edr_active=True, edr_vendor="crowdstrike", edr_prevention=blocking))
    assert other == 35.0                                                            # not memory corruption: no extra
    detect, why = apply_multipliers(50.0, ControlContext(edr_active=True, edr_vendor="crowdstrike",
                                                         edr_prevention={"blocking": [], "exploit": [], "name": "W"}))
    assert detect == 45.0 and "only detects" in why[0]
    usb, why = apply_multipliers(50.0, ControlContext(edr_active=True, edr_vendor="crowdstrike", edr_prevention=blocking,
                                                      usb_blocked=True, attack_vector="physical"))
    assert any("blocks USB storage" in w for w in why) and usb == pytest.approx(50 * 0.7 * 0.5 * 0.3)


def _fw(rules, default_in="DENY", enforce=True, test_mode=False):
    return NS(enabled=True, body={"enforce": enforce, "test_mode": test_mode, "default_inbound": default_in, "rules": rules})


def test_host_firewall_verdicts_follow_rule_order_and_defaults():
    smb = {"name": "Block SMB", "enabled": True, "action": "DENY", "direction": "IN", "protocol": "TCP", "local_port": [[445, 445]],
           "remote_address": ["*"]}
    rdp = {"name": "RDP from jump hosts", "enabled": True, "action": "ALLOW", "direction": "IN", "protocol": "TCP",
           "local_port": [[3389, 3389]], "remote_address": ["192.0.2.0/24"]}
    web = {"name": "Web", "enabled": True, "action": "ALLOW", "direction": "IN", "protocol": "TCP", "local_port": [[443, 443]],
           "remote_address": ["*"]}
    pol = _fw([smb, rdp, web])
    f, why = ec.firewall(pol, "445/tcp")
    assert f == 0.5 and 'rule "Block SMB"' in why
    f, why = ec.firewall(pol, "3389/tcp")
    assert f == 0.7 and "only from 192.0.2.0/24" in why
    assert ec.firewall(pol, "443/tcp") is None                                       # open to anyone: no credit
    f, why = ec.firewall(pol, "8080/tcp")
    assert f == 0.5 and "default inbound block" in why
    assert ec.firewall(_fw([smb], default_in="ALLOW"), "8080/tcp") is None
    assert ec.firewall(_fw([smb], enforce=False), "445/tcp") is None                 # not enforced: describes, doesn't protect
    assert ec.firewall(_fw([smb], test_mode=True), "445/tcp") is None
    assert ec.firewall(_fw([{**smb, "enabled": False}], default_in="ALLOW"), "445/tcp") is None
    assert ec.firewall(pol, "445/tcp 443/tcp") is None                               # one port open: the finding is reachable


@pytest.mark.asyncio
async def test_policies_upload_and_tabs_are_for_admins_and_cyber(client, client_admin, client_it_user, db):
    from api.collector.ingest import apply_batch
    from api.collector.schemas import CrowdStrikeBatch
    from api.models.device import Device
    n = uuid.uuid4().hex[:6]
    fw, usb, prev = "1" * 31 + "a", "2" * 31 + "b", "3" * 31 + "c"
    batch = CrowdStrikeBatch.model_validate({"kind": "crowdstrike", "run_id": str(uuid.uuid4()), "edr_policies": [
        {"id": fw, "kind": "firewall", "name": "Servers", "enabled": True, "enforce": True, "test_mode": False,
         "default_inbound": "DENY", "default_outbound": "ALLOW", "rules": [
             {"name": "Block SMB", "enabled": True, "action": "DENY", "direction": "IN", "protocol": "TCP", "local_port": [[445, 445]],
              "remote_address": ["*"]}]},
        {"id": usb, "kind": "device_control", "name": "USB", "enabled": True, "enforcement": "MONITOR_ENFORCE", "classes": [
            {"id": "MASS_STORAGE", "action": "FULL_BLOCK", "allowed": [{"vendor": "Acme Storage", "vendor_id": "0781", "serial": "ACME1",
                                                                       "action": "FULL_ACCESS"}]}]},
        {"id": prev, "kind": "prevention", "name": "Workstations", "enabled": True,
         "settings": {"ForceDEP": {"name": "Force DEP", "category": "Exploit Mitigation", "value": True}}}],
        "devices": [{"device_id": "e" * 32, "hostname": f"ws-edr-{n}", "status": "normal", "os_version": "Windows 11",
                     "firewall_policy_id": fw, "usb_policy_id": usb, "prevention_policy_id": prev, "usb_storage_blocked": True}]})
    await apply_batch(db, batch)
    await db.commit()
    from sqlalchemy import select
    d = (await db.execute(select(Device).where(Device.hostname == f"ws-edr-{n}"))).scalar_one()
    assert d.edr_firewall_policy == fw and d.edr_usb_policy == usb and d.edr_prevention_policy == prev
    r = (await client_admin.get(f"/api/v1/devices/{d.id}/firewall")).json()
    assert r["available"] and r["state"] == "Enforced" and r["rules"][0]["action"] == "Block" and r["rules"][0]["local_port"] == "445"
    assert r["rules"][-1]["default"] and r["rules"][-1]["direction"] == "Outbound" and r["rules"][-1]["action"] == "Allow"
    u = (await client_admin.get(f"/api/v1/devices/{d.id}/usb")).json()
    assert u["state"] == "Enforced" and u["classes"][0]["class"] == "USB storage" and u["classes"][0]["action"] == "Blocked"
    assert u["classes"][0]["allowed"][0]["serial"] == "ACME1" and u["classes"][0]["allowed"][0]["action"] == "Allowed"
    assert (await client_it_user.get(f"/api/v1/devices/{d.id}/firewall")).status_code == 404
    assert (await client_it_user.get(f"/api/v1/devices/{d.id}/usb")).status_code == 404
    assert (await client_admin.get(f"/api/v1/devices/{uuid.uuid4()}/firewall")).status_code == 404
    bad = {"kind": "crowdstrike", "run_id": str(uuid.uuid4()), "edr_policies": [{"id": fw, "kind": "firewall", "name": "<script>"}]}
    with pytest.raises(Exception):
        CrowdStrikeBatch.model_validate(bad)


def test_posture_puts_disk_encryption_first_and_reads_results():
    from api.routes.device_edr import posture_view
    v = posture_view({"overall": 74, "os": 70, "sensor_config": 90, "signals": [
        {"kind": "sensor", "name": "Sensor tamper protection", "meets": "yes"},
        {"kind": "os", "name": "Firewall enabled", "meets": "no"},
        {"kind": "os", "name": "BitLocker", "criteria": "BitLocker enabled on the system drive", "meets": "yes"}]})
    assert v["signals"][0]["name"] == "BitLocker" and v["disk_encryption"] is True and v["disk_encryption_reported"]
    assert v["signals"][1]["name"] == "Firewall enabled" and v["signals"][1]["passed"] is False   # failures next
    none = posture_view({"signals": [{"kind": "os", "name": "Screen lock", "meets": "yes"}]})
    assert none["disk_encryption"] is None and not none["disk_encryption_reported"]


def test_shipper_posture_is_optional_and_summarized():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))
    import collector_common as cc
    import collector_cs_policies as csp

    class Api:
        def __init__(self, deny=False):
            self.deny = deny

        def call(self, method, path):
            if self.deny:
                raise cc.HttpError(403, "forbidden")
            return {"resources": [{"aid": "a" * 32, "assessment": {"overall": 80, "os": 75, "sensor_config": 95},
                                   "assessment_items": {"os_signals": [{"signal_name": "BitLocker", "group_name": "Encryption",
                                                                        "criteria": "Enabled", "meets_criteria": "yes"}]}}]}
    p = csp.Posture(Api(), {}, "key")
    got = p.load(["a" * 32])
    assert got["a" * 32]["overall"] == 80 and got["a" * 32]["signals"][0] == {"kind": "os", "name": "BitLocker", "group": "Encryption",
                                                                               "criteria": "Enabled", "meets": "yes"}
    state = {}
    p.done(state)
    assert csp.Posture(Api(), state, "key").load(["a" * 32]) == {}       # not due again for a few hours
    off = csp.Posture(Api(deny=True), {}, "key")
    assert off.load(["a" * 32]) == {} and off.off and "Zero Trust Assessment: Read" in off.note
