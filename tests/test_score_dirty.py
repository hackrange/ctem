"""Rescore only what changed (api/scoring/dirty.py): an input change marks its device, a sync's housekeeping
doesn't, the scoring engine's own writes don't, every bulk statement on a scoring table marks what it touches,
and a selective rescore lands exactly where a full one would."""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

ROOT = Path(__file__).resolve().parents[1]
_BULK = re.compile(r"\b(update|delete|insert)\((Finding|Device|Vulnerability|_T|DeviceTag|CloudAsset|t)\b")
# Bulk statements that change nothing a score reads (or are followed by a full rescore), and why
NOT_INPUTS = {
    "api/scoring/dirty.py": "the marking itself",
    "api/scoring/engine.py": "affected-device counts, written by the scoring itself",
    "api/core/location.py": "where a device is (site, city): not a score input",
    "api/core/finding_history.py": "removes fixed findings into the history rollup; open findings are unchanged",
    "api/core/integration_truncate.py": "a truncate is followed by a full rescore",
    "api/integrations/horizon3_story.py": "deletes devices that no longer exist",
    "api/integrations/rapid7_insightvm.py": "clears pruned_at only",
    "api/integrations/horizon3_series.py": "pentest_exploited is shown, not scored; its deletes are marked",
    "api/enrichment/kev_epss.py": "writes score_inputs_at with every value it changes",
}
_MARKS = ("mark_devices", "mark_finding_devices", "mark_vulns", "score_inputs_at")


def test_every_bulk_statement_on_a_scoring_table_marks_what_it_changes():
    missing = []
    for path in (ROOT / "api").rglob("*.py"):
        rel = str(path.relative_to(ROOT))
        if rel.startswith("api/models/"):
            continue
        src = path.read_text()
        if not _BULK.search(src) or rel in NOT_INPUTS:
            continue
        if not any(m in src for m in _MARKS):
            missing.append(rel)
    assert not missing, f"bulk writes that never mark devices for rescoring: {missing} (see api/scoring/dirty.py)"


async def _host(db, tag):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    d = Device(hostname=f"dirty-{tag}", device_type=DeviceType.server, edr_active=False,
               last_seen=datetime.now(timezone.utc) - timedelta(days=1))
    v = Vulnerability(source="t_dirty", source_vuln_id=f"v-{tag}", title="Remote code execution", cvss_base=7.5,
                      cve_id=f"CVE-2026-{abs(hash(tag)) % 90000 + 10000}")
    db.add_all([d, v])
    await db.flush()
    f = Finding(device_id=d.id, vuln_id=v.id, source="t_dirty", source_id=f"f-{tag}", status=FindingStatus.open,
                exposure="listening", ports="443/tcp")
    db.add(f)
    await db.commit()
    return d, v, f


async def _marked(db, model, oid):
    return (await db.execute(select(model.score_inputs_at).where(model.id == oid)
                             .execution_options(populate_existing=True))).scalar_one()


@pytest.mark.asyncio
async def test_inputs_mark_and_housekeeping_does_not(db):
    from api.models.device import Device
    from api.models.vuln import Vulnerability
    from api.scoring.engine import recalculate_device
    d, v, f = await _host(db, uuid.uuid4().hex[:6])
    assert await _marked(db, Device, d.id) is not None   # new: scored
    past = datetime(2020, 1, 1, tzinfo=timezone.utc)
    from sqlalchemy import update

    async def reset():
        await db.execute(update(Device).where(Device.id == d.id).values(score_inputs_at=past))
        await db.execute(update(Vulnerability).where(Vulnerability.id == v.id).values(score_inputs_at=past))
        await db.commit()

    def at(x):
        return x if x is None or x.tzinfo else x.replace(tzinfo=timezone.utc)

    await reset()
    d.last_seen = datetime.now(timezone.utc)            # a sync saw it again: no score input moved
    f.last_seen = datetime.now(timezone.utc)
    await db.commit()
    assert at(await _marked(db, Device, d.id)) == past
    await recalculate_device(d, db)                    # the engine's own writes (scores, reasons) mark nothing
    assert at(await _marked(db, Device, d.id)) == past
    for change in (lambda: setattr(d, "edr_active", True), lambda: setattr(f, "is_reachable", True),
                   lambda: setattr(f, "status", f.status.__class__.remediated)):
        await reset()
        change()
        await db.commit()
        assert at(await _marked(db, Device, d.id)) > past
    await reset()
    v.is_kev = True                                    # a new KEV listing marks the vulnerability
    await db.commit()
    assert at(await _marked(db, Vulnerability, v.id)) > past
    await reset()
    d.last_seen = datetime.now(timezone.utc) - timedelta(days=60)   # gone quiet past the 30-day line
    await db.commit()
    assert at(await _marked(db, Device, d.id)) > past


@pytest.mark.asyncio
async def test_a_selective_rescore_lands_where_a_full_one_does(db):
    """The proof that nothing is skipped: change inputs every way the score reads them, rescore only what was
    marked, then rescore everything and compare."""
    from sqlalchemy import update

    from api.enrichment.kev_epss import apply_kev
    from api.models.device import Device
    from api.models.vuln import Finding
    from api.scoring.engine import recalculate_changed, recalculate_device
    hosts = [await _host(db, f"{uuid.uuid4().hex[:6]}{i}") for i in range(4)]
    for d, _, _ in hosts:
        await recalculate_device(d, db)
    since = datetime.now(timezone.utc)
    (d0, v0, f0), (d1, v1, f1), (d2, v2, f2), (d3, v3, f3) = hosts
    d0.edr_active, d0.edr_vendor = True, "crowdstrike"   # an ORM write on the device
    f1.is_reachable, f1.reachability_source = True, "horizon3"   # pentest proof on a finding
    await db.commit()
    await apply_kev(db, {v2.cve_id: None}, [v2.cve_id])   # a bulk KEV listing (no ORM objects)
    from api.scoring.dirty import mark_finding_devices
    await mark_finding_devices(db, Finding.id == f3.id)     # a bulk close, as a connector does it
    await db.execute(update(Finding).where(Finding.id == f3.id).values(status="remediated"))
    await db.commit()
    ids = [d.id for d, _, _ in hosts]
    db.expire_all()   # the pipeline rescores in a session of its own, which sees the bulk KEV write
    await recalculate_changed(db, since)

    async def scores():
        return {i: (s, g) for i, s, g in (await db.execute(select(Device.id, Device.risk_score, Device.risk_grade)
                                                           .where(Device.id.in_(ids)).execution_options(populate_existing=True))).all()}
    selective = await scores()
    for i in ids:
        await recalculate_device((await db.execute(select(Device).where(Device.id == i))).scalar_one(), db)
    assert selective == await scores()


@pytest.mark.asyncio
async def test_a_policy_report_marks_its_hosts_only_when_the_policy_changed(db):
    from sqlalchemy import update

    from api.models.device import Device
    from api.models.edr_policy import EdrPolicy
    t = uuid.uuid4().hex[:6]
    d, _, _ = await _host(db, t)
    d.edr_active, d.edr_vendor, d.edr_prevention_policy = True, "crowdstrike", f"p-{t}"
    p = EdrPolicy(vendor="crowdstrike", policy_id=f"p-{t}", kind="prevention", name="Workstations", enabled=True,
                  body={"settings": [{"id": "x", "value": True}]})
    db.add(p)
    await db.commit()
    past = datetime(2020, 1, 1, tzinfo=timezone.utc)

    async def reset():
        await db.execute(update(Device).where(Device.id == d.id).values(score_inputs_at=past))
        await db.commit()

    def at(x):
        return x if x is None or x.tzinfo else x.replace(tzinfo=timezone.utc)
    await reset()
    p.reported_at = datetime.now(timezone.utc)   # the shipper's routine re-report: same policy
    await db.commit()
    assert at(await _marked(db, Device, d.id)) == past
    p.body = {"settings": [{"id": "x", "value": False}]}   # a protection switched off
    await db.commit()
    assert at(await _marked(db, Device, d.id)) > past
