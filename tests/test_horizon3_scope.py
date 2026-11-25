"""Two NodeZero accounts in one CTEM: each Horizon3 integration writes, closes and deletes only its own findings."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, func, select


def _ser(vid: str, ip: str) -> dict:
    return {"uuid": f"{vid}-{ip}", "vuln_id": vid, "vuln_name": vid, "severity": "HIGH", "score": 7.5, "ip": ip, "port": 443,
            "protocol": "tcp", "status": "OPEN", "is_open": True, "first_seen_at": None,   # SQLite reloads times naive; Postgres keeps the zone
            "last_seen_at": None, "last_op_id": "op", "attack_paths_count": 0,
            "vuln": {"aliases": [], "cisa_kev": False, "known_ransomware_campaign_use": False, "base_score": 7.5}}


async def _setup(db, accounts: int):
    from api.models.device import Device, DeviceType
    from api.models.integration import IntegrationConfig, Vendor
    n = uuid.uuid4().hex[:8]
    d = Device(hostname=f"h3-scope-{n}", device_type=DeviceType.server)
    cfgs = [IntegrationConfig(vendor=Vendor.horizon3, name=f"NodeZero {k} {n}", config={}) for k in range(accounts)]
    db.add_all([d, *cfgs])
    await db.commit()
    d._h3_id = str(d.id)

    async def find(_ip):
        return d
    return n, d, [str(c.id) for c in cfgs], find


async def _cleanup(db, d, iids):
    from api.models.integration import IntegrationConfig
    from api.models.vuln import Finding
    did = d.__dict__.get("id") or getattr(d, "_h3_id", None)   # read before the rollback expires it
    await db.rollback()
    await db.execute(delete(Finding).where(Finding.device_id == did))
    await db.execute(delete(IntegrationConfig).where(IntegrationConfig.id.in_(iids)))
    await db.commit()


async def _rows(db, d) -> set[tuple]:
    from api.models.vuln import Finding
    did = d if isinstance(d, str) else d.id
    q = select(Finding.integration_id, Finding.source_id).where(Finding.device_id == did).execution_options(populate_existing=True)
    return {(i, s.split(":", 1)[1]) for i, s in (await db.execute(q)).all()}


@pytest.mark.asyncio
async def test_one_horizon3_integration_never_closes_anothers_findings(db):
    from api.integrations import horizon3_series as series
    n, d, (a, b), find = await _setup(db, 2)
    v1, v2 = f"H3S-{n}-1", f"H3S-{n}-2"
    try:
        await series.apply(db, [_ser(v1, "10.0.0.1")], {}, find, a)
        await series.apply(db, [_ser(v1, "10.0.0.1"), _ser(v2, "10.0.0.1")], {}, find, b)
        # The same host and weakness from two accounts is two findings: B's run never took over A's row
        assert await _rows(db, d) == {(a, v1), (b, v1), (b, v2)}

        # A's NodeZero no longer has anything open: only A's finding goes
        assert await series.close_the_rest(db, set(), a) == 1
        assert await _rows(db, d) == {(b, v1), (b, v2)}

        # B's fixes one of its two: only that one goes, and A's (now empty) set is untouched
        _, seen = await series.apply(db, [_ser(v1, "10.0.0.1")], {}, find, b)
        assert await series.close_the_rest(db, seen, b) == 1
        assert await _rows(db, d) == {(b, v1)}
    finally:
        await _cleanup(db, d, [a, b])


@pytest.mark.asyncio
async def test_without_an_integration_nothing_is_written_or_deleted(db):
    from api.integrations import horizon3_series as series
    from api.models.vuln import Finding
    n, d, (a,), find = await _setup(db, 1)
    did = str(d.id)
    try:
        await series.apply(db, [_ser(f"H3S-{n}-1", "10.0.0.2")], {}, find, a)
        before = (await db.execute(select(func.count()).select_from(Finding).where(Finding.source == "horizon3"))).scalar_one()
        with pytest.raises(RuntimeError):
            await series.close_the_rest(db, set(), None)
        with pytest.raises(RuntimeError):
            await series.apply(db, [_ser(f"H3S-{n}-2", "10.0.0.2")], {}, find, None)
        await db.rollback()
        after = (await db.execute(select(func.count()).select_from(Finding).where(Finding.source == "horizon3"))).scalar_one()
        assert after == before and await _rows(db, did) == {(a, f"H3S-{n}-1")}
    finally:
        await _cleanup(db, d, [a])


@pytest.mark.asyncio
async def test_an_untagged_older_finding_is_claimed_by_the_only_integration(db):
    from api.integrations import horizon3_series as series
    from api.models.integration import IntegrationConfig, Vendor
    from api.models.vuln import Finding, Vulnerability
    if (await db.execute(select(func.count()).select_from(IntegrationConfig)
                         .where(IntegrationConfig.vendor == Vendor.horizon3))).scalar_one():
        pytest.skip("another Horizon3 integration exists in this test database")
    n, d, (a,), find = await _setup(db, 1)
    vid = f"H3S-{n}-old"
    try:
        v = Vulnerability(source="horizon3", source_vuln_id=vid, title=vid)
        db.add(v)
        await db.flush()
        db.add(Finding(device_id=d.id, vuln_id=v.id, source="horizon3", source_id=f"{d.id}:{vid}"))   # before 1.11.2: no owner
        await db.commit()
        await series.apply(db, [_ser(vid, "10.0.0.3")], {}, find, a)
        assert await _rows(db, d) == {(a, vid)}   # claimed, not duplicated
    finally:
        await _cleanup(db, d, [a])


@pytest.mark.asyncio
async def test_with_two_integrations_an_untagged_finding_belongs_to_neither(db):
    from api.integrations import horizon3_series as series
    from api.models.vuln import Finding, Vulnerability
    n, d, (a, b), find = await _setup(db, 2)
    vid = f"H3S-{n}-old"
    try:
        v = Vulnerability(source="horizon3", source_vuln_id=vid, title=vid)
        db.add(v)
        await db.flush()
        db.add(Finding(device_id=d.id, vuln_id=v.id, source="horizon3", source_id=f"{d.id}:{vid}"))
        await db.commit()
        await series.close_the_rest(db, set(), a)
        await series.close_the_rest(db, set(), b)
        assert await _rows(db, d) == {(None, vid)}   # neither account can tell it's theirs, so neither deletes it
    finally:
        await _cleanup(db, d, [a, b])


@pytest.mark.asyncio
async def test_per_pentest_path_only_remediates_its_own_integrations_findings(db):
    from api.integrations import horizon3_apply as apply
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    n, d, (a, b), _ = await _setup(db, 2)
    try:
        v = Vulnerability(source="horizon3", source_vuln_id=f"H3S-{n}-p", title="p")
        db.add(v)
        await db.flush()
        old = __import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc)
        fa = Finding(device_id=d.id, vuln_id=v.id, source="horizon3", source_id=f"{d.id}:A", integration_id=a,
                     status=FindingStatus.open, last_seen=old)
        fb = Finding(device_id=d.id, vuln_id=v.id, source="horizon3", source_id=f"{d.id}:B", integration_id=b,
                     status=FindingStatus.open, last_seen=old)
        db.add_all([fa, fb])
        await db.commit()
        # A's pentest tested this host and found nothing there any more
        extra = {"hosts": [{"ip": None, "ip_addresses": [], "host_names": [d.hostname], "is_in_scope": True}]}
        await apply.op(db, {"op_id": f"op-{n}", "completed_at": "2026-06-15T23:14:19Z"}, [], None, extra, iid=a)
        await db.commit()
        q = select(Finding.integration_id, Finding.status).where(Finding.device_id == d.id).execution_options(populate_existing=True)
        got = dict((await db.execute(q)).all())
        assert got[b] == FindingStatus.open
        assert got[a] == FindingStatus.remediated
    finally:
        await _cleanup(db, d, [a, b])
