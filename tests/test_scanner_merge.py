"""One finding per CVE per host when Tanium and a scanner both report it: Tanium's merges into the scanner's, the
earlier first-found date wins, the scanner closing reopens Tanium's, and Tanium seeing it fixed after the scanner's last
look closes the scanner's with a note, only when Tanium knew every CVE of that check."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

NOW = datetime.now(timezone.utc)


def test_cves_of_a_scanner_check():
    from api.integrations.scanner_merge import cves_of
    assert cves_of("CVE-2026-1", ["CVE-2026-1", "CVE-2026-2"], "java-cpu-oct-2026") == {"CVE-2026-1", "CVE-2026-2"}
    assert cves_of(None, None, "msft-cve-2026-21311") == {"CVE-2026-21311"}


async def _setup(db, tag):
    from api.models.device import Device, DeviceType
    from api.models.vuln import Vulnerability
    d = Device(hostname=f"sm{tag}", device_type=DeviceType.workstation, source="tanium")
    r7a = Vulnerability(source="rapid7_insightvm", source_vuln_id=f"msft-cve-2026-{tag}1", cve_id=f"CVE-2026-{tag}1", title="a")
    r7b = Vulnerability(source="rapid7_insightvm", source_vuln_id=f"bundle-{tag}", cve_id=f"CVE-2026-{tag}2",
                        cve_ids=[f"CVE-2026-{tag}2", f"CVE-2026-{tag}3"], title="b")
    ta = Vulnerability(source="tanium", source_vuln_id=f"CVE-2026-{tag}1", cve_id=f"CVE-2026-{tag}1", title="ta")
    tb = Vulnerability(source="tanium", source_vuln_id=f"CVE-2026-{tag}2", cve_id=f"CVE-2026-{tag}2", title="tb")
    db.add_all([d, r7a, r7b, ta, tb])
    await db.commit()
    return d, r7a, r7b, ta, tb


async def _get(db, *ids):
    from api.models.vuln import Finding
    got = {f.id: f for f in (await db.execute(select(Finding).where(Finding.id.in_(ids)).execution_options(populate_existing=True))).scalars()}
    return [got[i] for i in ids]


@pytest.mark.asyncio
async def test_merge_unmerge_and_fixed_by_tanium(db):
    from api.integrations.scanner_merge import reconcile
    from api.models.device import Device
    from api.models.vuln import Finding, FindingStatus as S, Vulnerability
    tag = str(uuid.uuid4().int)[:5]
    d, r7a, r7b, ta, tb = await _setup(db, tag)
    p1 = Finding(device_id=d.id, vuln_id=r7a.id, source="rapid7_insightvm", status=S.open,
                 first_detected=NOW - timedelta(days=5), last_seen=NOW - timedelta(days=6))
    p2 = Finding(device_id=d.id, vuln_id=r7b.id, source="rapid7_insightvm", status=S.open, last_seen=NOW - timedelta(days=6))
    t1 = Finding(device_id=d.id, vuln_id=ta.id, source="tanium", status=S.open, first_detected=NOW - timedelta(days=40))
    t2 = Finding(device_id=d.id, vuln_id=tb.id, source="tanium", status=S.open, first_detected=NOW - timedelta(days=3))
    db.add_all([p1, p2, t1, t2])
    await db.commit()
    await reconcile(db)
    p1, p2, t1, t2 = await _get(db, p1.id, p2.id, t1.id, t2.id)
    assert t1.status == t2.status == S.merged and p1.status == p2.status == S.open
    assert abs((p1.first_detected.replace(tzinfo=timezone.utc) - (NOW - timedelta(days=40))).total_seconds()) < 2   # earlier date wins
    # Tanium checks again after InsightVM's last look and no longer finds either CVE
    for t in (t1, t2):
        t.status, t.closed_at = S.remediated, NOW - timedelta(days=1)
    await db.commit()
    await reconcile(db)
    p1, p2, t1, t2 = await _get(db, p1.id, p2.id, t1.id, t2.id)
    assert p1.status == S.remediated and "Tanium saw it fixed" in p1.closed_note
    assert p2.status == S.open    # that check covers a CVE Tanium never reported: no verdict
    assert t1.status == S.merged and t1.closed_at   # the fix counts once, on the scanner's finding
    # InsightVM closes its own while Tanium still reports the CVE: Tanium's opens again
    p2.status = S.remediated
    t2.status, t2.closed_at = S.merged, None
    await db.commit()
    await reconcile(db)
    (t2,) = await _get(db, t2.id)
    assert t2.status == S.open
    await db.execute(delete(Finding).where(Finding.device_id == d.id))
    await db.execute(delete(Vulnerability).where(Vulnerability.id.in_([r7a.id, r7b.id, ta.id, tb.id])))
    await db.execute(delete(Device).where(Device.id == d.id))
    await db.commit()


@pytest.mark.asyncio
async def test_found_by_names_both_and_shows_proof(db):
    from api.integrations.pentest_merge import found_by
    from api.integrations.scanner_merge import reconcile
    from api.models.device import Device
    from api.models.vuln import Finding, FindingStatus as S, Vulnerability
    tag = str(uuid.uuid4().int)[:5]
    d, r7a, r7b, ta, tb = await _setup(db, tag)
    db.add_all([Finding(device_id=d.id, vuln_id=r7a.id, source="rapid7_insightvm", status=S.open),
                Finding(device_id=d.id, vuln_id=ta.id, source="tanium", status=S.open,
                        details={"proof": {"tool": "Tanium", "tests": [{"found": "python.exe 3.12.6", "expected": "< 3.12.11"}]}})])
    await db.commit()
    await reconcile(db)
    row = {"source": "rapid7_insightvm"}
    await found_by(db, [(row, d.id, f"CVE-2026-{tag}1")])
    assert row["found_by"] == ["Rapid7 InsightVM", "Tanium"]
    # The Proof dialog: InsightVM's live lookup (not configured here) plus Tanium's stored evidence; Tanium's own
    # finding shows its evidence too
    from api.core.finding_proof import fetch
    from sqlalchemy.orm import selectinload
    r7, tan = [(await db.execute(select(Finding).options(selectinload(Finding.vuln)).where(Finding.device_id == d.id, Finding.source == s)
                                 .execution_options(populate_existing=True))).scalar_one() for s in ("rapid7_insightvm", "tanium")]
    got = await fetch(db, r7)
    assert got["available"] and [x["tool"] for x in got["instances"]] == ["Tanium"] and "python.exe 3.12.6" in got["instances"][0]["proof"]
    assert "< 3.12.11" in got["instances"][0]["proof"] and got["note"]
    own = await fetch(db, tan)
    assert own["available"] and own["instances"][0]["proof"] == got["instances"][0]["proof"]
    tan.details = {}
    assert not (await fetch(db, tan))["available"]
    await db.execute(delete(Finding).where(Finding.device_id == d.id))
    await db.execute(delete(Vulnerability).where(Vulnerability.id.in_([r7a.id, r7b.id, ta.id, tb.id])))
    await db.execute(delete(Device).where(Device.id == d.id))
    await db.commit()
