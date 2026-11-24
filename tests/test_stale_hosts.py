"""Hosts no tool has seen in N days, and the probe can't reach, lose their findings; nothing alive does."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

NOW = datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_gone_hosts_lose_their_findings_and_live_ones_keep_them(db):
    from api.core import stale_hosts
    from api.models.device import Device, DeviceType
    from api.models.vuln import Finding, FindingStatus, Vulnerability
    tag = uuid.uuid4().hex[:6]
    old = NOW - timedelta(days=40)
    gone = Device(hostname=f"gone-{tag}", device_type=DeviceType.server, sources=",rapid7_insightvm,", last_seen=old, open_findings=1)
    scanned = Device(hostname=f"scanned-{tag}", device_type=DeviceType.server, sources=",rapid7_insightvm,", last_seen=NOW - timedelta(days=2))
    answers = Device(hostname=f"answers-{tag}", device_type=DeviceType.unknown, sources=",horizon3,netprobe,", alive_at=NOW - timedelta(days=1))
    silent_probe = Device(hostname=f"silent-{tag}", device_type=DeviceType.unknown, sources=",netprobe,", alive_at=old)
    v = Vulnerability(source="t_stale", source_vuln_id=f"s{tag}", title="Stale test vuln")
    db.add_all([gone, scanned, answers, silent_probe, v])
    await db.flush()
    db.add_all([Finding(device_id=d.id, vuln_id=v.id, source="t_stale", status=FindingStatus.open, last_seen=old) for d in (gone, scanned, answers)])
    await db.commit()
    ids = {k: d.id for k, d in (("gone", gone), ("scanned", scanned), ("answers", answers), ("silent", silent_probe))}

    got = await stale_hosts.prune(db, 30)
    assert got["hosts"] >= 1 and got["probe_only"] >= 1

    async def findings(did):
        return (await db.execute(select(Finding).where(Finding.device_id == did))).scalars().all()
    assert await findings(ids["gone"]) == []
    assert len(await findings(ids["scanned"])) == 1 and len(await findings(ids["answers"])) == 1
    assert (await db.execute(select(Device).where(Device.id == ids["gone"]))).scalar_one_or_none() is not None   # the record stays
    assert (await db.execute(select(Device).where(Device.id == ids["silent"]))).scalar_one_or_none() is None


def test_the_window_is_a_bounded_setting():
    from pydantic import ValidationError

    from api.core.config import Settings
    assert Settings.model_fields["stale_host_days"].default == 30
    with pytest.raises(ValidationError):
        Settings(stale_host_days=1, secret_key="x" * 40, database_url="sqlite+aiosqlite://")
