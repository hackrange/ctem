"""One finding per CVE per host when an agent (Tanium) and a scanner (InsightVM, ...) both report it.

The scanner's finding is the one people work; the agent's for that CVE on that host is set to "merged" (kept with its
proof, out of every list, count and score; the scanner's then reads "Found by Rapid7 InsightVM + Tanium"). Its age
starts at the earlier of the two first-found dates. When the scanner's finding closes and the agent still reports
the CVE, the agent's opens again. When the agent stops reporting it after the scanner last saw it, every CVE of that
scanner check the agent knew is fixed, and none is still reported, the scanner's finding closes with a note; the
scanner reopens it if its next check still finds it. An agent finding closed while it had a scanner twin stays merged
(closed), so one fix counts once. Run after every sync, before scoring."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

AGENT_SOURCES = ("tanium",)
_CVE = re.compile(r"cve-\d{4}-\d{4,}", re.I)
_RECENT = timedelta(days=30)


def _aware(d):
    return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)


def cves_of(cve_id: str | None, cve_ids: list | None, source_vuln_id: str | None) -> set[str]:
    """Every CVE a scanner check covers: its list, its first CVE, and any CVE in its id (msft-cve-2026-1234)."""
    out = {str(c).upper() for c in cve_ids or [] if c}
    out |= {c.upper() for c in _CVE.findall(source_vuln_id or "")}
    if cve_id:
        out.add(cve_id.upper())
    return out


async def reconcile(db, since: datetime | None = None) -> set[str]:
    """Merge, unmerge and close across agent and scanner findings; returns the devices whose findings changed.
    since: only devices whose findings changed since then (a sync's start); None (the nightly pass) means all."""
    from api.integrations.pentest_merge import PENTEST_SOURCES, label
    from api.models.device import Device
    from api.models.vuln import Finding, FindingStatus as S, Vulnerability
    now = datetime.now(timezone.utc)
    q = select(Finding.device_id).distinct().where(
        Finding.source.in_(AGENT_SOURCES), Finding.status.in_((S.open, S.merged, S.remediated)),
        (Finding.closed_at.is_(None)) | (Finding.closed_at >= now - _RECENT))
    if since is not None:
        q = q.where(Finding.device_id.in_(select(Device.id).where(Device.score_inputs_at >= since)))
    devices = [str(d) for (d,) in (await db.execute(q)).all()]
    changed: set[str] = set()
    live = (S.open, S.in_progress)
    for i in range(0, len(devices), 300):
        chunk = devices[i:i + 300]
        agent = (await db.execute(select(Finding.id, Finding.device_id, Finding.status, Finding.first_detected, Finding.closed_at,
                                         Vulnerability.cve_id).join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                                  .where(Finding.source.in_(AGENT_SOURCES), Finding.device_id.in_(chunk)))).all()
        scan = (await db.execute(select(Finding.id, Finding.device_id, Finding.status, Finding.first_detected, Finding.last_seen,
                                        Finding.source, Vulnerability.cve_id, Vulnerability.cve_ids, Vulnerability.source_vuln_id)
                                 .join(Vulnerability, Vulnerability.id == Finding.vuln_id)
                                 .where(Finding.source.not_in(AGENT_SOURCES + tuple(PENTEST_SOURCES)), Finding.device_id.in_(chunk),
                                        Finding.status.in_(live + (S.remediated,))))).all()
        a_by: dict[tuple, object] = {(str(r.device_id), (r.cve_id or "").upper()): r for r in agent if r.cve_id}
        s_live: dict[tuple, list] = {}
        s_any: set[tuple] = set()
        for r in scan:
            for c in cves_of(r.cve_id, r.cve_ids, r.source_vuln_id):
                s_any.add((str(r.device_id), c))
                if r.status in live:
                    s_live.setdefault((str(r.device_id), c), []).append(r)
        to_merge, to_open, to_bury, first = [], [], [], {}
        for key, a in a_by.items():
            twins = s_live.get(key)
            if a.status == S.open and twins:
                to_merge.append(a.id)
            elif a.status == S.merged and a.closed_at is None and not twins:
                to_open.append(a.id)   # the scanner closed it but the agent still reports it
            elif a.status == S.remediated and key in s_any:
                to_bury.append(a.id)   # the scanner has this CVE: the fix counts once, on the scanner's finding
            if a.status in (S.open, S.merged) and a.closed_at is None and a.first_detected:
                for t in twins or []:
                    if t.first_detected is None or _aware(a.first_detected) < _aware(t.first_detected):
                        first[t.id] = min(first.get(t.id, _aware(a.first_detected)), _aware(a.first_detected))
        fixed: dict[str, tuple] = {}
        for r in scan:
            if r.status not in live:
                continue
            dev, mine = str(r.device_id), cves_of(r.cve_id, r.cve_ids, r.source_vuln_id)
            known = [a_by[(dev, c)] for c in mine if (dev, c) in a_by]
            if not known or len(known) < len(mine):
                continue   # the agent doesn't know every CVE this check covers: no verdict
            if all(a.status in (S.remediated, S.merged) and a.closed_at and r.last_seen and _aware(a.closed_at) > _aware(r.last_seen)
                   for a in known):
                fixed[r.id] = (max(_aware(a.closed_at) for a in known), r.source)
        for ids, values in ((to_merge, {"status": S.merged}), (to_open, {"status": S.open})):
            for j in range(0, len(ids), 500):
                await db.execute(update(Finding).where(Finding.id.in_(ids[j:j + 500])).values(**values)
                                 .execution_options(synchronize_session=False))
        for j in range(0, len(to_bury), 500):
            await db.execute(update(Finding).where(Finding.id.in_(to_bury[j:j + 500])).values(status=S.merged)
                             .execution_options(synchronize_session=False))
        for fid, when in first.items():
            await db.execute(update(Finding).where(Finding.id == fid).values(first_detected=when)
                             .execution_options(synchronize_session=False))
        for fid, (when, src) in fixed.items():
            note = f"Tanium saw it fixed on {when.date().isoformat()}; {label(src)} will re-check"
            await db.execute(update(Finding).where(Finding.id == fid).values(status=S.remediated, closed_at=now, closed_note=note[:200])
                             .execution_options(synchronize_session=False))
        touched = set(to_merge) | set(to_open) | set(to_bury) | set(first) | set(fixed)
        changed |= {str(r.device_id) for r in list(agent) + list(scan) if r.id in touched}
        await db.commit()
    if changed:
        from api.scoring.dirty import mark_devices
        await mark_devices(db, list(changed))
        await db.commit()
    return changed
