"""Which devices need a rescore: the ones where something the score reads actually changed, not every device a
sync touched. A sync bumps last-seen on every host it reports, which used to send half the fleet (3.9 million
findings) through scoring every run.

Inputs, by where they live (api/scoring/engine.py reads exactly these):
  device         EDR on and its policies, USB, internet exposure, criticality, type, containment, not-in-scope,
                 back from offline (over 30 days), its tags (repositories and sites), its cloud firewall
  finding        status, reachability and who said so, exposure, ports, domain, its vulnerability, details
  vulnerability  CVSS, EPSS, KEV, attack vector, threat actors, title and description (memory-flaw check)

Ordinary ORM writes are caught by a flush hook. Bulk UPDATE and DELETE statements bypass it, so each of those
calls mark_devices / mark_vulns itself (tests/test_score_dirty.py fails on an unmarked one). The scoring engine's
own writes never mark anything. The nightly full rescore stays as the backstop."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import event, inspect, update
from sqlalchemy.orm import Session

DEVICE_INPUTS = ("edr_active", "edr_vendor", "edr_prevention_policy", "edr_firewall_policy", "usb_storage_blocked",
                 "is_internet_exposed", "criticality", "device_type", "edr_contained", "scope_exempt_until")
FINDING_INPUTS = ("status", "is_reachable", "reachability_source", "exposure", "ports", "domain", "vuln_id",
                  "device_id", "details", "exception_id")
VULN_INPUTS = ("cvss_base", "epss_score", "is_kev", "attack_vector", "threat_actors", "title", "description", "cve_id")
OFFLINE_DAYS = 30   # compensating.py: offline over 30 days is discounted
CLOUD_INPUTS = ("ports", "firewalls", "internet_exposed", "device_id")   # not seen_at, bumped every sync
POLICY_INPUTS = ("body", "enabled", "name")                              # not reported_at, bumped every push
QUIET = "score_dirty.quiet"
log = logging.getLogger("open-ctem.score_dirty")


def _changed(obj, names) -> bool:
    return bool(_which(obj, names))


def _which(obj, names) -> list[str]:
    """The score inputs this object changed (their names only)."""
    st = inspect(obj)
    out = []
    for n in names:
        h = st.attrs[n].history
        if h.added and (not h.deleted or h.added[0] != h.deleted[0]):
            out.append(n)
    return out


LOUD = 100   # a save marking more devices than this is logged with why (counts and field names, never data)


def _why(obj, new_or_gone, names) -> str:
    kind = type(obj).__name__.lower()
    if new_or_gone:
        return f"{kind} added or removed"
    return f"{kind} " + ",".join(_which(obj, names) or ["offline flip" if kind == "device" else "changed"])


def _offline_flip(dev) -> bool:
    """last_seen moved across the 30-day line (back from long offline): the only last-seen change that matters."""
    h = inspect(dev).attrs["last_seen"].history
    if not h.added or not h.deleted:
        return False

    def far(dt):
        if dt is None:
            return True
        dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days > OFFLINE_DAYS
    return far(h.added[0]) != far(h.deleted[0])


def _collect(session: Session, flush_context, instances) -> None:
    """Before the flush: which objects changed an input. Their ids are read after it (a new row has none yet)."""
    if session.info.get(QUIET):
        return
    from api.models.cloud import CloudAsset
    from api.models.device import Device, DeviceTag
    from api.models.edr_policy import EdrPolicy
    from api.models.vuln import Finding, Vulnerability
    picked = session.info.setdefault("dirty_objects", [])
    # session.new and .deleted build a new set on every access: read them once, or a big flush is quadratic
    added, gone = session.new, session.deleted
    for obj in [*added, *session.dirty, *gone]:
        new_or_gone = obj in added or obj in gone
        if isinstance(obj, Device):
            if new_or_gone or _changed(obj, DEVICE_INPUTS) or _offline_flip(obj):
                picked.append(("device", obj, (), _why(obj, new_or_gone, DEVICE_INPUTS)))
        elif isinstance(obj, Finding):
            if new_or_gone or _changed(obj, FINDING_INPUTS):
                picked.append(("finding", obj, tuple(d for d in inspect(obj).attrs["device_id"].history.deleted if d),
                               _why(obj, new_or_gone, FINDING_INPUTS)))
        elif isinstance(obj, Vulnerability):
            if new_or_gone or _changed(obj, VULN_INPUTS):
                picked.append(("vuln", obj, (), _why(obj, new_or_gone, VULN_INPUTS)))
        elif isinstance(obj, DeviceTag) or (isinstance(obj, CloudAsset) and (new_or_gone or _changed(obj, CLOUD_INPUTS))):
            picked.append(("finding", obj, tuple(d for d in inspect(obj).attrs["device_id"].history.deleted if d),
                           _why(obj, new_or_gone, CLOUD_INPUTS if isinstance(obj, CloudAsset) else ())))
        elif isinstance(obj, EdrPolicy) and (new_or_gone or _changed(obj, POLICY_INPUTS)):   # not its reported_at
            picked.append(("policy", obj, (), _why(obj, new_or_gone, POLICY_INPUTS)))


def _stamp(session: Session, flush_context) -> None:
    from api.models.device import Device
    from api.models.vuln import Vulnerability
    from collections import Counter
    devs, vulns, policies, why = set(), set(), [], Counter()
    for kind, obj, before, reason in session.info.pop("dirty_objects", []):
        why[reason] += 1
        if kind == "device":
            devs.add(obj.id)
        elif kind == "finding":   # a finding, tag or cloud asset: the device it's on (and any it moved off)
            devs.add(obj.device_id)
            devs.update(before)
        elif kind == "vuln":
            vulns.add(obj.id)
        else:
            policies.append((obj.vendor, obj.policy_id))
    devs.discard(None)
    vulns.discard(None)
    now = datetime.now(timezone.utc)
    ids = [str(i) for i in devs]
    for i in range(0, len(ids), 500):
        session.execute(update(Device).where(Device.id.in_(ids[i:i + 500])).values(score_inputs_at=now)
                        .execution_options(synchronize_session=False))
    vids = [str(i) for i in vulns]
    for i in range(0, len(vids), 500):
        session.execute(update(Vulnerability).where(Vulnerability.id.in_(vids[i:i + 500])).values(score_inputs_at=now)
                        .execution_options(synchronize_session=False))
    by_policy = 0
    for vendor, pid in policies:   # a policy every host using it scores by
        r = session.execute(update(Device).where(Device.edr_vendor == vendor, (Device.edr_prevention_policy == pid)
                                                 | (Device.edr_firewall_policy == pid)).values(score_inputs_at=now)
                            .execution_options(synchronize_session=False))
        by_policy += r.rowcount or 0
    if len(ids) + by_policy > LOUD:   # worth knowing: why so many devices will be scored again
        log.warning("score inputs: %d devices marked (%d directly, %d through %d EDR policies), %d vulnerabilities; "
                    "changed: %s", len(ids) + by_policy, len(ids), by_policy, len(policies), len(vids),
                    "; ".join(f"{n} {r}" for r, n in why.most_common(8)))


def install() -> None:
    if not event.contains(Session, "before_flush", _collect):
        event.listen(Session, "before_flush", _collect)
        event.listen(Session, "after_flush", _stamp)


async def mark_devices(db, ids) -> None:
    """For bulk statements the flush hook can't see: these devices' scores must be worked out again."""
    from api.models.device import Device
    ids = [str(i) for i in {*ids} if i]
    if len(ids) > LOUD:
        import sys
        caller = sys._getframe(1).f_globals.get("__name__", "?")   # the module, never data
        log.warning("score inputs: %d devices marked by %s", len(ids), caller)
    now = datetime.now(timezone.utc)
    for i in range(0, len(ids), 500):
        await db.execute(update(Device).where(Device.id.in_(ids[i:i + 500])).values(score_inputs_at=now)
                         .execution_options(synchronize_session=False))


async def mark_finding_devices(db, *where) -> None:
    """The devices of the findings a bulk statement is about to change (call it before the statement)."""
    from sqlalchemy import select

    from api.models.vuln import Finding
    res = await db.execute(select(Finding.device_id).where(*where).distinct())
    await mark_devices(db, [d for (d,) in (res.all() if res is not None else [])])


async def mark_vulns(db, ids) -> None:
    from api.models.vuln import Vulnerability
    ids = [str(i) for i in {*ids} if i]
    now = datetime.now(timezone.utc)
    for i in range(0, len(ids), 500):
        await db.execute(update(Vulnerability).where(Vulnerability.id.in_(ids[i:i + 500])).values(score_inputs_at=now)
                         .execution_options(synchronize_session=False))


async def mark_app_assets(db) -> None:
    """Tag-role rules (environment, owners) feed every repository's and site's score."""
    from api.models.device import Device, DeviceType
    await db.execute(update(Device).where(Device.device_type.in_([DeviceType.code_repository, DeviceType.website]))
                     .values(score_inputs_at=datetime.now(timezone.utc)).execution_options(synchronize_session=False))
