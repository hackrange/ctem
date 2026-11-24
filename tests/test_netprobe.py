"""Network discovery: the box probes only internal, approved, unmanaged addresses, fast; CTEM picks them and records
what answers, including devices no tool knows."""
from __future__ import annotations

import socket
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api" / "collector" / "agent"))

import collector_common as cc  # noqa: E402
import collector_netprobe as np  # noqa: E402


def test_scope_is_internal_minus_exclusions_and_sweeps_skip_managed_hosts():
    s = {"targets": {"hosts": ["10.82.180.50", "198.51.100.7", "10.40.1.1", "not-an-ip"], "sweep": ["10.82.180.0/24", "10.0.0.0/8"],
                     "skip": ["10.82.180.11"]}, "exclude_cidrs": "10.40.0.0/16"}
    got = np.targets(s, np.exclusions(s), 10_000)
    assert got[0] == "10.82.180.50" and "198.51.100.7" not in got and "10.40.1.1" not in got   # public and excluded: never
    assert "10.82.180.11" not in got and "10.82.180.12" in got and len(got) == 253          # the /24 minus one managed host
    assert not any(ip.startswith("10.0.") for ip in got)                                     # nothing wider than a /24 is swept
    assert len(np.targets({**s, "sweep_subnets": "off"}, [], 10_000)) == 2
    assert len(np.targets(s, [], 5)) == 5
    with pytest.raises(ValueError):
        np.exclusions({"exclude_cidrs": "10.1.2.3/99"})


def test_ports_are_the_common_ones_unless_set():
    assert np.ports_of({}) == np.COMMON_PORTS and 3389 in np.COMMON_PORTS and len(np.COMMON_PORTS) <= 40
    assert np.ports_of({"ports": "22, 3389,22,70000,x"}) == (22, 3389)


def test_a_host_is_checked_on_every_port_at_once(monkeypatch):
    srv, gone = socket.socket(), socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    gone.bind(("127.0.0.1", 0))
    closed = gone.getsockname()[1]
    gone.close()   # nothing listens there now: refused at once
    port = srv.getsockname()[1]
    assert np.listening("127.0.0.1", (port, closed), 500) == [port]
    srv.close()

    # A silent host, without depending on what the test machine's network does with a real address: every connect
    # is left pending and nothing ever answers, so all ports share one timeout instead of one each
    class Pending:
        def __init__(self, *a):
            pass

        def setblocking(self, _):
            pass

        def connect_ex(self, _addr):
            return np.errno.EINPROGRESS

        def close(self):
            pass

    class Quiet:
        def __init__(self):
            self.n = 0

        def register(self, *_):
            self.n += 1

        def select(self, timeout=None):
            time.sleep(timeout or 0)
            return []

        def close(self):
            pass
    monkeypatch.setattr(np.socket, "socket", Pending)
    monkeypatch.setattr(np.selectors, "DefaultSelector", Quiet)
    t = time.monotonic()
    assert np.listening("10.82.180.99", np.COMMON_PORTS, 300) == []
    assert time.monotonic() - t < 1   # one 0.3 s timeout, not one per port


def test_collect_sends_answers_and_known_hosts_only(monkeypatch):
    up = {"10.82.180.50", "10.82.180.77"}
    # Only the network is faked (ping and the port check), so the real per-host code runs
    monkeypatch.setattr(np, "_ping", lambda ip, t: False)
    monkeypatch.setattr(np, "listening", lambda ip, ports, t: [80] if ip in up else [])
    s = {"targets": {"hosts": ["10.82.180.50", "10.82.180.60"], "sweep": ["10.82.180.0/24"]}}
    sent = [p for batch in np.collect(s, {}, {}) for p in batch["probes"]]
    assert {p["ip"] for p in sent} == {"10.82.180.50", "10.82.180.60", "10.82.180.77"}   # the silent known host is reported too


def test_cron_schedule():
    day = datetime(2026, 11, 24, tzinfo=timezone.utc).timestamp()
    assert cc.cron_due("0 2 * * *", day, day + 2 * 3600)                # 02:00 passed
    assert not cc.cron_due("0 2 * * *", day + 2 * 3600, day + 3 * 3600)  # already ran at 02:00
    assert cc.cron_due("*/15 * * * 1-5", day, day + 15 * 60)             # a Tuesday, every 15 minutes
    assert not cc.cron_due("0 2 * * 0", day, day + 23 * 3600)            # Sundays only
    with pytest.raises(ValueError):
        cc.cron_parse("0 25 * * *")


def test_settings_are_checked():
    from api.collector.profile import NetProbeSettings, dest_digest
    ok = NetProbeSettings(cron="30 1 * * 1-5", ports="22, 445,22", exclude_cidrs="10.40.0.0/16; 10.82.200.0/24")
    assert ok.ports == "22,445" and ok.exclude_cidrs == "10.40.0.0/16,10.82.200.0/24"
    for bad in ({"cron": "0 2 * *"}, {"cron": "0 24 * * *"}, {"ports": "0"}, {"ports": ",".join(str(p) for p in range(1, 42))},
                {"exclude_cidrs": "10.1/99"}, {"concurrency": 1000}):
        with pytest.raises(ValidationError):
            NetProbeSettings(**bad)
    # What it may touch needs a yes on the box: changing it changes the approval digest, the schedule doesn't
    base = ok.model_dump()
    assert dest_digest("netprobe", base) != dest_digest("netprobe", {**base, "exclude_cidrs": ""})
    assert dest_digest("netprobe", base) == dest_digest("netprobe", {**base, "cron": "0 3 * * *"})
    assert cc.dest_digest("netprobe", base) == dest_digest("netprobe", base)   # the box agrees byte for byte


def test_results_refuse_public_addresses():
    from api.collector.schemas import NetProbeResult
    assert NetProbeResult(ip="10.1.2.3", alive=True, ports=[22]).ip == "10.1.2.3"
    with pytest.raises(ValidationError):
        NetProbeResult(ip="198.51.100.7")


@pytest.mark.asyncio
async def test_targets_are_unmanaged_hosts_and_their_subnets(db):
    import random

    from api.core import netprobe
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType
    net = f"10.{random.randint(200, 250)}.{random.randint(0, 255)}"
    tag = uuid.uuid4().hex[:6]

    def host(last, sources, **kw):
        ip = f"{net}.{last}"
        d = Device(hostname=f"np-{tag}-{last}", device_type=kw.pop("kind", DeviceType.unknown), sources=sources, ip=ip,
                   ip_hash=search_hash(ip), subnet_hash=search_hash(f"{net}.0/24"), **kw)
        db.add(d)
        return d
    host(50, ",horizon3,")
    host(11, ",crowdstrike,rapid7_insightvm,", kind=DeviceType.workstation, edr_vendor="crowdstrike")
    await db.commit()
    t = await netprobe.targets(db)
    assert f"{net}.50" in t["hosts"] and f"{net}.11" not in t["hosts"]
    assert f"{net}.0/24" in t["sweep"] and f"{net}.11" in t["skip"]


@pytest.mark.asyncio
async def test_what_answers_is_recorded_and_unknown_devices_appear(db):
    import random

    from sqlalchemy import select

    from api.core import netprobe
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType
    net = f"10.{random.randint(1, 99)}.{random.randint(0, 255)}"
    known = Device(hostname=f"np-known-{uuid.uuid4().hex[:6]}", device_type=DeviceType.unknown, sources=",horizon3,",
                   ip=f"{net}.50", ip_hash=search_hash(f"{net}.50"))
    db.add(known)
    await db.commit()
    now = datetime.now(timezone.utc)
    n = await netprobe.apply(db, [{"ip": f"{net}.50", "alive": True, "icmp": True, "ports": [80, 554], "at": now},
                                  {"ip": f"{net}.77", "alive": True, "icmp": False, "ports": [23], "at": now},
                                  {"ip": f"{net}.99", "alive": False, "icmp": False, "ports": [], "at": now}])
    await db.commit()
    assert n == 2
    await db.refresh(known)
    assert known.alive_ports == "80/tcp 554/tcp" and known.alive_at and ",netprobe," in known.sources
    rogue = (await db.execute(select(Device).where(Device.ip_hash == search_hash(f"{net}.77")))).scalar_one()
    assert rogue.source == "netprobe" and rogue.alive_ports == "23/tcp" and rogue.hostname == f"{net}.77"
    assert known.silent_since is None   # it answered
    # A silence starts a clock that only an answer stops
    later = datetime.now(timezone.utc)
    await netprobe.apply(db, [{"ip": f"{net}.50", "alive": False, "icmp": False, "ports": [], "at": now - timedelta(days=30)}])
    await db.commit()
    await db.refresh(known)
    first = known.silent_since
    assert first.replace(tzinfo=None) >= now.replace(tzinfo=None)   # the server's time, never the backdated one it was sent
    await netprobe.apply(db, [{"ip": f"{net}.50", "alive": False, "icmp": False, "ports": [], "at": later}])
    await db.commit()
    await db.refresh(known)
    assert known.silent_since == first   # from the first silence
    await netprobe.apply(db, [{"ip": f"{net}.50", "alive": True, "icmp": True, "ports": [], "at": later}])
    await db.commit()
    await db.refresh(known)
    assert known.silent_since is None
    assert (await db.execute(select(Device).where(Device.ip_hash == search_hash(f"{net}.99")))).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_targets_route_needs_the_owning_shipper(client):
    r = await client.get(f"/api/v1/collector/netprobe/{uuid.uuid4()}/targets")
    assert r.status_code in (401, 403, 404)


def test_a_rejected_setting_says_which_field_and_why():
    from fastapi import HTTPException

    from api.collector.service import clean_modules
    ok = clean_modules({"netprobe": {"settings": {"cron": "18 1 * * *", "ports": "21,22,23,80,443,8443,3389,3306,8080",
                                                  "sweep_subnets": "off", "timeout_ms": 200, "concurrency": 32}}})
    assert ok["netprobe"]["settings"]["max_hosts"] == 4096
    for bad, says in (({"max_hosts": 50000}, "max_hosts: Input should be less than or equal to 20000"),
                      ({"exclude_cidrs": "10.1.1.1-10.1.1.50"}, "exclude_cidrs: only networks such as 192.0.2.0/24"),
                      ({"cron": "18 1 * *"}, "cron: a cron schedule has five fields")):
        with pytest.raises(HTTPException) as e:
            clean_modules({"netprobe": {"settings": {"cron": "18 1 * * *", **bad}}})
        assert says in e.value.detail and "10.1.1.1-10.1.1.50" not in e.value.detail   # never echoes the value


def test_approve_can_show_and_check_the_scope():
    assert np.KIND == "netprobe" and np.LABEL
    s = {"exclude_cidrs": "10.40.0.0/16", "ports": "22,3389", "sweep_subnets": "off"}
    cc.check_dest("netprobe", s)                    # no host needed: the scope is what's approved
    assert np.probe(s) == ({}, None)
    assert "never: 10.40.0.0/16" in np.scope_text(s) and "22,3389" in np.scope_text(s) and "no /24 sweep" in np.scope_text(s)
    with pytest.raises(ValueError):
        cc.check_dest("netprobe", {"exclude_cidrs": "nope/99"})


def test_runs_take_turns_through_a_long_list(monkeypatch):
    monkeypatch.setattr(np, "_ping", lambda ip, t: False)
    monkeypatch.setattr(np, "listening", lambda ip, ports, t: [])
    hosts = [f"10.9.{i // 250}.{i % 250 + 1}" for i in range(2307)]
    s, state, seen = {"targets": {"hosts": hosts}, "sweep_subnets": "off", "max_hosts": 1000}, {}, []
    for _ in range(3):
        seen += [p["ip"] for b in np.collect(s, {}, state) for p in b["probes"]]
    assert set(seen) == set(hosts)   # three runs of 1,000 cover all 2,307


def test_a_shipper_with_every_source_approved_can_check_in():
    """Every source the box knows must be accepted at check-in, or one approval stops all of them from shipping."""
    import collector_core as core

    from api.collector.schemas import CheckinRequest
    digest = "a" * 64
    req = CheckinRequest(hostname="shipper001", agent_version="1.7.1", approved={k: digest for k in core.MODULES},
                         errors={k: "x" for k in core.MODULES})
    assert set(req.approved) == set(core.MODULES)



def test_approve_and_run_use_different_functions():
    """1.7.1 named both "probe", so the run called the approve-time one and failed on every host."""
    import inspect
    assert list(inspect.signature(np.probe).parameters) == ["settings"]
    assert list(inspect.signature(np.probe_host).parameters) == ["ip", "ports", "timeout_ms"]


def test_the_box_command_passes_only_through_and_has_probe():
    """run-now dropped --only, and there was no probe command for --dry-run (local and Docker helpers alike)."""
    sh = (Path(np.__file__).parent / "install.sh").read_text()
    assert sh.count(r'run --force "\${@:2}"') == 2
    assert sh.count(r'probe "\${@:2}"') == 2 and sh.count("probe [--dry-run]") == 2


@pytest.mark.asyncio
async def test_a_probe_answer_counts_as_last_seen(db, client_cyber):
    from datetime import timedelta

    from api.models.device import Device, DeviceType
    name = f"seen-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)
    db.add(Device(hostname=name, device_type=DeviceType.server, sources=",rapid7_insightvm,netprobe,",
                  last_seen=now - timedelta(days=40), alive_at=now - timedelta(minutes=5)))
    await db.commit()
    d = [x for x in (await client_cyber.get("/api/v1/devices", params={"q": name})).json()["devices"] if x["hostname"].lower() == name][0]
    assert d["last_seen_by"] == "net probe" and d["last_seen"].startswith(now.date().isoformat())
    assert d["scan_last_seen"].startswith((now - timedelta(days=40)).date().isoformat())   # the scanner's own date stays
    assert "net probe" in d["seen_by"]
