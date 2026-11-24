"""open-ctem shipper: reads internal sources and ships them to CTEM's REST API over HTTPS.

Config and sealed passwords come from CTEM; destinations only change after `approve` on this box.

  ctem_collector.py setup ...      enroll this box (the installer runs this)
  ctem_collector.py approve        review + approve destination changes made in CTEM
  ctem_collector.py secrets        type source passwords here (sealed to this box, stored in CTEM)
  ctem_collector.py test-ctem      check CTEM is reachable and the TLS chain is good
  ctem_collector.py test           check every source with the current config, ship nothing
  ctem_collector.py run [--force]  check in, and ship if the schedule says so (cron fires this)
  ctem_collector.py daemon         Docker mode: check in every 5 minutes forever
"""
import argparse
import fcntl
import json
import os
import random
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import collector_common as cc  # noqa: E402
import collector_core as core  # noqa: E402

TICK = 5 * 60
SPOOL_MAX_AGE = 7 * 86400
MAX_BODY = 768 * 1024  # load balancers commonly stop at 1 MB


def _state(update=None, kind=None):
    """A source's own state (state.<kind>.json), so sources running side by side never overwrite each other's.
    A source's first file starts from the shared state.json older shippers kept, so nothing restarts from zero."""
    path = os.path.join(core.STATE_DIR, f"state.{kind}.json" if kind else "state.json")
    if update is not None:
        core.write_json(path, update, 0o600)
        return update
    if kind and not os.path.exists(path):
        return dict(core.read_json(os.path.join(core.STATE_DIR, "state.json"), {}))
    return core.read_json(path, {})


# ── staging: every batch hits disk before it leaves, and is deleted once CTEM has it ──
def _spool_dir(iid):
    path = os.path.join(core.STATE_DIR, "spool", iid)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _count(part):
    return sum(len(v) for k, v in part.items() if isinstance(v, list) and k != "warnings")


def _fit(part, limit=None):
    """Halve the biggest list until each piece fits under the load balancer's body limit."""
    limit = limit or MAX_BODY
    if len(json.dumps(part, separators=(",", ":"))) <= limit:
        yield part
        return
    key = max((k for k, v in part.items() if isinstance(v, list)), key=lambda k: len(part[k]), default=None)
    if key is None or len(part[key]) < 2:
        yield part  # one giant record; let CTEM say no
        return
    half = len(part[key]) // 2
    yield from _fit({**part, key: part[key][:half]}, limit)
    yield from _fit({key: part[key][half:]}, limit)


def _send(api, path, kind, run_id, part, spool_file):
    for piece in _fit(part):
        api.call("POST", path, {"kind": kind, "run_id": run_id, "final": False, **piece}, retries=4)
    os.remove(spool_file)
    return _count(part)


def ship(api, m, s, secret, state):
    run_id, sent = str(uuid.uuid4()), 0
    path = f"/api/v1/collector/ingest/{m['integration_id']}"
    spool = _spool_dir(m["integration_id"])
    # Anything a crashed or offline run left behind goes out first, then fresh data overwrites it
    for name in sorted(os.listdir(spool)):
        f = os.path.join(spool, name)
        if time.time() - os.path.getmtime(f) > SPOOL_MAX_AGE:
            os.remove(f)
            continue
        sent += _send(api, path, m["kind"], run_id, core.read_json(f), f)
    for seq, part in enumerate(core.mod(m["kind"]).collect(s, secret, state)):
        f = os.path.join(spool, f"{time.time_ns()}-{seq:06d}.json")
        core.write_json(f, part, 0o600)
        sent += _send(api, path, m["kind"], run_id, part, f)
    api.call("POST", path, {"kind": m["kind"], "run_id": run_id, "final": True}, retries=4)
    return sent


def _prune_spool(keep):
    root = os.path.join(core.STATE_DIR, "spool")
    if not os.path.isdir(root):
        return
    for iid in os.listdir(root):
        if iid not in keep:
            d = os.path.join(root, iid)
            for name in os.listdir(d):
                os.remove(os.path.join(d, name))
            os.rmdir(d)


# ── the run ───────────────────────────────────────────────────────────────────
# Each source runs under its own lock and state, so sources run side by side: a long console pass never holds up
# the EDR. systemd starts one instance per source (open-ctem-collector-source@<kind>); Docker mode starts one process
# per source; a plain "run" (run-now, older units) does every due source in turn, skipping any already running.
def run(force=False, only=None):
    os.makedirs(core.STATE_DIR, exist_ok=True)
    # A run from a shipper before 1.5.0 holds the one shared lock; let it finish rather than run alongside it
    with open(os.path.join(core.STATE_DIR, "run.lock"), "w") as legacy:
        try:
            fcntl.flock(legacy, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            cc.say("a run from the previous shipper version is still going; starting once it's done")
            return 0
    sh = core.Shipper()
    cfg = sh.checkin()
    mods = [m for m in sh.modules() if only is None or m["kind"] == only]
    if only is None:
        _prune_spool({m["integration_id"] for m in sh.modules()})
    if not mods:
        return 0
    secrets, problems = None, {}
    worst = 0
    for m in mods:
        kind = m["kind"]
        with open(os.path.join(core.STATE_DIR, f"run.{kind}.lock"), "w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                if only:
                    cc.say(f"{kind}: still running from an earlier start; skipping")
                continue
            state = _state(kind=kind)
            if not _due(m, cfg, state, time.time(), force):
                continue
            if secrets is None:
                secrets, problems = sh.secrets()
            err = _run_source(sh, m, cfg, state, secrets, problems)
            state.setdefault("errors", {}).pop(kind, None)
            if err:
                state["errors"][kind] = err
                worst = 1
            _state(state, kind=kind)   # this source's run is recorded now, whatever the others do
            sh.checkin({kind: err} if err else {}, ran=True)
    return worst


def _every(m, cfg):
    """Minutes between runs for one source: its own setting, else the shipper's."""
    return int((m.get("settings") or {}).get("schedule_minutes") or cfg["schedule_minutes"])


def _due(m, cfg, state, now, force):
    last = float((state.get("last_by_kind") or {}).get(m["kind"], state.get("last_run", 0)))
    cron = (m.get("settings") or {}).get("cron")
    if cron:   # a source with a cron schedule (network discovery) runs at those times only
        try:
            return force or cc.cron_due(cron, last, now)
        except ValueError:
            return False
    return force or now - last >= _every(m, cfg) * 60 - 60  # a minute of slack for cron jitter


def _run_source(sh, m, cfg, state, secrets, problems):
    """Ship one source; returns its error, or None."""
    kind = m["kind"]
    state.setdefault("last_by_kind", {})[kind] = time.time()
    s = sh.settings_for(m)
    if s is None:
        return "destination changed in CTEM; waiting for `open-ctem-collector approve` on the box"
    if kind in problems:
        return problems[kind]
    secret = secrets.get(kind, {})
    missing = [f for f in core.mod(kind).SECRETS if f not in secret]
    if missing:
        return f"no {', '.join(missing)} set in CTEM yet"
    if kind == "netprobe":   # what to probe, fresh from CTEM; the box still limits it to the approved scope
        s["targets"] = sh.api.call("GET", f"/api/v1/collector/netprobe/{m['integration_id']}/targets") or {}
    if kind == "splunk":
        gap = (time.time() - float(state.get("splunk_ok", 0))) / 60
        s["lookback_minutes"] = int(min(max(gap, _every(m, cfg)) + 5, 7 * 1440))
    started = time.time()
    try:
        n = ship(sh.api, m, s, secret, state)
        cc.say(f"{kind}: shipped {n} records in {time.time() - started:.0f}s")
        if kind == "splunk":
            state["splunk_ok"] = started
            core.mod(kind).deliver(sh.api, m, s, secret, state, os.path.join(core.STATE_DIR, "alerts"))
        return None
    except Exception as e:
        err = cc.short_error(e)
        cc.say(f"{kind}: FAILED {err}")
        return err


def probe(dry_run):
    """What network discovery touches, after this box's approved scope; --dry-run sends nothing to any host."""
    import collector_netprobe as npm
    sh = core.Shipper()
    m = next((x for x in sh.modules() if x["kind"] == "netprobe"), None)
    if m is None:
        cc.say("  network discovery isn't enabled for this shipper in CTEM")
        return 1
    s = sh.settings_for(m)
    if s is None:
        cc.say("  its scope changed in CTEM; run `open-ctem-collector approve` first")
        return 1
    s["targets"] = sh.api.call("GET", f"/api/v1/collector/netprobe/{m['integration_id']}/targets") or {}
    todo = npm.targets(s, npm.exclusions(s), min(max(int(s.get("max_hosts") or 4096), 1), 20000))
    ports = npm.ports_of(s)
    cc.say(f"  {len(todo)} addresses in scope (internal only, minus {s.get('exclude_cidrs') or 'no exclusions'}), "
           f"ports {','.join(map(str, ports))}")
    for ip in todo[:50]:
        cc.say(f"    {ip}")
    if len(todo) > 50:
        cc.say(f"    ... and {len(todo) - 50} more")
    if dry_run:
        return 0
    state = _state(kind="netprobe")
    cc.say(f"  shipped {ship(sh.api, m, s, {}, state)} results")
    _state(state, kind="netprobe")
    return 0


def daemon():
    """Docker mode: no cron in the container, so tick here, each source in its own process (side by side)."""
    import subprocess  # nosec B404 - runs this same script, fixed arguments
    while not os.path.exists(os.path.join(core.CONF_DIR, "collector.json")):
        cc.say("waiting for setup; run the installer first")
        time.sleep(60)
    running = {}
    while True:
        for kind, proc in list(running.items()):
            if proc.poll() is not None:
                running.pop(kind)
        for kind in core.MODULES:
            if kind not in running:
                running[kind] = subprocess.Popen([sys.executable, os.path.abspath(__file__), "run", "--only", kind])  # nosec B603
        time.sleep(TICK + random.randint(0, 30))  # nosec B311 - jitter, not crypto


def test():
    bad = 0
    try:
        sh = core.Shipper()
        sh.checkin()
        cc.say(f"  ok: CTEM accepted this shipper (profile '{sh.cfg['name']}', config v{sh.cfg['config_version']})")
    except Exception as e:
        cc.say(f"  CTEM: {core.explain(e)}")
        return 1
    secrets, problems = sh.secrets()
    for m in sh.modules():
        kind, s = m["kind"], sh.settings_for(m)
        try:
            if s is None:
                raise RuntimeError("destination not approved on this box yet (run approve)")
            if kind in problems:
                raise RuntimeError(problems[kind])
            core.mod(kind).test(s, secrets.get(kind, {}))
            cc.say(f"  ok: {kind}")
        except Exception as e:
            bad += 1
            cc.say(f"  {kind}: {cc.short_error(e)}")
    return 1 if bad else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="open-ctem-collector")
    p.add_argument("--version", action="version", version=f"open-ctem shipper {core.AGENT_VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("setup")
    w.add_argument("--url", default="")
    w.add_argument("--code", default="")
    w.add_argument("--name", default="")
    w.add_argument("--out-dir", required=True)
    sub.add_parser("approve")
    u = sub.add_parser("set-url", help="point this shipper at CTEM's new address (same CTEM, new hostname)")
    u.add_argument("url", nargs="?", default="")
    u.add_argument("--ca-file", default=None, help="CA bundle for the new address ('' to drop the saved one)")
    u.add_argument("--yes", action="store_true", help="don't ask before checking in at the new address")
    sub.add_parser("secrets").add_argument("--all", action="store_true", help="re-enter even the ones already set")
    t = sub.add_parser("test-ctem")
    t.add_argument("--url", default="")
    t.add_argument("--ca-file", default=None)
    sub.add_parser("test")
    rp = sub.add_parser("run")
    rp.add_argument("--force", action="store_true")
    rp.add_argument("--only", choices=sorted(core.MODULES), help="run just this source (one per systemd instance)")
    sub.add_parser("daemon")
    pr = sub.add_parser("probe", help="network discovery: show what it would touch (--dry-run) or run it now")
    pr.add_argument("--dry-run", action="store_true", help="list the addresses and ports, probe nothing")
    args = p.parse_args(argv)
    cc.say(f"open-ctem shipper {core.AGENT_VERSION}")   # first line of every command, run and log
    if args.cmd in ("setup", "approve", "secrets", "set-url"):
        import collector_setup as setup
        if args.cmd == "setup":
            return setup.setup(args) or 0
        if args.cmd == "set-url":
            return setup.set_url(args)
        return setup.approve() if args.cmd == "approve" else setup.enter_secrets(only_missing=not args.all)
    if args.cmd == "test-ctem":
        url, ca = args.url, args.ca_file
        if not url:
            try:
                conf = core.load_conf()
                url, ca = conf["ctem_url"], ca or conf.get("ctem_ca_file")
            except (OSError, ValueError, KeyError):
                url = cc.ask("CTEM URL")
        try:
            core.test_ctem(url, ca)
            return 0
        except Exception as e:
            cc.say(f"  CTEM test failed: {core.explain(e)}")
            return 1
    if args.cmd == "run":
        return run(args.force, args.only)
    if args.cmd == "probe":
        return probe(args.dry_run)
    return daemon() if args.cmd == "daemon" else test()


if __name__ == "__main__":
    sys.exit(main())
