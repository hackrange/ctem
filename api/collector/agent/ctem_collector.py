"""open-ctem shipper: reads internal sources and ships them to CTEM's REST API over HTTPS.

Config and sealed passwords come from CTEM; destinations only change after `approve` on this box.

  ctem_collector.py setup ...      enroll this box (the installer runs this)
  ctem_collector.py approve        review + approve destination changes made in CTEM
  ctem_collector.py secrets        type source passwords here (sealed to this box, stored in CTEM)
  ctem_collector.py test-ctem      check CTEM is reachable and the TLS chain is good
  ctem_collector.py test           check every source with the current config, ship nothing
  ctem_collector.py run [--force]  check in, and ship if the schedule says so (cron fires this)
  ctem_collector.py daemon         Docker mode: check in every 15 minutes forever
"""
import argparse
import fcntl
import os
import random
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import collector_common as cc  # noqa: E402
import collector_core as core  # noqa: E402

TICK = 15 * 60
SPOOL_MAX_AGE = 7 * 86400


def _state(update=None):
    path = os.path.join(core.STATE_DIR, "state.json")
    if update is not None:
        core.write_json(path, update, 0o600)
        return update
    return core.read_json(path, {})


# ── staging: every batch hits disk before it leaves, and is deleted once CTEM has it ──
def _spool_dir(iid):
    path = os.path.join(core.STATE_DIR, "spool", iid)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _post_and_forget(api, path, body, spool_file):
    api.call("POST", path, body, retries=4)
    os.remove(spool_file)


def _count(part):
    return sum(len(v) for v in part.values() if isinstance(v, list))


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
        part = core.read_json(f)
        _post_and_forget(api, path, {"kind": m["kind"], "run_id": run_id, "final": False, **part}, f)
        sent += _count(part)
    for seq, part in enumerate(core.mod(m["kind"]).collect(s, secret, state)):
        f = os.path.join(spool, f"{time.time_ns()}-{seq:06d}.json")
        core.write_json(f, part, 0o600)
        _post_and_forget(api, path, {"kind": m["kind"], "run_id": run_id, "final": False, **part}, f)
        sent += _count(part)
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
def run(force=False):
    os.makedirs(core.STATE_DIR, exist_ok=True)
    with open(os.path.join(core.STATE_DIR, "run.lock"), "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            cc.say("another run is still going; skipping this one")
            return 0
        return _run_locked(force)


def _run_locked(force):
    state = _state()
    sh = core.Shipper()
    cfg = sh.checkin()
    due = force or time.time() - float(state.get("last_run", 0)) >= cfg["schedule_minutes"] * 60 - 60
    if not due:
        return 0
    _prune_spool({m["integration_id"] for m in sh.modules()})
    secrets, errors = sh.secrets()
    for m in sh.modules():
        kind = m["kind"]
        s = sh.settings_for(m)
        if s is None:
            errors[kind] = "destination changed in CTEM; waiting for `open-ctem-collector approve` on the box"
            continue
        secret = secrets.get(kind, {})
        missing = [f for f in core.mod(kind).SECRETS if f not in secret]
        if missing:
            errors.setdefault(kind, f"no {', '.join(missing)} set in CTEM yet")
            continue
        if kind == "splunk":
            gap = (time.time() - float(state.get("splunk_ok", 0))) / 60
            s["lookback_minutes"] = int(min(max(gap, cfg["schedule_minutes"]) + 5, 7 * 1440))
        started = time.time()
        try:
            n = ship(sh.api, m, s, secret, state)
            cc.say(f"{kind}: shipped {n} records in {time.time() - started:.0f}s")
            if kind == "splunk":
                state["splunk_ok"] = started
        except Exception as e:
            errors[kind] = cc.short_error(e)
            cc.say(f"{kind}: FAILED {errors[kind]}")
    state.update(last_run=time.time())
    _state(state)
    sh.checkin(errors, ran=True)
    return 1 if errors else 0


def daemon():
    """Docker mode: no cron in the container, so tick here."""
    while not os.path.exists(os.path.join(core.CONF_DIR, "collector.json")):
        cc.say("waiting for setup; run the installer first")
        time.sleep(60)
    while True:
        try:
            run()
        except Exception as e:
            cc.say(f"run failed: {cc.short_error(e)}")
        time.sleep(TICK + random.randint(0, 60))  # nosec B311 - jitter, not crypto


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
    sub = p.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("setup")
    w.add_argument("--url", default="")
    w.add_argument("--code", default="")
    w.add_argument("--name", default="")
    w.add_argument("--out-dir", required=True)
    sub.add_parser("approve")
    sub.add_parser("secrets").add_argument("--all", action="store_true", help="re-enter even the ones already set")
    t = sub.add_parser("test-ctem")
    t.add_argument("--url", default="")
    t.add_argument("--ca-file", default=None)
    sub.add_parser("test")
    sub.add_parser("run").add_argument("--force", action="store_true")
    sub.add_parser("daemon")
    args = p.parse_args(argv)
    if args.cmd in ("setup", "approve", "secrets"):
        import collector_setup as setup
        if args.cmd == "setup":
            return setup.setup(args) or 0
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
        return run(args.force)
    return daemon() if args.cmd == "daemon" else test()


if __name__ == "__main__":
    sys.exit(main())
