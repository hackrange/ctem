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
def run(force=False):
    os.makedirs(core.STATE_DIR, exist_ok=True)
    with open(os.path.join(core.STATE_DIR, "run.lock"), "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            cc.say("another run is still going; skipping this one")
            return 0
        return _run_locked(force)


def _every(m, cfg):
    """Minutes between runs for one source: its own setting, else the shipper's."""
    return int((m.get("settings") or {}).get("schedule_minutes") or cfg["schedule_minutes"])


def _due(m, cfg, state, now, force):
    last = float((state.get("last_by_kind") or {}).get(m["kind"], state.get("last_run", 0)))
    return force or now - last >= _every(m, cfg) * 60 - 60  # a minute of slack for cron jitter


def _run_locked(force):
    state = _state()
    sh = core.Shipper()
    cfg = sh.checkin()
    now = time.time()
    due = [m for m in sh.modules() if _due(m, cfg, state, now, force)]
    if not due:
        return 0
    _prune_spool({m["integration_id"] for m in sh.modules()})
    secrets, problems = sh.secrets()
    # Sources that weren't due keep reporting their last problem, so CTEM's status doesn't flap
    errors = {k: v for k, v in (state.get("errors") or {}).items() if k in {m["kind"] for m in sh.modules()}}
    last_by_kind = state.setdefault("last_by_kind", {})
    for m in due:
        kind = m["kind"]
        errors.pop(kind, None)
        last_by_kind[kind] = time.time()
        s = sh.settings_for(m)
        if s is None:
            errors[kind] = "destination changed in CTEM; waiting for `open-ctem-collector approve` on the box"
            continue
        if kind in problems:
            errors[kind] = problems[kind]
            continue
        secret = secrets.get(kind, {})
        missing = [f for f in core.mod(kind).SECRETS if f not in secret]
        if missing:
            errors[kind] = f"no {', '.join(missing)} set in CTEM yet"
            continue
        if kind == "splunk":
            gap = (time.time() - float(state.get("splunk_ok", 0))) / 60
            s["lookback_minutes"] = int(min(max(gap, _every(m, cfg)) + 5, 7 * 1440))
        started = time.time()
        try:
            n = ship(sh.api, m, s, secret, state)
            cc.say(f"{kind}: shipped {n} records in {time.time() - started:.0f}s")
            if kind == "splunk":
                state["splunk_ok"] = started
        except Exception as e:
            errors[kind] = cc.short_error(e)
            cc.say(f"{kind}: FAILED {errors[kind]}")
    state.update(last_run=time.time(), errors=errors)
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
    sub.add_parser("run").add_argument("--force", action="store_true")
    sub.add_parser("daemon")
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
        return run(args.force)
    return daemon() if args.cmd == "daemon" else test()


if __name__ == "__main__":
    sys.exit(main())
