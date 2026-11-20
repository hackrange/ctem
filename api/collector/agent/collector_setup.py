"""Interactive bits: enroll this box, approve destinations, and (optionally) type secrets here."""
import os
import re
import shutil

import collector_common as cc
import collector_core as core
import collector_crypto as crypto

QUESTIONS = {"ldap": "Ship LDAP / Active Directory data?", "rapid7_console": "Ship Rapid7 InsightVM console data?",
             "crowdstrike": "Ship CrowdStrike Falcon data?", "splunk": "Ship local Splunk data?"}
SCHEDULES = ("15", "30", "60", "120", "240", "360", "720", "1440")
SVC_GROUP = "octem-collector"


def _share_with_service(path):
    # Root writes it; the service user only needs to read it
    try:
        shutil.chown(path, group=SVC_GROUP)
    except (LookupError, PermissionError, OSError):
        pass


def _ctem(default_url):
    cc.say("\n== CTEM server ==")
    cafile = None
    while True:
        url = cc.ask("CTEM URL", default=default_url or None,
                     validate=lambda v: None if core.URL_RE.match(v.rstrip("/")) else "use https://host[:port] with nothing after it").rstrip("/")
        try:
            return url, cafile, core.test_ctem(url, cafile)
        except Exception as e:
            cc.say(f"  CTEM test failed: {core.explain(e)}")
            if cc.is_cert_error(e) and cc.yes_no("Point at a CA bundle file for CTEM?", True):
                path = cc.ask("CA bundle path (PEM)")
                cafile = path if os.path.isfile(path) else None
            elif not cc.yes_no("Try again?", True):
                raise SystemExit("cancelled") from None


def _describe_box(args):
    """Generic installer: no profile in CTEM yet, so the box says what it ships."""
    host = core.host_name().split(".")[0]
    name = args.name or cc.ask("Name for this shipper", default=re.sub(r"[^A-Za-z0-9._-]", "-", host)[:64] or "shipper",
                               validate=lambda v: None if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", v) else "letters, digits, . _ - only")
    modules = {}
    for kind, question in QUESTIONS.items():
        if cc.yes_no(question, kind == "ldap"):
            modules[kind] = core.mod(kind).ask_settings()
    if not modules:
        raise SystemExit("nothing selected to ship")
    minutes = int(cc.ask(f"Ship every how many minutes? ({', '.join(SCHEDULES)})", default="60",
                         validate=lambda v: None if v in SCHEDULES else "pick one of the listed values"))
    return name, modules, minutes


def _sign_in_and_enroll(api, info, args, pub):
    if not info.get("password_login"):
        raise SystemExit("password sign-in is off on this CTEM. Download this shipper's installer from CTEM > Shippers instead.")
    cc.say("\n== CTEM admin sign-in (used once to enroll; never saved) ==")
    while True:
        user, password = cc.ask("CTEM username"), cc.ask_secret("CTEM password")
        try:
            check = api.call("POST", "/api/v1/collector/login-check", {"username": user, "password": password})
            cc.say("  ok: credentials accepted")
            break
        except Exception as e:
            cc.say(f"  sign-in failed: {core.explain(e)}")
            if not cc.yes_no("Try again?", True):
                raise SystemExit("cancelled") from None
    name, modules, minutes = _describe_box(args)
    totp = None
    if check.get("mfa"):
        totp = cc.ask("CTEM MFA code", validate=lambda v: None if re.fullmatch(r"\d{6,8}", v) else "digits only")
    return api.call("POST", "/api/v1/collector/enroll-login", {
        **core.hello(), "username": user, "password": password, "totp": totp, "name": name,
        "public_key": pub, "schedule_minutes": minutes, "modules": modules})


def setup(args):
    cc.say("open-ctem shipper setup\n" + "-" * 23)
    url, cafile, info = _ctem(args.url)
    api = core.Ctem(url, cafile=cafile)
    cc.say("  generating this shipper's key pair (the private key never leaves this box)")
    priv, pub = crypto.new_identity()
    fp = crypto.fingerprint(pub)
    try:
        if args.code:
            res = api.call("POST", "/api/v1/collector/enroll", {**core.hello(), "code": args.code, "public_key": pub})
        else:
            res = _sign_in_and_enroll(api, info, args, pub)
    except SystemExit:
        raise
    except Exception as e:
        raise SystemExit(f"enrollment failed: {core.explain(e)}") from None
    if res.get("key_fp") != fp:
        raise SystemExit("CTEM reported a different key fingerprint than the one we sent; stopping")
    cfg = res["config"]
    out = args.out_dir
    core.write_json(os.path.join(out, "collector.json"), {
        "ctem_url": url, "ctem_ca_file": cafile, "name": cfg["name"],
        "profile_id": cfg["profile_id"], "collector_id": res["collector_id"]}, 0o640)
    core.write_json(os.path.join(out, "identity.json"),
                    {"token": res["token"], "private_key": priv, "public_key": pub, "key_fp": fp}, 0o600)
    cc.say(f"\nEnrolled as shipper '{cfg['name']}'.")
    cc.say(f"  key fingerprint {cc.pretty_fp(fp)[:47]}...")
    cc.say("  CTEM > Shippers should show the same fingerprint. If it doesn't, stop and revoke.")
    approve(out)
    enter_secrets(out, only_missing=True)


def approve(conf_dir=core.CONF_DIR):
    """Destinations only change with a yes typed on this box. That's what keeps passwords home."""
    sh = core.Shipper(conf_dir)
    sh.checkin()
    changed = False
    for m in sh.modules():
        if sh.approved(m):
            continue
        kind, new = m["kind"], cc.dest_of(m["kind"], m["settings"])
        old = (sh.pins.get(kind) or {}).get("dest")
        cc.say(f"\n== {core.mod(kind).LABEL}: destination {'change' if old else 'to approve'} ==")
        if old:
            cc.say(f"  was: {old}")
        cc.say(f"  now: {new}")
        try:
            cc.check_dest(kind, m["settings"])
            resolved, pin = core.mod(kind).probe(m["settings"])
        except Exception as e:
            cc.say(f"  can't reach it securely: {cc.short_error(e)}. Leaving it unapproved.")
            continue
        if cc.yes_no(f"Approve this {kind} destination?", True):
            sh.pins[kind] = {"digest": cc.dest_digest(kind, m["settings"]), "dest": new, "resolved": resolved, "pin": pin}
            changed = True
    if changed:
        path = os.path.join(conf_dir, "pins.json")
        core.write_json(path, sh.pins, 0o640)
        _share_with_service(path)
        sh.checkin()
    waiting = [m["kind"] for m in sh.modules() if not sh.approved(m)]
    cc.say(f"\nApproved destinations: {', '.join(sh.pins) or 'none'}" + (f"; still waiting: {', '.join(waiting)}" if waiting else ""))
    return 0


def enter_secrets(conf_dir=core.CONF_DIR, only_missing=False):
    sh = core.Shipper(conf_dir)
    sh.checkin()
    have = {(s["kind"], s["field"]) for s in sh.cfg.get("secrets", [])}
    todo = [(m, f, label) for m in sh.modules() for f, label in core.mod(m["kind"]).SECRETS.items()
            if not (only_missing and (m["kind"], f) in have)]
    if not todo:
        cc.say("All source secrets are already set in CTEM.")
        return 0
    cc.say("\nSource passwords can be typed here or later in CTEM > Shippers. Either way they're sealed")
    cc.say("to this box's key, so CTEM stores them but can't read them.")
    if not cc.yes_no("Enter them here now?", True):
        return 0
    for m, field, label in todo:
        kind, s = m["kind"], sh.settings_for(m)
        while True:
            val = cc.ask_secret(label)
            if s is not None:
                try:
                    core.mod(kind).test(s, {field: val})
                    cc.say(f"  ok: {kind} accepted it")
                except Exception as e:
                    cc.say(f"  {kind} test failed: {cc.short_error(e)}")
                    if cc.yes_no("Try again?", True):
                        continue
                    if not cc.yes_no("Store it anyway?", False):
                        break
            env = crypto.seal(sh.ident["public_key"], sh.cfg["profile_id"], kind, field, val)
            sh.api.call("PUT", "/api/v1/collector/secrets", {"secrets": [{"kind": kind, "field": field, "envelope": env}]})
            cc.say(f"  sealed and stored in CTEM: {kind}.{field}")
            break
    return 0
