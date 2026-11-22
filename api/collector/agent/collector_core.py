"""Shipper plumbing shared by setup and run: CTEM client, local files, check-in, unsealing."""
import importlib
import json
import os
import re
import socket
import subprocess  # nosec B404 - only ever runs systemd-creds with fixed args
import time

import collector_common as cc
import collector_crypto as crypto

AGENT_VERSION = "1.1.2"
CONF_DIR = os.environ.get("OCTEM_CONF_DIR", "/etc/open-ctem-collector")
STATE_DIR = os.environ.get("STATE_DIRECTORY", "/var/lib/open-ctem-collector")
MODULES = {"ldap": "collector_ldap", "rapid7_console": "collector_rapid7",
           "crowdstrike": "collector_crowdstrike", "splunk": "collector_splunk"}
URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:\d{1,5})?$")


def mod(kind):
    return importlib.import_module(MODULES[kind])


def host_name():
    # In Docker the container id isn't a useful name; the installer passes the real host's name in
    return os.environ.get("OCTEM_HOST") or socket.getfqdn()


def hello(extra=None):
    out = {"hostname": re.sub(r"[^A-Za-z0-9._-]", "-", host_name())[:253] or "shipper", "agent_version": AGENT_VERSION}
    return {**out, **(extra or {})}


class Ctem:
    def __init__(self, url, token=None, cafile=None):
        if not URL_RE.match(url.rstrip("/")):
            raise ValueError("CTEM URL must be https://host[:port]")
        self.url, self.token, self.cafile = url.rstrip("/"), token, cafile

    def call(self, method, path, body=None, retries=0):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        for attempt in range(retries + 1):
            try:
                return cc.url_json(method, self.url + path, headers=headers, body=body, cafile=self.cafile, timeout=120)
            except cc.HttpError as e:
                if attempt >= retries or not (e.status == 429 or e.status >= 500):
                    raise
            except OSError:
                if attempt >= retries:
                    raise
            time.sleep(min(60, 2 ** (attempt + 2)))


def explain(e):
    if isinstance(e, cc.HttpError):
        return {401: "rejected: wrong username/password, MFA code, enrollment code, or a revoked shipper",
                403: "not allowed: needs an admin account with MFA set up, or password sign-in is off (use an installer from CTEM)",
                409: "CTEM says this shipper isn't enrolled yet",
                429: "too many attempts, wait a few minutes"}.get(e.status, f"CTEM answered HTTP {e.status}")
    if cc.is_cert_error(e):
        return "CTEM's TLS certificate isn't trusted here (TLS inspection proxy? give the CA bundle path)"
    return cc.short_error(e)


def test_ctem(url, cafile=None, quiet=False):
    """Reachability, TLS, and 'is this really open-ctem' in one go."""
    info = Ctem(url, cafile=cafile).call("GET", "/api/v1/collector/info")
    if not isinstance(info, dict) or info.get("service") != "open-ctem":
        raise RuntimeError("that URL answered, but it isn't an open-ctem server")
    if not quiet:
        cc.say(f"  ok: open-ctem {info.get('version')} reachable over verified HTTPS")
    return info


# ── local files ───────────────────────────────────────────────────────────────
def write_json(path, data, mode):
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)


def read_json(path, default=None):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        if default is not None:
            return default
        raise


def load_conf(conf_dir=CONF_DIR):
    return read_json(os.path.join(conf_dir, "collector.json"))


def load_pins(conf_dir=CONF_DIR):
    return read_json(os.path.join(conf_dir, "pins.json"), {})


def load_identity(conf_dir=CONF_DIR):
    """Systemd hands it over decrypted; root can unseal it on demand; Docker keeps a 0600 file."""
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir and os.path.exists(os.path.join(cred_dir, "octem-identity")):
        return read_json(os.path.join(cred_dir, "octem-identity"))
    plain = os.path.join(conf_dir, "identity.json")
    if os.path.exists(plain):
        return read_json(plain)
    sealed = os.path.join(conf_dir, "identity.cred")
    if os.path.exists(sealed):
        out = subprocess.run(["systemd-creds", "decrypt", "--name=octem-identity", sealed, "-"],  # nosec B603 B607
                             capture_output=True, check=True, timeout=30)
        return json.loads(out.stdout)
    raise SystemExit("no shipper identity found; run the installer")


class Shipper:
    """One enrolled box: its CTEM client, identity, approvals, and the latest profile from CTEM."""

    def __init__(self, conf_dir=CONF_DIR):
        self.conf_dir = conf_dir
        self.conf = load_conf(conf_dir)
        self.ident = load_identity(conf_dir)
        self.pins = load_pins(conf_dir)
        self.api = Ctem(self.conf["ctem_url"], self.ident["token"], self.conf.get("ctem_ca_file"))
        self.cfg = None

    def checkin(self, errors=None, ran=False):
        approved = {k: v["digest"] for k, v in self.pins.items() if v.get("digest")}
        self.cfg = self.api.call("POST", "/api/v1/collector/checkin",
                                 hello({"approved": approved, "errors": errors or {}, "ran": ran}), retries=3)
        return self.cfg

    def modules(self):
        return [m for m in (self.cfg or {}).get("modules", []) if m.get("enabled", True) and m["kind"] in MODULES]

    def approved(self, m):
        """Recompute the digest ourselves; never trust CTEM's word for what changed."""
        mine = cc.dest_digest(m["kind"], m["settings"])
        pin = self.pins.get(m["kind"]) or {}
        return pin if pin.get("digest") == mine else None

    def settings_for(self, m):
        pin = self.approved(m)
        return None if pin is None else {**m["settings"], **pin.get("resolved", {}), "pin": pin.get("pin")}

    def secrets(self):
        """Unseal everything CTEM sent for us. Plaintext lives in memory only."""
        out, problems = {}, {}
        for s in (self.cfg or {}).get("secrets", []):
            try:
                val = crypto.unseal(self.ident["private_key"], self.ident["key_fp"], self.cfg["profile_id"],
                                    s["kind"], s["field"], s["envelope"])
                out.setdefault(s["kind"], {})[s["field"]] = val
            except Exception as e:
                problems[s["kind"]] = f"couldn't open sealed {s['field']} ({type(e).__name__}); re-enter it in CTEM"
        return out, problems
