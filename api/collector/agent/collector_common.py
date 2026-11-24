"""Shared bits for the open-ctem collector: prompts, HTTPS, and certificate pinning."""
import getpass
import hashlib
import hmac
import http.client
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit

MAX_RESPONSE = 64 * 1024 * 1024
HOSTPORT_RE = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?::(\d{1,5}))?$")
_tty = None


class PinMismatch(Exception):
    pass


class HttpError(Exception):
    def __init__(self, status, body=None):
        why = _reason(body)
        super().__init__(f"HTTP {status}" + (f" ({why})" if why else ""))
        self.status, self.body = status, body


def _reason(body):
    """The API's own one-line reason (Falcon: errors[0].message, CTEM: detail), for the log. Never a secret."""
    msg = None
    if isinstance(body, dict):
        errs = body.get("errors")
        if isinstance(errs, list) and errs and isinstance(errs[0], dict):
            msg = errs[0].get("message")
        elif isinstance(body.get("detail"), str):
            msg = body["detail"]
    if not isinstance(msg, str):
        return None
    msg = "".join(ch if ord(ch) >= 32 else " " for ch in msg).strip()
    return msg[:160] or None


def say(msg=""):
    print(msg, file=sys.stderr, flush=True)


def _console():
    # Prompts go to the terminal even when the installer was piped into bash
    global _tty
    if _tty is None:
        try:
            _tty = (open("/dev/tty"), open("/dev/tty", "w"))  # noqa: SIM115 - held for the process lifetime
        except OSError:
            _tty = False
    return _tty


def ask(prompt, default=None, validate=None):
    while True:
        text = f"{prompt}{f' [{default}]' if default else ''}: "
        con = _console()
        if con:
            con[1].write(text)
            con[1].flush()
            raw = con[0].readline()
        else:
            sys.stderr.write(text)
            raw = sys.stdin.readline()
        if raw == "":
            raise SystemExit("\ninput closed, giving up")
        val = raw.strip() or (default or "")
        if not val:
            continue
        err = validate(val) if validate else None
        if err:
            say(f"  {err}")
            continue
        return val


def ask_secret(prompt):
    while True:
        val = getpass.getpass(f"{prompt}: ")
        if val:
            return val


def yes_no(prompt, default=True):
    hint = "Y/n" if default else "y/N"
    while True:
        val = ask(f"{prompt} ({hint})", default="y" if default else "n").lower()
        if val in ("y", "yes"):
            return True
        if val in ("n", "no"):
            return False


def host_port(val, default_port=None):
    m = HOSTPORT_RE.match(val.strip())
    if not m:
        raise ValueError("expected host or host:port")
    port = int(m.group(2)) if m.group(2) else default_port
    if port is not None and not 0 < port < 65536:
        raise ValueError("port out of range")
    return m.group(1), port


def check_host_port(val):
    try:
        host_port(val)
    except ValueError as e:
        return str(e)
    return None


def short_error(exc):
    # Good enough for a log line or a CTEM status chip; never includes credentials
    msg = str(exc).replace("\n", " ")
    return f"{type(exc).__name__}: {msg}"[:280]


def tls_context(cafile=None):
    ctx = ssl.create_default_context(cafile=cafile or None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _unverified_context():
    # Only used when a pinned fingerprint is checked right after the handshake
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # nosec B501 - fingerprint pin enforced by caller
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def fingerprint(der):
    return hashlib.sha256(der).hexdigest()


def pretty_fp(fp):
    return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)).upper()


def peer_fingerprint(host, port, timeout=10):
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with _unverified_context().wrap_socket(raw, server_hostname=host) as s:
            return fingerprint(s.getpeercert(binary_form=True))


def check_pin(der, pin):
    if not hmac.compare_digest(fingerprint(der), pin):
        raise PinMismatch("server certificate changed since it was pinned; re-run the installer to trust the new one")


def is_cert_error(exc):
    text = str(exc)
    return isinstance(exc, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text


def _decode(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def pinned_json(method, host, port, path, headers=None, body=None, pin=None, cafile=None, timeout=60, form=None):
    """HTTPS to an internal box (no proxy), optionally pinned to a cert fingerprint."""
    ctx = _unverified_context() if pin else tls_context(cafile)
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
    try:
        conn.connect()
        if pin:
            check_pin(conn.sock.getpeercert(binary_form=True), pin)
        hdrs = {"Accept": "application/json", **(headers or {})}
        data = None
        if form is not None:
            from urllib.parse import urlencode
            data = urlencode(form).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = _decode(resp.read(MAX_RESPONSE))
        if resp.status >= 400:
            raise HttpError(resp.status, payload)
        return payload
    finally:
        conn.close()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A redirect could carry our Authorization header somewhere else; just refuse
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HttpError(code, {"detail": f"unexpected redirect to {newurl}"})


def url_json(method, url, headers=None, body=None, form=None, cafile=None, timeout=60):
    """HTTPS via urllib so HTTPS_PROXY works. Always verifies certificates."""
    if urlsplit(url).scheme != "https":
        raise ValueError("only https URLs are allowed")
    hdrs = {"Accept": "application/json", "User-Agent": "open-ctem-collector", **(headers or {})}
    data = None
    if form is not None:
        from urllib.parse import urlencode
        data = urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=tls_context(cafile)), _NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:  # nosec B310 - scheme checked above
            return _decode(resp.read(MAX_RESPONSE))
    except urllib.error.HTTPError as e:
        raise HttpError(e.code, _decode(e.read(65536))) from None


# Mirrors api/collector/profile.py on the server; a test keeps the two in lockstep
DEST_KEYS = {"ldap": ("host", "port", "tls"), "rapid7_console": ("host", "port"),
             "crowdstrike": ("cloud",), "splunk": ("host", "port", "query"),
             # what the network probe may touch and how: only ever changed with a yes on the box
             "netprobe": ("exclude_cidrs", "ports", "sweep_subnets")}


# Destinations added later count only once set (each anchor key with the keys that go with it), so existing
# approvals stay valid: a new place a secret goes still needs a yes on the box
DEST_EXTRA = {"crowdstrike": {"fdr_queue_url": ("fdr_queue_url",)}, "splunk": {"hec_host": ("hec_host", "hec_port")}}


def dest_of(kind, settings):
    out = {k: settings.get(k) for k in DEST_KEYS[kind]}
    for anchor, keys in DEST_EXTRA.get(kind, {}).items():
        if settings.get(anchor):
            out.update({k: settings.get(k) for k in keys})
    return out


def dest_digest(kind, settings):
    import hashlib as _h
    blob = json.dumps([kind, dest_of(kind, settings)], sort_keys=True, separators=(",", ":"))
    return _h.sha256(blob.encode()).hexdigest()


def tls_probe(host, port, label):
    """Verified TLS if the CA store trusts it; otherwise show the fingerprint and offer to pin. Returns pin or None."""
    try:
        with socket.create_connection((host, port), timeout=15) as raw:
            with tls_context().wrap_socket(raw, server_hostname=host):
                say(f"  {label}: certificate verified by this machine's CA store")
                return None
    except ssl.SSLError as e:
        if not is_cert_error(e):
            raise
    fp = peer_fingerprint(host, port)
    say(f"  {label}: certificate isn't trusted by this machine (normal for self-signed)")
    say(f"  SHA-256 fingerprint: {pretty_fp(fp)}")
    if not yes_no("  Does that match the real server's certificate? Pin it", False):
        raise RuntimeError("certificate not trusted")
    return fp


def check_dest(kind, settings):
    """The box validates destinations itself; CTEM's validation is a courtesy, not a guarantee."""
    if kind == "netprobe":   # no destination; its scope is what gets approved
        import collector_netprobe as npm
        npm.exclusions(settings)
        if str(settings.get("sweep_subnets") or "on") not in ("on", "off"):
            raise ValueError("sweep_subnets is on or off")
        return
    host = settings.get("host")
    if kind != "crowdstrike" and (not isinstance(host, str) or not HOSTPORT_RE.match(host) or ":" in host):
        raise ValueError("destination host looks wrong")
    port = settings.get("port")
    if port is not None and (not isinstance(port, int) or not 0 < port < 65536):
        raise ValueError("destination port looks wrong")
    if kind == "ldap" and settings.get("tls") not in (None, "ldaps", "starttls"):
        raise ValueError("LDAP TLS mode must be ldaps or starttls; plain LDAP is never used")
    if kind == "splunk" and (not isinstance(settings.get("query"), str) or len(settings["query"]) > 2000):
        raise ValueError("SPL query looks wrong")


def _cron_field(spec, lo, hi):
    out = set()
    for part in str(spec).split(","):
        step = 1
        if "/" in part:
            part, st = part.split("/", 1)
            step = int(st)
        if part == "*":
            a, b = lo, hi
        elif "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
        else:
            a = b = int(part)
        if step < 1 or a < lo or b > hi or a > b:
            raise ValueError("cron field out of range")
        out.update(range(a, b + 1, step))
    return out


def cron_parse(expr):
    """Five fields, minute hour day-of-month month day-of-week (0 or 7 is Sunday): *, lists, ranges and steps."""
    f = str(expr or "").split()
    if len(f) != 5:
        raise ValueError("a cron schedule has five fields, like '30 2 * * *'")
    m, h, dom, mon, dow = (_cron_field(x, lo, hi) for x, (lo, hi) in zip(f, ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))))
    return m, h, dom, mon, {d % 7 for d in dow}, f[2] == "*", f[4] == "*"


def cron_due(expr, last, now):
    """Did a scheduled minute fall after `last` and by `now` (epoch seconds, UTC)? Looks back at most 8 days."""
    import datetime as _dt
    m, h, dom, mon, dow, any_dom, any_dow = cron_parse(expr)
    t = max(int(last // 60 + 1), int(now // 60) - 8 * 1440)
    for minute in range(t, int(now // 60) + 1):
        d = _dt.datetime.fromtimestamp(minute * 60, _dt.timezone.utc)
        day_ok = (d.day in dom or d.isoweekday() % 7 in dow) if not (any_dom or any_dow) else (d.day in dom and d.isoweekday() % 7 in dow)
        if d.minute in m and d.hour in h and d.month in mon and day_ok:
            return True
    return False
