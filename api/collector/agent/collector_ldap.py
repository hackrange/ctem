"""LDAP / Active Directory module: users and computer objects, paged, over LDAPS or StartTLS."""
import re
import ssl
from datetime import datetime, timedelta, timezone

import collector_common as cc

KIND = "ldap"
LABEL = "LDAP / Active Directory"
SECRETS = {"password": "LDAP bind password"}  # nosec B105 - prompt label
BATCH = 500
AD_CAPABILITY = "1.2.840.113556.1.4.800"
_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


def _ldap3():
    try:
        import ldap3
        return ldap3
    except ImportError:
        raise SystemExit("the ldap3 Python package is missing; re-run the installer") from None


def _open(s, password=None, probe=False):
    """Connect + TLS (+ pin check), then bind when a password is given. probe=True returns the cert fingerprint."""
    ldap3 = _ldap3()
    insecure = probe or bool(s.get("pin"))
    tls = ldap3.Tls(validate=ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED,  # nosec B504 - pin checked below
                    ca_certs_file=s.get("ca_file") or None)
    server = ldap3.Server(s["host"], port=s["port"], use_ssl=s["tls"] == "ldaps", tls=tls,
                          get_info=ldap3.ALL, connect_timeout=15)
    conn = ldap3.Connection(server, user=s.get("bind_user"), password=password, read_only=True,
                            raise_exceptions=True, receive_timeout=120, auto_bind=ldap3.AUTO_BIND_NONE)
    conn.open()
    if s["tls"] == "starttls":
        conn.start_tls()
    der = conn.socket.getpeercert(binary_form=True)
    if probe:
        conn.unbind()
        return cc.fingerprint(der)
    if s.get("pin"):
        cc.check_pin(der, s["pin"])
    if password is not None:
        conn.bind()
    return conn


def ask_settings():
    cc.say(f"\n== {LABEL} ==")
    host, port = cc.host_port(cc.ask("LDAP server (host or host:port)", validate=cc.check_host_port))
    s = {"host": host, "port": port, "tls": None}
    if port and port not in (389, 636):
        s["tls"] = "ldaps" if cc.yes_no(f"Is port {port} LDAPS (TLS from the first byte)?", True) else "starttls"
    s["bind_user"] = cc.ask("Bind username (ACME\\svc-ctem, svc-ctem@acme.example, or a full DN)")
    base = cc.ask("Base DN (blank = detect it)", default="auto")
    s["base_dn"] = None if base == "auto" else base
    return s


def _tries(s):
    if s.get("tls"):
        return [(s.get("port") or (636 if s["tls"] == "ldaps" else 389), s["tls"])]
    if s.get("port") == 636:
        return [(636, "ldaps")]
    if s.get("port") == 389:
        return [(389, "starttls")]
    return [(636, "ldaps"), (389, "starttls")]


def probe(settings):
    """Find a TLS path to the server and decide trust. Never sends the password. Returns (resolved, pin)."""
    last = None
    for port, mode in _tries(settings):
        s = {**settings, "port": port, "tls": mode, "pin": None}
        cc.say(f"  trying {mode} on {s['host']}:{port} ...")
        try:
            _open(s).unbind()
            cc.say("  certificate verified by this machine's CA store")
            return {"port": port, "tls": mode}, None
        except Exception as e:
            last = e
            if not cc.is_cert_error(e):
                cc.say(f"  {cc.short_error(e)}")
                continue
        fp = _open(s, probe=True)
        cc.say(f"  certificate isn't trusted here. SHA-256 fingerprint: {cc.pretty_fp(fp)}")
        if cc.yes_no("  Does that match your directory server's certificate? Pin it", False):
            return {"port": port, "tls": mode}, fp
    raise RuntimeError(f"no TLS path to the directory ({cc.short_error(last) if last else 'unreachable'}); plain LDAP is never used")


def test(s, secret):
    conn = _open(s, secret["password"])
    try:
        flavor, base = _flavor(conn), _base(s, conn)
        conn.search(base, _user_filter(flavor), attributes=["cn"], size_limit=1)
        if not any(e.get("type") == "searchResEntry" for e in conn.response or []):
            raise RuntimeError(f"bind worked but no {'AD' if flavor == 'ad' else 'LDAP'} users are visible under {base}")
    finally:
        conn.unbind()


def _flavor(conn):
    # ldap3 files supportedCapabilities under supported_features, not other
    info = conn.server.info
    if not info:
        return "openldap"
    oids = {f[0] if isinstance(f, (tuple, list)) else f for f in (info.supported_features or [])}
    oids.update(info.other.get("supportedCapabilities") or [])
    return "ad" if AD_CAPABILITY in oids else "openldap"


def _base(s, conn):
    if s.get("base_dn"):
        return s["base_dn"]
    info = conn.server.info
    found = ((info.other.get("defaultNamingContext") or [None])[0] if info else None) \
        or ((info.naming_contexts or [None])[0] if info else None)
    if not found:
        raise RuntimeError("couldn't detect the base DN; set it in CTEM")
    return found


def _user_filter(flavor):
    return "(&(objectCategory=person)(objectClass=user))" if flavor == "ad" else "(objectClass=inetOrgPerson)"


def _one(attrs, key):
    v = attrs.get(key)
    if isinstance(v, list):
        v = v[0] if v else None
    return None if v in (None, "") else v


def _text(attrs, key, cap):
    v = _one(attrs, key)
    return str(v)[:cap] if v is not None else None


def _paged(conn, base, flt, attrs):
    chunk = []
    for e in conn.extend.standard.paged_search(base, flt, attributes=attrs, paged_size=BATCH, generator=True):
        if e.get("type") != "searchResEntry":
            continue
        chunk.append(e)
        if len(chunk) >= BATCH:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def _user(e, ad):
    a = e.get("attributes", {})
    name = _text(a, "sAMAccountName" if ad else "uid", 256) or (None if ad else _text(a, "cn", 256))
    if not name or any(ord(ch) < 32 for ch in name):
        return None
    dn = e.get("dn", "")
    groups = [str(g) for g in (a.get("memberOf") or []) if len(str(g)) <= 1024][:5000] if ad else []
    uac = _int(_one(a, "userAccountControl"))
    out = {
        "username": name,
        "email": _text(a, "mail", 320),
        "display_name": _text(a, "displayName", 256) or _text(a, "cn", 256),
        "ad_dn": dn if len(dn) <= 1024 else None,
        "groups": groups,
        "disabled": bool(uac & 0x2) if ad else False,
    }
    if ad:
        out.update(_account_state(a, uac))
        # Raw values; CTEM normalizes phone numbers using the user's country
        for key, attr, cap in (("first_name", "givenName", 128), ("last_name", "sn", 128), ("title", "title", 256),
                               ("phone", "telephoneNumber", 64), ("mobile", "mobile", 64), ("country", "c", 2)):
            v = _text(a, attr, cap)
            out[key] = v if v and not any(ord(ch) < 32 for ch in v) else None
        upn = _text(a, "userPrincipalName", 256)
        out["upn"] = upn if upn and "@" in upn and not any(ord(ch) <= 32 for ch in upn) else None
    return out


def _int(v):
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


_NEVER = 0x7FFFFFFFFFFFFFFF


def _filetime(v):
    """AD timestamps arrive as datetimes or raw 100ns-since-1601 counts; 0 and max mean 'never'."""
    if isinstance(v, datetime):
        return v if v.year > 1601 and v.year < 9000 else None
    n = _int(v)
    if n <= 0 or n >= _NEVER:
        return None
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=n // 10)
    except OverflowError:
        return None


def _iso(dt):
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def _account_state(a, uac):
    """Logon, password and lockout signals for one AD user."""
    computed = _int(_one(a, "msDS-User-Account-Control-Computed"))
    expires = _filetime(_one(a, "msDS-UserPasswordExpiryTimeComputed"))
    never = bool(uac & 0x10000)
    expired = bool(computed & 0x800000) or (not never and expires is not None
                                             and expires < datetime.now(timezone.utc))
    return {
        "last_logon": _iso(_filetime(_one(a, "lastLogonTimestamp"))),
        "pwd_last_set": _iso(_filetime(_one(a, "pwdLastSet"))),
        "pwd_expires": None if never else _iso(expires),
        "pwd_expired": expired,
        "pwd_never_expires": never,
        "locked_out": bool(computed & 0x10),
    }


def _computer(e, ad):
    a = e.get("attributes", {})
    host = (_text(a, "name" if ad else "cn", 253) or "").rstrip("$")
    if not _HOST_RE.match(host):
        return None  # the server would reject the whole batch for one odd name
    dn = e.get("dn", "")
    os_name = _text(a, "operatingSystem", 128) if ad else None
    if not ad:
        for part in (_text(a, "description", 1024) or "").split(";"):
            if part.startswith("os="):
                os_name = part[3:131]
    last = _one(a, "lastLogonTimestamp") if ad else None
    return {
        "hostname": host,
        "fqdn": _text(a, "dNSHostName" if ad else "l", 512),
        "ad_dn": dn if len(dn) <= 1024 else None,
        "os": os_name,
        "last_logon": last.isoformat() if hasattr(last, "isoformat") and last.year > 1601 else None,
    }


def collect(s, secret, state):
    conn = _open(s, secret["password"])
    try:
        ad, base = _flavor(conn) == "ad", _base(s, conn)
        uattrs = ["sAMAccountName", "mail", "displayName", "cn", "memberOf", "userAccountControl",
                  "lastLogonTimestamp", "pwdLastSet", "msDS-UserPasswordExpiryTimeComputed",
                  "msDS-User-Account-Control-Computed", "givenName", "sn", "title", "telephoneNumber",
                  "mobile", "c", "userPrincipalName"] if ad \
            else ["uid", "cn", "mail", "displayName"]
        for chunk in _paged(conn, base, _user_filter("ad" if ad else "openldap"), uattrs):
            yield {"users": [u for u in (_user(e, ad) for e in chunk) if u]}
        cflt = "(objectCategory=computer)" if ad else "(objectClass=device)"
        cattrs = ["name", "dNSHostName", "operatingSystem", "lastLogonTimestamp"] if ad else ["cn", "l", "description"]
        for chunk in _paged(conn, base, cflt, cattrs):
            yield {"computers": [c for c in (_computer(e, ad) for e in chunk) if c]}
    finally:
        conn.unbind()
