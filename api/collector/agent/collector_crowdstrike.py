"""CrowdStrike Falcon module: host inventory + recent alerts, pulled from inside the network."""
import re
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

import collector_common as cc

KIND = "crowdstrike"
LABEL = "CrowdStrike Falcon"
SECRETS = {"client_secret": "CrowdStrike API client secret"}  # nosec B105 - prompt label
CLOUDS = {
    "us-1": "api.crowdstrike.com",
    "us-2": "api.us-2.crowdstrike.com",
    "eu-1": "api.eu-1.crowdstrike.com",
    "us-gov-1": "api.laggar.gcw.crowdstrike.com",
}
_ID = re.compile(r"^[0-9a-fA-F]{32}$")
_ALERT_ID = re.compile(r"^[A-Za-z0-9:_.-]{1,200}$")
_TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_TACTIC = re.compile(r"^TA\d{4}$")
_LINK = re.compile(r"^https://falcon(?:\.[a-z0-9-]+)*\.crowdstrike\.com/[^\s\"'<>]*$")
ALERT_DAYS = 30


class _Falcon:
    def __init__(self, s, secret):
        self.base = f"https://{CLOUDS[s['cloud']]}"
        self.client_id, self.secret, self.cafile = s["client_id"], secret, s.get("ca_file")
        self.token, self.born = None, 0.0

    def _login(self):
        data = cc.url_json("POST", f"{self.base}/oauth2/token", cafile=self.cafile,
                           form={"client_id": self.client_id, "client_secret": self.secret["client_secret"]})
        self.token, self.born = data["access_token"], time.time()

    def call(self, method, path, body=None):
        if not self.token or time.time() - self.born > 25 * 60:  # tokens live 30 minutes
            self._login()
        for attempt in range(4):
            try:
                return cc.url_json(method, f"{self.base}{path}", body=body, cafile=self.cafile,
                                   headers={"Authorization": f"Bearer {self.token}"}) or {}
            except cc.HttpError as e:
                if e.status == 401 and attempt == 0:
                    self._login()
                elif e.status == 429 or e.status >= 500:
                    time.sleep(2 ** (attempt + 1))
                else:
                    raise
        raise RuntimeError(f"Falcon API kept failing on {path}")


def test(s, secret):
    _Falcon(s, secret).call("GET", "/devices/queries/devices/v1?limit=1")


def ask_settings():
    cc.say(f"\n== {LABEL} ==")
    cc.say("  needs an API client with Hosts: Read and Alerts: Read scopes")
    cc.say("  (Firewall management: Read and Device control policies: Read add the firewall / USB columns)")
    cloud = cc.ask(f"Falcon cloud ({', '.join(CLOUDS)})", default="us-1",
                   validate=lambda v: None if v in CLOUDS else "pick one of the listed clouds")
    cid = cc.ask("API client ID", validate=lambda v: None if _ID.match(v) else "client IDs are 32 hex chars")
    return {"cloud": cloud, "client_id": cid}


def probe(settings):
    # Public cloud API with a public CA; nothing to pin, just make sure it's a cloud we know
    if settings.get("cloud") not in CLOUDS:
        raise RuntimeError("unknown Falcon cloud")
    cc.say(f"  CrowdStrike: {CLOUDS[settings['cloud']]} (verified against the public CA store)")
    return {}, None


def _device_ids(api):
    ids, offset = [], ""
    while len(ids) < 2_000_000:
        q = f"/devices/queries/devices-scroll/v1?limit=5000{f'&offset={offset}' if offset else ''}"
        data = api.call("GET", q)
        batch = data.get("resources") or []
        ids.extend(batch)
        offset = ((data.get("meta") or {}).get("pagination") or {}).get("offset") or ""
        if not batch or not offset:
            return ids
    return ids


class _Policies:
    """Falcon firewall and device-control policies, fetched once per run and cached by id."""

    def __init__(self, api):
        self.api, self.fw, self.usb, self.denied = api, {}, {}, set()

    def _fetch(self, path, ids, into, kind):
        todo = [i for i in ids if i not in into]
        for i in range(0, len(todo), 100):
            q = "&".join(f"ids={x}" for x in todo[i:i + 100])
            try:
                rows = self.api.call("GET", f"{path}?{q}").get("resources") or []
            except cc.HttpError as e:
                if e.status in (401, 403, 404):
                    if kind not in self.denied:
                        why = "isn't available on this cloud" if e.status == 404 else "needs read access"
                        cc.say(f"  CrowdStrike: {kind} policy API {why}; that column stays blank")
                    self.denied.add(kind)
                    for x in todo:
                        into[x] = None
                    return
                raise
            for r in rows:
                rid = str(r.get("id") or r.get("policy_id") or "") if isinstance(r, dict) else ""
                if _ID.match(rid):  # fwmgr calls it policy_id, the policy API calls it id
                    into[rid] = r
            for x in todo[i:i + 100]:
                into.setdefault(x, None)

    def load(self, rows):
        fw_ids, usb_ids = set(), set()
        for d in rows:
            fw_ids.add(_policy_id(d, "firewall"))
            usb_ids.add(_policy_id(d, "device_control"))
        self._fetch("/policy/entities/firewall/v1", sorted(i for i in fw_ids if i), self.fw, "firewall")
        enforce = {}
        if "firewall" not in self.denied:
            self._fetch("/fwmgr/entities/policies/v1", sorted(i for i in fw_ids if i), enforce, "firewall rule")
        for pid, pol in self.fw.items():
            if isinstance(pol, dict) and pid in enforce and isinstance(enforce[pid], dict):
                pol["_enforce"] = enforce[pid].get("enforce")
        self._fetch("/policy/entities/device-control/v1", sorted(i for i in usb_ids if i), self.usb, "device control")

    def firewall_on(self, d):
        pid = _policy_id(d, "firewall")
        if pid is None:
            return False  # no Falcon firewall policy applied to this host
        pol = self.fw.get(pid)
        if not isinstance(pol, dict):
            return None  # couldn't read the policy
        if not pol.get("enabled"):
            return False
        return pol.get("_enforce") if isinstance(pol.get("_enforce"), bool) else None

    def usb_blocked(self, d):
        pid = _policy_id(d, "device_control")
        if pid is None:
            return False
        pol = self.usb.get(pid)
        if not isinstance(pol, dict):
            return None
        st = pol.get("settings") or {}
        if not pol.get("enabled") or st.get("enforcement_mode") != "MONITOR_ENFORCE":
            return False
        mass = next((c for c in st.get("classes") or [] if isinstance(c, dict) and c.get("id") == "MASS_STORAGE"), {})
        return mass.get("action") == "BLOCK_ALL"


class _Logins:
    """Recent sign-ins per host, so a kiosk or password-reset account signing in last doesn't hide the owner."""
    PATHS = ("/devices/combined/devices/login-history/v2", "/devices/combined/devices/login-history/v1")
    KEEP = 10

    def __init__(self, api):
        self.api, self.off, self.paths = api, False, list(self.PATHS)

    def _call(self, ids):
        while self.paths:
            try:
                return self.api.call("POST", self.paths[0], {"ids": ids}).get("resources") or []
            except cc.HttpError as e:
                if e.status == 404:  # older clouds only have v1
                    self.paths.pop(0)
                    continue
                if e.status in (401, 403):
                    cc.say("  CrowdStrike: no access to login history; using the last sign-in only")
                    self.off = True
                    return []
                raise
        self.off = True
        return []

    def load(self, rows):
        out = {}
        ids = [d["device_id"] for d in rows if isinstance(d.get("device_id"), str) and _ID.match(d["device_id"])]
        for i in range(0, len(ids), 100):
            if self.off:
                break
            for r in self._call(ids[i:i + 100]):
                if isinstance(r, dict) and isinstance(r.get("device_id"), str):
                    out[r["device_id"]] = _recent(r.get("recent_logins"), self.KEEP)
        return out


def _recent(logins, keep):
    """Newest first, one entry per name."""
    rows = [x for x in (logins or []) if isinstance(x, dict)]
    rows.sort(key=lambda x: str(x.get("login_time") or ""), reverse=True)
    names, seen = [], set()
    for x in rows:
        n = _user(x.get("user_name"))
        if n and n.lower() not in seen:
            seen.add(n.lower())
            names.append(n)
        if len(names) == keep:
            break
    return names


def _policy_id(d, name):
    p = ((d.get("device_policies") or {}).get(name) or {})
    pid = p.get("policy_id")
    return pid if p.get("applied") and isinstance(pid, str) and _ID.match(pid) else None


def _device(d, policies=None, logins=None):
    did = d.get("device_id")
    return {"device_id": did if isinstance(did, str) and _ID.match(did) else None,
            "hostname": (d.get("hostname") or "")[:253] or None,
            "status": (d.get("status") or "")[:32] or None,
            "os_version": (d.get("os_version") or "")[:128] or None,
            "last_login_user": _user(d.get("last_login_user")),
            "product_type": (d.get("product_type_desc") or "")[:64] or None,
            "firewall_enabled": policies.firewall_on(d) if policies else None,
            "usb_storage_blocked": policies.usb_blocked(d) if policies else None,
            "recent_logins": (logins or {}).get(d.get("device_id")) or None}


def _user(v):
    v = (v or "").strip() if isinstance(v, str) else ""
    return v[:256] if v and not any(ord(ch) < 32 for ch in v) else None


def _txt(v, cap):
    v = v.strip() if isinstance(v, str) else ""
    return v[:cap] if v and not any(ord(ch) < 32 for ch in v) else None


def _match(rx, v):
    v = _txt(v, 1000)
    return v if v and rx.match(v) else None


def _alert(a):
    cid = a.get("composite_id")
    if not isinstance(cid, str) or not _ALERT_ID.match(cid):
        return None
    desc = a.get("description") or a.get("display_name")
    dev = a.get("device") if isinstance(a.get("device"), dict) else {}
    did = dev.get("device_id")
    return {"detection_id": cid, "max_severity_displayname": (a.get("severity_name") or "")[:32] or None,
            "title": _txt(a.get("display_name") or a.get("name"), 300),
            "status": _txt(a.get("status"), 32),
            "detected_at": _txt(a.get("created_timestamp") or a.get("timestamp"), 40),
            "tactic": (a.get("tactic") or "")[:128] or None, "technique": (a.get("technique") or "")[:128] or None,
            "tactic_id": _match(_TACTIC, a.get("tactic_id")), "technique_id": _match(_TECH, a.get("technique_id")),
            "link": _match(_LINK, a.get("falcon_host_link")),
            "device": {"hostname": (dev.get("hostname") or "")[:253] or None,
                       "device_id": did if isinstance(did, str) and _ID.match(did) else None},
            "behaviors": [{"description": str(desc)[:2000]}] if desc else []}


def _alert_query(offset, now=None):
    """Every alert from the last ALERT_DAYS days in any status, newest first, so status changes come through."""
    since = ((now or datetime.now(timezone.utc)) - timedelta(days=ALERT_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return "/alerts/queries/alerts/v2?" + urllib.parse.urlencode(
        {"limit": 1000, "offset": offset, "sort": "created_timestamp.desc", "filter": f"created_timestamp:>'{since}'"})


def collect(s, secret, state):
    api = _Falcon(s, secret)
    policies, history = _Policies(api), _Logins(api)
    ids = _device_ids(api)  # scroll cursors expire fast, so grab every id before shipping
    for i in range(0, len(ids), 500):
        rows = api.call("POST", "/devices/entities/devices/v2", {"ids": ids[i:i + 500]}).get("resources") or []
        policies.load(rows)
        logins = history.load(rows)
        yield {"devices": [_device(d, policies, logins) for d in rows]}
    for offset in range(0, 10000, 1000):  # the alerts query endpoint stops at 10k
        found = api.call("GET", _alert_query(offset)).get("resources") or []
        if not found:
            return
        rows = api.call("POST", "/alerts/entities/alerts/v2", {"composite_ids": found}).get("resources") or []
        yield {"detections": [x for x in map(_alert, rows) if x]}
        if len(found) < 1000:
            return
