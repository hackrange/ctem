"""CrowdStrike Falcon module: host inventory + new alerts, pulled from inside the network."""
import re
import time

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


def _device(d):
    did = d.get("device_id")
    return {"device_id": did if isinstance(did, str) and _ID.match(did) else None,
            "hostname": (d.get("hostname") or "")[:253] or None,
            "status": (d.get("status") or "")[:32] or None,
            "os_version": (d.get("os_version") or "")[:128] or None,
            "last_login_user": _user(d.get("last_login_user"))}


def _user(v):
    v = (v or "").strip() if isinstance(v, str) else ""
    return v[:256] if v and not any(ord(ch) < 32 for ch in v) else None


def _alert(a):
    cid = a.get("composite_id")
    if not isinstance(cid, str) or not _ALERT_ID.match(cid):
        return None
    desc = a.get("description") or a.get("display_name")
    return {"detection_id": cid, "max_severity_displayname": (a.get("severity_name") or "")[:32] or None,
            "tactic": (a.get("tactic") or "")[:128] or None, "technique": (a.get("technique") or "")[:128] or None,
            "device": {"hostname": ((a.get("device") or {}).get("hostname") or "")[:253] or None},
            "behaviors": [{"description": str(desc)[:2000]}] if desc else []}


def collect(s, secret, state):
    api = _Falcon(s, secret)
    ids = _device_ids(api)  # scroll cursors expire fast, so grab every id before shipping
    for i in range(0, len(ids), 500):
        rows = api.call("POST", "/devices/entities/devices/v2", {"ids": ids[i:i + 500]}).get("resources") or []
        yield {"devices": [_device(d) for d in rows]}
    for offset in range(0, 10000, 1000):  # the alerts query endpoint stops at 10k
        q = f"/alerts/queries/alerts/v2?limit=1000&offset={offset}&filter=status:'new'"
        found = api.call("GET", q.replace("'", "%27")).get("resources") or []
        if not found:
            return
        rows = api.call("POST", "/alerts/entities/alerts/v2", {"composite_ids": found}).get("resources") or []
        yield {"detections": [x for x in map(_alert, rows) if x]}
        if len(found) < 1000:
            return
