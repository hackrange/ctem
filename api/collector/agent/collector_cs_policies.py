"""Falcon policies for the CrowdStrike source: firewall, device control (USB) and prevention, fetched once per run.

Each policy API is optional. A tenant without the module or an API client without the scope gets a note for CTEM's
integration card (which scope to add), and that part stays blank; the rest of the run carries on."""
import re

import collector_common as cc

_ID = re.compile(r"^[0-9a-fA-F]{32}$")
SCOPE = {"firewall": "Firewall management: Read", "firewall rule": "Firewall management: Read",
         "firewall rules": "Firewall management: Read",
         "device control": "Device control policies: Read", "prevention": "Prevention policies: Read"}
MAX_SETTINGS = 120


def policy_id(d, name):
    p = ((d.get("device_policies") or {}).get(name) or {})
    pid = p.get("policy_id")
    return pid if p.get("applied") and isinstance(pid, str) and _ID.match(pid) else None


def _txt(v, cap):
    v = v.strip() if isinstance(v, str) else ""
    return v[:cap] if v and not any(ord(ch) < 32 for ch in v) else None


def _value(v):
    """A Falcon setting's value, flattened: a toggle is True/False, an ML slider its prevention level."""
    if isinstance(v, dict):
        if isinstance(v.get("enabled"), bool):
            return v["enabled"]
        if isinstance(v.get("prevention"), str):
            return v["prevention"][:24]
        if isinstance(v.get("detection"), str):
            return f"detect:{v['detection'][:16]}"
    return v if isinstance(v, bool) else None


def prevention_summary(pol):
    """{id, name, enabled, platform, settings: {setting id: {name, category, value}}} for CTEM to judge."""
    out = {}
    for cat in pol.get("prevention_settings") or []:
        cname = _txt(cat.get("name"), 64) if isinstance(cat, dict) else None
        for st in (cat.get("settings") or []) if isinstance(cat, dict) else []:
            sid = _txt(st.get("id"), 64) if isinstance(st, dict) else None
            val = _value(st.get("value")) if sid else None
            if sid and val is not None and len(out) < MAX_SETTINGS and re.match(r"^[A-Za-z0-9_.-]+$", sid):
                out[sid] = {"name": _txt(st.get("name"), 96) or sid, "category": cname, "value": val}
    return {"id": pol.get("id"), "kind": "prevention", "name": _txt(pol.get("name"), 128),
            "enabled": bool(pol.get("enabled")), "platform": _txt(pol.get("platform_name"), 32), "settings": out}


MAX_RULES = 2000


def _ports(v):
    out = []
    for p in v or []:
        if isinstance(p, dict) and isinstance(p.get("start"), int):
            a, b = p["start"], p.get("end") if isinstance(p.get("end"), int) and p.get("end") else p["start"]
            if 0 <= a <= 65535 and 0 <= b <= 65535:
                out.append([a, b])
    return out[:50]


def _addrs(v):
    out = []
    for a in v or []:
        if isinstance(a, dict) and isinstance(a.get("address"), str) and re.match(r"^[0-9a-fA-F:.*]{1,45}$", a["address"]):
            mask = a.get("netmask")
            out.append(f"{a['address']}/{mask}" if isinstance(mask, int) and a["address"] != "*" else a["address"])
    return out[:50]


_FQDN = re.compile(r"^[A-Za-z0-9*][A-Za-z0-9*._-]{0,252}$")


def _fqdns(r):
    """The rule's domain names (Falcon keeps them as one ";"-separated string), when the rule matches on them."""
    if r.get("fqdn_enabled") is False or not isinstance(r.get("fqdn"), str):
        return []
    return [n for n in (p.strip() for p in re.split(r"[;,\s]+", r["fqdn"])) if n and _FQDN.match(n)][:50]


def _program(r):
    """The executable a rule is limited to (Falcon's "image_name" field), if any."""
    for f in r.get("fields") or []:
        if isinstance(f, dict) and f.get("name") == "image_name":
            v = f.get("value") or next((x for x in f.get("values") or [] if isinstance(x, str) and x), None)
            if isinstance(v, str) and v.strip():
                return _txt(v.strip(), 260)
    return None


def rule_summary(r):
    """One Falcon firewall rule as a plain ruleset row."""
    proto = str(r.get("protocol") or "*")
    return {"name": _txt(r.get("name"), 128), "description": _txt(r.get("description"), 256),
            "enabled": bool(r.get("enabled")), "action": str(r.get("action") or "").upper()[:8] or None,
            "direction": str(r.get("direction") or "").upper()[:8] or None,
            "protocol": {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPv6", "*": "Any"}.get(proto, proto[:8]),
            "local_address": _addrs(r.get("local_address")), "remote_address": _addrs(r.get("remote_address")),
            "local_port": _ports(r.get("local_port")), "remote_port": _ports(r.get("remote_port")),
            "fqdn": _fqdns(r), "program": _program(r),
            # Falcon's "monitoring" logs matches (count as text, "0" when off); the rule still acts
            "logged": str((r.get("monitor") or {}).get("count") or "0").strip() not in ("", "0") if isinstance(r.get("monitor"), dict) else False}


def _hex(v, n=4):
    v = str(v or "").strip().lower().removeprefix("0x")
    return v[:n] if re.match(r"^[0-9a-f]{1,8}$", v) else None


# Device control actions that keep a USB storage device from being used, in v1 (FULL_BLOCK) and v2 (BLOCK_ALL, or
# WHITELIST: only the allowed devices). READ_ONLY, BLOCK_EXECUTE and BLOCK_WRITE_EXECUTE are partial, kept as they are.
BLOCKED = {"FULL_BLOCK", "BLOCK_ALL", "WHITELIST"}


def usb_settings(pol):
    """v1 keeps the USB settings under "settings", v2 under "usb_settings"."""
    st = pol.get("usb_settings") if isinstance(pol.get("usb_settings"), dict) else pol.get("settings")
    return st if isinstance(st, dict) else {}


def class_name(c):
    """v1 names the class in "id" (MASS_STORAGE); v2 has its own id and names the class in "class"."""
    return _txt(c.get("class"), 48) or _txt(c.get("id"), 48)


def usb_summary(pid, pol):
    """The device control policy as CTEM shows it: what each device class may do, and the devices allowed anyway."""
    st = usb_settings(pol)
    classes = []
    for c in st.get("classes") or []:
        if not isinstance(c, dict) or not class_name(c):
            continue
        allowed = []
        for e in (c.get("exceptions") or [])[:500]:
            if not isinstance(e, dict):
                continue
            allowed.append({"vendor_id": _hex(e.get("vendor_id")), "vendor": _txt(e.get("vendor_name"), 128),
                            "match": _txt(e.get("match_method"), 32),
                            "product_id": _hex(e.get("product_id")), "product": _txt(e.get("product_name"), 128),
                            "serial": _txt(e.get("serial_number"), 128), "action": _txt(e.get("action"), 32),
                            "description": _txt(e.get("description"), 256), "expires": _txt(e.get("expiration_time"), 40)})
        classes.append({"id": class_name(c), "action": _txt(c.get("action"), 32), "allowed": allowed})
    return {"id": pid, "kind": "device_control", "name": _txt(pol.get("name"), 128), "enabled": bool(pol.get("enabled")),
            "platform": _txt(pol.get("platform_name"), 32), "enforcement": _txt(st.get("enforcement_mode"), 32),
            "classes": classes[:40]}


class Policies:
    def __init__(self, api):
        self.api, self.fw, self.usb, self.prev, self.denied, self.notes = api, {}, {}, {}, set(), []
        self.sent = set()   # prevention policies already sent this run

    def _fetch(self, paths, ids, into, kind):
        """Fetch policies by id from the first of `paths` the tenant answers (a newer API version, then older)."""
        todo = [i for i in ids if i not in into]
        for i in range(0, len(todo), 100):
            q = "&".join(f"ids={x}" for x in todo[i:i + 100])
            rows = None
            for path in paths:
                try:
                    rows = self.api.call("GET", f"{path}?{q}").get("resources") or []
                    break
                except cc.HttpError as e:
                    if e.status == 404 and path != paths[-1]:
                        continue   # this version isn't on this cloud: try the older one
                    if 400 <= e.status < 500 and e.status != 429:   # an extra: never worth failing the whole pull
                        self._deny(kind, e.status)
                        for x in todo:
                            into[x] = None
                        return
                    raise
            for r in rows or []:
                rid = str(r.get("id") or r.get("policy_id") or "") if isinstance(r, dict) else ""
                if _ID.match(rid):  # fwmgr calls it policy_id, the policy API calls it id
                    into[rid] = r
            for x in todo[i:i + 100]:
                into.setdefault(x, None)

    def _deny(self, kind, status):
        if kind in self.denied:
            return
        self.denied.add(kind)
        why = {404: "isn't available on this tenant", 401: "needs read access", 403: "needs read access"}.get(status, "refused")
        cc.say(f"  CrowdStrike: {kind} policy API {why}; that part stays blank")
        self.notes.append(f"Falcon refused the {kind} policy API (HTTP {status}), so that part stays blank; "
                          f"if the module is licensed, give the API client the {SCOPE.get(kind, 'matching')} scope")

    def load(self, rows):
        fw_ids, usb_ids, prev_ids = set(), set(), set()
        for d in rows:
            fw_ids.add(policy_id(d, "firewall"))
            usb_ids.add(policy_id(d, "device_control"))
            prev_ids.add(policy_id(d, "prevention"))
        self._fetch(("/policy/entities/firewall/v1",), sorted(i for i in fw_ids if i), self.fw, "firewall")
        enforce = {}
        if "firewall" not in self.denied:
            self._fetch(("/fwmgr/entities/policies/v1",), sorted(i for i in fw_ids if i), enforce, "firewall rule")
        for pid, pol in self.fw.items():
            if isinstance(pol, dict) and pid in enforce and isinstance(enforce[pid], dict):
                pol["_enforce"] = enforce[pid].get("enforce")
                pol["_container"] = enforce[pid]
        self._fetch(("/policy/entities/device-control/v2", "/policy/entities/device-control/v1"),
                    sorted(i for i in usb_ids if i), self.usb, "device control")
        self._fetch(("/policy/entities/prevention/v1",), sorted(i for i in prev_ids if i), self.prev, "prevention")

    def new_policies(self):
        """Prevention policies and firewall rulesets not sent yet this run, summarized for CTEM."""
        out = []
        for pid, pol in self.prev.items():
            if isinstance(pol, dict) and ("p", pid) not in self.sent:
                self.sent.add(("p", pid))
                out.append(prevention_summary(pol))
        for pid, pol in self.fw.items():
            if isinstance(pol, dict) and ("f", pid) not in self.sent and isinstance(pol.get("_container"), dict):
                self.sent.add(("f", pid))
                out.append(self._ruleset(pid, pol))
        for pid, pol in self.usb.items():
            if isinstance(pol, dict) and ("u", pid) not in self.sent:
                self.sent.add(("u", pid))
                out.append(usb_summary(pid, pol))
        return out

    def _ruleset(self, pid, pol):
        """The firewall policy as a ruleset: its rule groups in order, each group's rules in order, then the defaults."""
        c = pol["_container"]
        rules = []
        if "firewall rules" not in self.denied:
            groups = {}
            self._fetch(("/fwmgr/entities/rule-groups/v1",), [g for g in c.get("rule_group_ids") or [] if isinstance(g, str)],
                        groups, "firewall rules")
            for gid in c.get("rule_group_ids") or []:
                g = groups.get(gid)
                if not isinstance(g, dict) or not g.get("enabled", True):
                    continue
                ids = [str(i) for i in g.get("rule_ids") or []][:MAX_RULES]
                found = {}
                for i in range(0, len(ids), 100):
                    try:
                        q = "&".join(f"ids={x}" for x in ids[i:i + 100])
                        for r in self.api.call("GET", f"/fwmgr/entities/rules/v1?{q}").get("resources") or []:
                            if isinstance(r, dict):   # a group may list a rule by its id or its family id
                                for k in {str(r.get("id") or ""), str(r.get("family") or "")} - {""}:
                                    found[k] = r
                    except cc.HttpError as e:
                        if 400 <= e.status < 500 and e.status != 429:
                            self._deny("firewall rules", e.status)
                            break
                        raise
                rules += [rule_summary(found[x]) for x in ids if x in found]
        return {"id": pid, "kind": "firewall", "name": _txt(pol.get("name"), 128), "enabled": bool(pol.get("enabled")),
                "platform": _txt(pol.get("platform_name"), 32), "enforce": bool(c.get("enforce")),
                "test_mode": bool(c.get("test_mode")), "default_inbound": str(c.get("default_inbound") or "")[:8] or None,
                "default_outbound": str(c.get("default_outbound") or "")[:8] or None, "rules": rules[:MAX_RULES]}

    def usb_of(self, d):
        pid = policy_id(d, "device_control")
        return pid if pid and isinstance(self.usb.get(pid), dict) else None

    def firewall_of(self, d):
        pid = policy_id(d, "firewall")
        return pid if pid and isinstance(self.fw.get(pid), dict) else None

    def prevention_of(self, d):
        pid = policy_id(d, "prevention")
        return pid if pid and isinstance(self.prev.get(pid), dict) else None

    def firewall_on(self, d):
        pid = policy_id(d, "firewall")
        if pid is None:
            return False  # no Falcon firewall policy applied to this host
        pol = self.fw.get(pid)
        if not isinstance(pol, dict):
            return None  # couldn't read the policy
        if not pol.get("enabled"):
            return False
        return pol.get("_enforce") if isinstance(pol.get("_enforce"), bool) else None

    def usb_blocked(self, d):
        pid = policy_id(d, "device_control")
        if pid is None:
            return False
        pol = self.usb.get(pid)
        if not isinstance(pol, dict):
            return None
        st = usb_settings(pol)
        if not pol.get("enabled") or st.get("enforcement_mode") != "MONITOR_ENFORCE":
            return False
        mass = next((c for c in st.get("classes") or [] if isinstance(c, dict) and class_name(c) == "MASS_STORAGE"), None)
        if mass is None:
            return None   # the policy doesn't say what happens to USB storage
        return str(mass.get("action") or "").upper() in BLOCKED


POSTURE_HOURS = 6   # Zero Trust Assessment changes slowly and is large: every few hours is plenty


class Posture:
    """Falcon Zero Trust Assessment per host: its scores and every signal it checked (OS and sensor settings, which
    can include disk encryption such as BitLocker). Optional: no license or scope means a note and nothing else."""

    def __init__(self, api, state, host_key):
        import time
        self.api, self.key, self.off, self.note = api, f"cs_posture_at:{host_key}", False, None
        self.due = time.time() - float(state.get(self.key, 0)) >= POSTURE_HOURS * 3600

    def load(self, aids):
        if not self.due or self.off:
            return {}
        out = {}
        for i in range(0, len(aids), 100):
            q = "&".join(f"ids={x}" for x in aids[i:i + 100] if _ID.match(str(x)))
            try:
                rows = self.api.call("GET", f"/zero-trust-assessment/entities/assessments/v1?{q}").get("resources") or []
            except cc.HttpError as e:
                if e.status == 404 and i:
                    continue   # no assessment for these hosts yet
                if 400 <= e.status < 500 and e.status != 429:
                    self.off = True
                    cc.say(f"  CrowdStrike: Zero Trust Assessment refused (HTTP {e.status}); posture is skipped")
                    self.note = (f"Falcon refused Zero Trust Assessment (HTTP {e.status}), so host posture (including disk "
                                 "encryption checks) is skipped; if it's licensed, give the API client the Zero Trust Assessment: Read scope")
                    return out
                raise
            for r in rows:
                if isinstance(r, dict) and _ID.match(str(r.get("aid") or "")):
                    out[r["aid"]] = posture_summary(r)
        return out

    def done(self, state):
        import time
        if self.due and not self.off:
            state[self.key] = time.time()


def posture_summary(r):
    a = r.get("assessment") or {}
    score = lambda k: a.get(k) if isinstance(a.get(k), int) and 0 <= a.get(k) <= 100 else None  # noqa: E731
    signals = []
    items = r.get("assessment_items") or {}
    for kind in ("os_signals", "sensor_signals"):
        for sg in items.get(kind) or []:
            if isinstance(sg, dict) and _txt(sg.get("signal_name"), 128):
                signals.append({"kind": "os" if kind == "os_signals" else "sensor", "name": _txt(sg.get("signal_name"), 128),
                                "group": _txt(sg.get("group_name"), 64), "criteria": _txt(sg.get("criteria"), 256),
                                "meets": _txt(sg.get("meets_criteria"), 16)})
    return {"overall": score("overall"), "os": score("os"), "sensor_config": score("sensor_config"),
            "at": _txt(r.get("modified_time"), 40), "signals": signals[:120]}
