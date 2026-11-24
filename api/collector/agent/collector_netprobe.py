"""Network discovery: is a host up, and is anything listening on the common ports? A ping and a plain TCP connect
per port (opened and closed at once: no data sent, nothing read), fast and in parallel.

CTEM sends the targets: addresses its tools know that nothing manages (only a pentest or a cloud inventory saw them),
and the internal /24s they sit in, minus the managed hosts there, so unknown devices turn up. The box decides what
may be touched: internal address space only (RFC 1918), minus the exclusions approved here with
`open-ctem-collector approve`. A target outside that is skipped, whatever CTEM sends."""
import errno
import ipaddress
import selectors
import shutil
import socket
import subprocess  # nosec B404 - the system ping, fixed arguments, no shell
import time
from concurrent.futures import ThreadPoolExecutor

import collector_common as cc

KIND = "netprobe"
LABEL = "Network discovery (ping and common ports)"
SECRETS = {}   # nothing to log in to
INTERNAL = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))  # nosec - the box's own scope guard
COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985,
                6379, 8080, 8443, 9200)
MAX_PORTS, BATCH = 40, 500


def ports_of(s):
    raw = str(s.get("ports") or "").replace(" ", "")
    out = []
    for p in raw.split(",") if raw else []:
        if p.isdigit() and 0 < int(p) < 65536 and int(p) not in out:
            out.append(int(p))
    return tuple(out[:MAX_PORTS]) or COMMON_PORTS


def exclusions(s):
    out = []
    for c in str(s.get("exclude_cidrs") or "").replace(";", ",").split(","):
        c = c.strip()
        if c:
            try:
                out.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                raise ValueError(f"exclusion {c!r} isn't a network (a CIDR such as 192.0.2.0/24)") from None
    return out


def allowed(ip, excluded):
    """Internal and not excluded: the only addresses this box will ever probe."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and any(a in n for n in INTERNAL) and not any(a in n for n in excluded)


def targets(s, excluded, cap):
    """Each host CTEM named, then every address of each /24 to sweep (less the managed ones), all within scope."""
    t = s.get("targets") or {}
    skip = set(t.get("skip") or [])
    out, seen = [], set()

    def add(ip):
        if ip not in seen and ip not in skip and allowed(ip, excluded):
            seen.add(ip)
            out.append(ip)
    for ip in t.get("hosts") or []:
        add(str(ip))
    if str(s.get("sweep_subnets") or "on") == "on":
        for net in t.get("sweep") or []:
            try:
                n = ipaddress.ip_network(str(net), strict=False)
            except ValueError:
                continue
            if n.prefixlen < 24:   # never more than a /24 per entry
                continue
            for a in n.hosts():
                add(str(a))
    return out[:cap]


def _ping(ip, timeout_ms):
    exe = shutil.which("ping")
    if not exe:
        return False
    wait = str(max(1, round(timeout_ms / 1000)))
    try:
        return subprocess.run([exe, "-c", "1", "-W", wait, "-n", "-q", ip], stdout=subprocess.DEVNULL,  # nosec B603
                              stderr=subprocess.DEVNULL, timeout=timeout_ms / 1000 + 2, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def listening(ip, ports, timeout_ms):
    """Every port at once, non-blocking: a silent host costs one timeout, not one per port. Connect, then close."""
    sel, socks, out = selectors.DefaultSelector(), {}, []
    try:
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            rc = s.connect_ex((ip, p))
            if rc in (0, errno.EINPROGRESS, errno.EWOULDBLOCK):
                socks[s] = p
                sel.register(s, selectors.EVENT_WRITE)
            else:
                s.close()
        deadline = time.monotonic() + timeout_ms / 1000
        while socks and time.monotonic() < deadline:
            for key, _ in sel.select(timeout=max(0.0, deadline - time.monotonic())):
                s = key.fileobj
                if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                    out.append(socks[s])
                sel.unregister(s)
                s.close()
                socks.pop(s, None)
    finally:
        for s in socks:
            s.close()
        sel.close()
    return sorted(out)


def probe_host(ip, ports, timeout_ms):
    up = _ping(ip, timeout_ms)
    listening_ports = listening(ip, ports, timeout_ms)
    return {"ip": ip, "alive": bool(up or listening_ports), "icmp": up, "ports": listening_ports,
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def scope_text(s):
    """What approving this lets the box touch, in words."""
    ex = ", ".join(str(n) for n in exclusions(s)) or "none"
    sweep = "and the /24s around them" if str(s.get("sweep_subnets") or "on") == "on" else "only (no /24 sweep)"
    return (f"internal addresses only ({', '.join(str(n) for n in INTERNAL)}), never: {ex}; addresses CTEM names {sweep}; "
            f"ping and TCP ports {','.join(map(str, ports_of(s)))}")


def probe(settings):
    """Approve-time check: nothing to connect to, so show exactly what the box would be allowed to touch."""
    cc.say(f"  network discovery may touch {scope_text(settings)}")
    return {}, None


def collect(s, secret, state):
    excluded = exclusions(s)
    ports = ports_of(s)
    timeout_ms = min(max(int(s.get("timeout_ms") or 600), 100), 3000)
    workers = min(max(int(s.get("concurrency") or 32), 4), 64)
    workers = max(1, min(workers, 900 // len(ports)))   # each host holds a socket per port: stay under 1024 open files
    cap = min(max(int(s.get("max_hosts") or 4096), 1), 20000)
    every = targets(s, excluded, 20000)
    # Each run picks up where the last stopped, so a list longer than the cap is covered over a few runs
    start = int(state.get("netprobe_next") or 0) % max(len(every), 1)
    todo = (every[start:] + every[:start])[:cap]
    state["netprobe_next"] = start + len(todo)
    cc.say(f"  netprobe: {len(todo)} addresses, {len(ports)} ports each, {workers} at a time")
    known = set((s.get("targets") or {}).get("hosts") or [])
    batch, up = [], 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for r in pool.map(lambda ip: probe_host(ip, ports, timeout_ms), todo):
            if r["alive"]:
                up += 1
            if r["alive"] or r["ip"] in known:   # a swept address that didn't answer isn't worth sending
                batch.append(r)
            if len(batch) >= BATCH:
                yield {"probes": batch}
                batch = []
    if batch:
        yield {"probes": batch}
    cc.say(f"  netprobe: {up} of {len(todo)} answered")


def test(s, secret):
    exclusions(s)
    if not _ping("127.0.0.1", 1000):  # nosec - loopback self-test of ping
        cc.say("  netprobe: ping isn't allowed here (no ping, or no ICMP for this user), so only the TCP ports are tried")
