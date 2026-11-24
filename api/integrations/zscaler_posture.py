"""What Zscaler's configuration and agents say about risk (read by api/integrations/zscaler.py, GET only):

  coverage     workstations CTEM knows (seen by an EDR or scanner in the last 30 days) with no registered Zscaler Client
               Connector, or whose registered one hasn't checked in for 14 days
  URL policy   enabled rules that ALLOW security-risk categories (anonymizers, newly registered domains, hacking, P2P,
               malware or phishing)
  SSL policy   enabled rules that skip inspection broadly (any category, everyone)
  firewall     enabled ALLOW rules with no destination, service, application or source limit (any to any)
  DLP          DLP rules that are off or only allow (monitor)
  admins       enabled ZIA admins with password sign-in instead of SSO, and how many have super admin

Each is a posture finding (source zscaler) naming the rules or devices; findings no longer true are marked resolved."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

SOURCE = "zscaler"
STALE_DAYS, SEEN_DAYS = 14, 30
RISKY_CATEGORIES = ("anonym", "newly_reg", "newly reg", "hacking", "p2p", "peer", "malware", "malicious", "phish", "spyware",
                    "botnet", "cryptomin", "suspicious")
FW_LIMITS = ("destAddresses", "destIpCategories", "destIpGroups", "destCountries", "destIpv6Groups", "nwServices",
             "nwServiceGroups", "nwApplications", "nwApplicationGroups", "appServices", "srcIps", "srcIpGroups", "srcIpv6Groups",
             "locations", "locationGroups", "users", "groups", "departments", "devices", "deviceGroups")
SUPER_ADMINS_OK = 5


def _aware(d: datetime | None) -> datetime | None:
    return d.replace(tzinfo=timezone.utc) if d is not None and d.tzinfo is None else d


def _when(v) -> datetime | None:
    if v in (None, "", 0):
        return None
    try:
        if isinstance(v, (int, float)) or str(v).isdigit():
            n = float(v)
            return datetime.fromtimestamp(n / 1000 if n > 1e11 else n, tz=timezone.utc)
        return datetime.fromisoformat(str(v).replace("Z", "+00:00").replace(" ", "T"))
    except (ValueError, OSError):
        return None


async def devices(conn, db: AsyncSession) -> int:
    """Client Connector inventory into zscaler_devices, matched to CTEM devices; ZDX presence; coverage findings."""
    from api.core.device_match import find_devices, host_key
    from api.models.zscaler import ZscalerDevice
    rows, page = [], 1
    while page <= 40:   # 100 calls an hour for the whole Client Connector API: large pages, few calls
        got = await conn.get("/zcc/papi/public/v1/getDevices", {"page": page, "pageSize": 5000})
        if not got:
            break
        rows += [d for d in got if isinstance(d, dict)]
        if len(got) < 5000:
            break
        page += 1
    zdx = set()
    offset = None
    for _ in range(50):
        params = {"limit": 1000, **({"offset": offset} if offset else {})}
        got = await conn.get("/zdx/v1/devices", params)
        if not isinstance(got, dict):
            break
        # ZDX names a device "HOSTNAME(make model OS ...)": the host is the part before the bracket
        zdx |= {host_key(str(d.get("name") or "").split("(", 1)[0].strip()) for d in got.get("devices") or [] if isinstance(d, dict)} - {None}
        offset = got.get("next_offset")
        if not offset:
            break
    latest: dict[str, dict] = {}   # the inventory can list a device more than once: keep the copy seen last
    for d in rows:
        u = str(d.get("udid") or "")[:128]
        if u and (u not in latest or str(d.get("last_seen_time") or "") > str(latest[u].get("last_seen_time") or "")):
            latest[u] = d
    rows = list(latest.values())
    names = [d.get("machineHostname") for d in rows if d.get("machineHostname")]
    found = await find_devices(db, names) if names else {}
    have = {z.udid: z for z in (await db.execute(select(ZscalerDevice))).scalars()}
    seen = set()
    for d in rows:
        udid = str(d.get("udid") or "")[:128]
        if not udid:
            continue
        seen.add(udid)
        z = have.get(udid) or ZscalerDevice(udid=udid)
        name = str(d.get("machineHostname") or "")[:253] or None
        dev = found.get(name) if name else None
        z.hostname, z.host_key, z.device_id = name, host_key(name), str(dev.id) if dev else None
        z.user = str(d.get("user") or "")[:256] or None
        z.os_version, z.agent_version = str(d.get("osVersion") or "")[:128] or None, str(d.get("agentVersion") or "")[:64] or None
        z.registration_state = str(d.get("registrationState") or "")[:32] or None
        z.tunnel_status = str(d.get("unifiedTunnelStatus") or "")[:64] or None
        z.last_seen = _when(d.get("last_seen_time") or d.get("keepAliveTime"))
        z.zdx = z.host_key in zdx
        db.add(z)
    for udid, z in have.items():   # gone from Zscaler's inventory
        if udid not in seen:
            await db.delete(z)
    await db.commit()
    await _coverage(db, rows)
    return len(rows)


async def _coverage(db: AsyncSession, rows: list[dict]) -> None:
    from api.core.device_match import host_key
    from api.models.device import Device, DeviceType
    from api.models.zscaler import ZscalerDevice
    now = datetime.now(timezone.utc)
    zs = list((await db.execute(select(ZscalerDevice))).scalars())
    registered = {z.host_key for z in zs if (z.registration_state or "").lower() == "registered"} - {None}
    since = now - timedelta(days=SEEN_DAYS)
    ours = (await db.execute(select(Device.hostname).where(Device.device_type == DeviceType.workstation,
                                                           Device.last_seen >= since))).scalars().all()
    active = {host_key(h) for h in ours} - {None}
    missing = sorted({h for h in ours if host_key(h) not in registered})
    # A registered agent silent for 2 weeks on a machine the EDR or a scanner still sees: Zscaler isn't working there.
    # (Removed or unregistered agents are usually retired machines, so they aren't counted.)
    # Judged per machine by its newest check-in: a re-enrolled or reimaged machine leaves its old record behind
    newest: dict[str, ZscalerDevice] = {}
    for z in zs:
        if (z.registration_state or "").lower() == "registered" and z.host_key in active and z.last_seen:
            if z.host_key not in newest or _aware(z.last_seen) > _aware(newest[z.host_key].last_seen):
                newest[z.host_key] = z
    stale = [z for z in newest.values() if _aware(z.last_seen) < now - timedelta(days=STALE_DAYS)]
    findings = []
    if rows:   # only judge coverage when Zscaler answered with its inventory
        findings.append(("zscaler_no_client_connector", "zcc:coverage", "high" if len(missing) > 10 else "medium",
                         f"{len(missing)} workstation{'s' if len(missing) != 1 else ''} with no registered Zscaler Client Connector",
                         "Workstations an EDR or scanner saw in the last 30 days that Zscaler has no registered agent for: their web "
                         "traffic isn't inspected or protected by Zscaler. First ones: " + ", ".join(missing[:25]), len(missing)))
        findings.append(("zscaler_client_connector_stale", "zcc:stale", "medium",
                         f"{len(stale)} active workstation{'s' if len(stale) != 1 else ''} whose Zscaler agent is silent for {STALE_DAYS} days",
                         "Registered Client Connectors that haven't checked in for two weeks on machines an EDR or scanner still sees: "
                         "Zscaler likely isn't protecting them. " +
                         ", ".join(sorted({z.hostname or z.udid for z in stale})[:25]), len(stale)))
    await _save(db, findings, prefix="zcc:")


async def policy(conn, db: AsyncSession) -> int:
    url = await conn.get("/zia/api/v1/urlFilteringRules") or []
    ssl = await conn.get("/zia/api/v1/sslInspectionRules") or []
    fw = await conn.get("/zia/api/v1/firewallFilteringRules") or []
    dlp = await conn.get("/zia/api/v1/webDlpRules") or []
    admins = await conn.get("/zia/api/v1/adminUsers") or []
    on = lambda r: str(r.get("state") or "").upper() == "ENABLED"   # noqa: E731
    f = []
    for r in url:
        cats = [str(c) for c in r.get("urlCategories") or []]
        bad = [c for c in cats if any(k in c.lower() for k in RISKY_CATEGORIES)]
        if on(r) and str(r.get("action") or "").upper() == "ALLOW" and bad:
            f.append(("zia_url_allows_risky", f"zia:url:{r.get('id')}", "high", f"URL rule \"{r.get('name')}\" allows {', '.join(bad[:4])}",
                      f"Enabled URL filtering rule (order {r.get('order')}) allows security-risk categories: {', '.join(bad)}.", 1))
    for r in ssl:
        kind = str((r.get("action") or {}).get("type") or "").upper()
        cats = [str(c).upper() for c in r.get("urlCategories") or []]
        broad = (not cats or "ANY" in cats) and not r.get("users") and not r.get("groups") and not r.get("cloudApplications")
        if on(r) and "DO_NOT" in kind and broad and not r.get("defaultRule"):
            f.append(("zia_ssl_bypass_broad", f"zia:ssl:{r.get('id')}", "high", f"SSL rule \"{r.get('name')}\" skips inspection for everything",
                      f"Enabled SSL inspection rule (order {r.get('order')}) does not inspect traffic of any category for everyone, "
                      "so malware and data leaving in HTTPS go unseen there.", 1))
    for r in fw:
        if on(r) and str(r.get("action") or "").upper() == "ALLOW" and not any(r.get(k) for k in FW_LIMITS) and not r.get("defaultRule"):
            f.append(("zia_firewall_allow_any", f"zia:fw:{r.get('id')}", "high", f"Firewall rule \"{r.get('name')}\" allows any to any",
                      f"Enabled firewall rule (order {r.get('order')}) allows traffic with no destination, service, application or "
                      "source limit.", 1))
    for r in dlp:
        action = str(r.get("action") or "").upper()
        if not on(r) or action == "ALLOW":
            f.append(("zia_dlp_not_enforcing", f"zia:dlp:{r.get('id')}", "medium",
                      f"DLP rule \"{r.get('name')}\" is {'off' if not on(r) else 'monitor only'}",
                      f"DLP rule {'is disabled' if not on(r) else 'allows matches (monitor only)'}: data it should catch can leave.", 1))
    live = [a for a in admins if not a.get("disabled")]
    pw = [a for a in live if a.get("isPasswordLoginAllowed")]
    supers = [a for a in live if "super" in str((a.get("role") or {}).get("name") or "").lower()]
    if pw:
        f.append(("zia_admin_password_login", "zia:admins:password", "medium",
                  f"{len(pw)} Zscaler admin{'s' if len(pw) != 1 else ''} can sign in with a password",
                  "Admins allowed to sign in with a password instead of SSO (and its MFA): " +
                  ", ".join(sorted(str(a.get("loginName") or a.get("name")) for a in pw)[:25]), len(pw)))
    if len(supers) > SUPER_ADMINS_OK:
        f.append(("zia_too_many_super_admins", "zia:admins:super", "medium", f"{len(supers)} Zscaler super admins",
                  f"More than {SUPER_ADMINS_OK} enabled admins hold a super admin role: " +
                  ", ".join(sorted(str(a.get("loginName") or a.get("name")) for a in supers)[:25]), len(supers)))
    if url or ssl or fw or dlp or admins:   # only judge what Zscaler answered
        await _save(db, f, prefix="zia:")
    return len(f)


async def _save(db: AsyncSession, findings: list[tuple], prefix: str) -> None:
    """Upsert this run's findings; this source's findings with the prefix that weren't found again are resolved."""
    from api.models.identity import PostureFinding
    now = datetime.now(timezone.utc)
    have = {p.external_id: p for p in (await db.execute(select(PostureFinding).where(
        PostureFinding.source == SOURCE, PostureFinding.external_id.like(f"{prefix}%")))).scalars()}
    keep = set()
    for kind, ext, sev, title, desc, count in findings:
        if count == 0:
            continue
        p = have.get(ext) or PostureFinding(source=SOURCE, external_id=ext, detected_at=now)
        p.finding_type, p.severity, p.title, p.description = kind, sev, title[:512], desc[:4000]
        p.affected_count, p.is_resolved, p.resolved_at, p.app_name = count, False, None, "Zscaler"
        db.add(p)
        keep.add(ext)
    gone = [e for e in have if e not in keep]
    if gone:
        await db.execute(update(PostureFinding).where(PostureFinding.source == SOURCE, PostureFinding.external_id.in_(gone),
                                                      PostureFinding.is_resolved.is_(False))
                         .values(is_resolved=True, resolved_at=now))
    await db.commit()
