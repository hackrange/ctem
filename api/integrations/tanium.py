"""Tanium (API Gateway, read only): endpoints, their users, disk encryption and patch history; installed software;
vulnerabilities (api/integrations/tanium_vulns.py). Each kind follows the integration's Pull options."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.integrations.base import BaseConnector, pulls, register
from api.integrations.tanium_gql import Gateway, sensor_args
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.tanium")

SOURCE = "tanium"
_PAGE = 200
_SENSORS = ["Patch Installation History", "Patch Installation History - Linux", "Patch - Scan Age", "Reboot Required",
            "Last Reboot", "BitLocker Details"]
_ENDPOINT = ("id name domainName serialNumber manufacturer model chassisType isVirtual isEncrypted eidLastSeen ipAddress "
             "macAddresses lastLoggedInUser primaryUser { name email } os { name platform } "
             "sensorReadings(sensors: %s) { columns { name sensor { name } values } }")
_NOISE = re.compile(r"^(\[no results\]|\[current result unavailable\]|tse-error|error:|n/a$)", re.I)
STALE_PATCH_DAYS = 30
STALE_SCAN_DAYS = 7


def _clean(v, n: int = 128):
    v = str(v or "").strip()
    return None if not v or _NOISE.match(v) else v[:n]


def _date(v) -> str | None:
    v = _clean(v, 40)
    if not v:
        return None
    for fmt, cut in (("%Y-%m-%d", 10), ("%m/%d/%Y", 10)):
        try:
            return datetime.strptime(v[:cut], fmt).date().isoformat()
        except ValueError:
            continue
    return None


def _sensors(node: dict) -> dict[str, dict[str, list]]:
    out: dict[str, dict[str, list]] = {}
    for c in ((node.get("sensorReadings") or {}).get("columns") or []):
        out.setdefault((c.get("sensor") or {}).get("name") or "", {})[c.get("name") or ""] = c.get("values") or []
    return out


def _rows(cols: dict[str, list]) -> list[dict]:
    n = max((len(v) for v in cols.values()), default=0)
    return [{k: (v[i] if i < len(v) else None) for k, v in cols.items()} for i in range(n)]


def patches(s: dict) -> dict:
    """Last patch installed, by what, how many in 90 days, scan age and reboot state, from the patch sensors."""
    got = []
    for name, src in (("Patch Installation History", "Install Source"), ("Patch Installation History - Linux", "Package Manager")):
        for r in _rows(s.get(name) or {}):
            d, t = _date(r.get("Date Installed")), _clean(r.get("Title"), 200)
            if d and t:
                got.append({"date": d, "title": t, "source": _clean(r.get(src), 64)})
    got.sort(key=lambda x: x["date"], reverse=True)
    age_raw = next(iter((s.get("Patch - Scan Age") or {}).get("Days Since Successful Scan") or []), None)
    m = re.match(r"\s*(\d+)\s*day", str(age_raw or ""), re.I)
    reboot = next((str(v) for vals in (s.get("Reboot Required") or {}).values() for v in vals
                   if str(v).lower() in ("yes", "no", "true", "false")), "")
    last_reboot = next((v for vals in (s.get("Last Reboot") or {}).values() for v in vals), None)
    cut = (datetime.now(timezone.utc) - timedelta(days=90)).date().isoformat()
    return {"last_installed": got[0]["date"] if got else None, "last_title": got[0]["title"] if got else None,
            "last_source": got[0]["source"] if got else None, "in_90_days": sum(1 for g in got if g["date"] >= cut),
            "recent": got[:10], "scan_age_days": int(m.group(1)) if m else None,
            "scan_note": None if m else _clean(age_raw, 80),
            "reboot_required": True if reboot.lower() in ("yes", "true") else False if reboot.lower() in ("no", "false") else None,
            "last_reboot": _clean(last_reboot, 40)}


def bitlocker(s: dict) -> list[dict]:
    return [{"drive": _clean(r.get("Drive"), 16), "protection": _clean(r.get("Protection Status"), 40),
             "conversion": _clean(r.get("Conversion Status"), 40), "method": _clean(r.get("Encryption Method"), 40),
             "percent": _clean(r.get("Encryption Percentage"), 8), "lock": _clean(r.get("Lock Status"), 20)}
            for r in _rows(s.get("BitLocker Details") or {}) if _clean(r.get("Drive"), 16)][:8]


def view(node: dict, encryption: bool) -> dict:
    """What CTEM keeps per endpoint (encrypted on the device row)."""
    s = _sensors(node)
    pu = node.get("primaryUser") or {}
    out = {"id": _clean(node.get("id"), 64), "seen": _clean(node.get("eidLastSeen"), 40),
           "serial": _clean(node.get("serialNumber"), 64), "manufacturer": _clean(node.get("manufacturer")),
           "model": _clean(node.get("model")), "chassis": _clean(node.get("chassisType"), 40),
           "virtual": node.get("isVirtual"), "os": _clean((node.get("os") or {}).get("name")),
           "platform": _clean((node.get("os") or {}).get("platform"), 32), "domain": _clean(node.get("domainName"), 253),
           "primary_user": _clean(pu.get("name")), "primary_email": _clean(pu.get("email"), 254),
           "last_user": _clean(node.get("lastLoggedInUser")), "patch": patches(s),
           "at": datetime.now(timezone.utc).isoformat()}
    if encryption:
        out["encrypted"] = node.get("isEncrypted") if isinstance(node.get("isEncrypted"), bool) else None
        out["bitlocker"] = bitlocker(s)
    return out


@register(Vendor.tanium)
class TaniumConnector(BaseConnector):

    def _gw(self) -> Gateway:
        return Gateway(self.config.get("api_url"), self.config.get("api_token"))

    async def test_connection(self) -> bool:
        try:
            return "now" in await self._gw().query("{ now }")
        except Exception as e:
            log.warning("Tanium test failed: %s", type(e).__name__)
            return False

    async def sync(self, db: AsyncSession) -> int:
        gw, started = self._gw(), datetime.now(timezone.utc)
        self.warnings: list[str] = []
        listed: set[str] = set()
        n = await self._endpoints(gw, db, listed)
        if pulls(self.config, "software"):
            n += await self._software(gw, db, started)
        if pulls(self.config, "vulns"):
            from api.integrations import tanium_vulns
            n += await tanium_vulns.sync(gw, db, self.integration_id, listed)
        await posture(db, pulls(self.config, "disk_encryption"))
        return n

    async def _endpoints(self, gw: Gateway, db: AsyncSession, listed: set[str]) -> int:
        from api.core.device_match import add_source, find_devices, host_os, type_from_os
        from api.core.encryption import search_hash
        from api.models.device import Device, DeviceType
        enc, count = pulls(self.config, "disk_encryption"), 0
        async for page in gw.pages("endpoints", _ENDPOINT % sensor_args(_SENSORS), _PAGE):
            page = [p for p in page if _clean(p.get("name"), 253)]
            hit = await find_devices(db, [(p["name"], p.get("domainName") and f"{p['name']}.{p['domainName']}") for p in page])
            devs = []
            for p in page:
                dev = hit.get(p["name"])
                if dev is None:
                    dev = Device(hostname=p["name"][:253], source=SOURCE, device_type=DeviceType.workstation)
                    db.add(dev)
                add_source(dev, SOURCE)
                dev.os = host_os(dev.os, _clean((p.get("os") or {}).get("name")))
                dev.device_type = type_from_os(dev.os, dev.device_type)
                if not dev.ip and _clean(p.get("ipAddress"), 45):
                    dev.ip, dev.ip_hash = p["ipAddress"], search_hash(p["ipAddress"])
                macs = [m for m in p.get("macAddresses") or [] if _clean(m, 17)]
                dev.mac_address = dev.mac_address or (macs[0][:17] if macs else None)
                try:
                    seen = datetime.fromisoformat(str(p.get("eidLastSeen")).replace("Z", "+00:00"))
                    if dev.last_seen is None or seen > (dev.last_seen if dev.last_seen.tzinfo else dev.last_seen.replace(tzinfo=timezone.utc)):
                        dev.last_seen = seen
                except ValueError:
                    pass
                dev.tanium = view(p, enc)
                count += 1
                devs.append(dev)
            await db.flush()
            listed.update(str(d.id) for d in devs)
            await db.commit()
            db.expunge_all()
        return count

    async def _software(self, gw: Gateway, db: AsyncSession, started) -> int:
        from api.core.software_ingest import prune_run, upsert
        n, cache = 0, {}
        async for page in gw.pages("endpoints", "name installedApplications { name version }", _PAGE):
            items: dict[tuple, dict] = {}
            for p in page:
                for a in p.get("installedApplications") or []:
                    name, ver = _clean(a.get("name"), 256), _clean(a.get("version"), 128) or ""
                    if name and p.get("name"):
                        items.setdefault((name, ver), {"product": name, "version": ver, "hosts": []})["hosts"].append(p["name"])
            n += await upsert(db, list(items.values()), SOURCE, cache)
        await prune_run(db, SOURCE, started)
        await db.commit()
        return n


async def posture(db: AsyncSession, encryption: bool) -> None:
    """Posture findings: computers whose last patch is over 30 days old, with no successful patch scan in 7, and (with
    Pull disk encryption) not encrypted. A machine whose patch sensors answered only errors is unknown, never flagged."""
    from api.models.device import Device
    rows = (await db.execute(select(Device.hostname, Device.tanium).where(Device.sources.like(f"%,{SOURCE},%")))).all()
    cut = (datetime.now(timezone.utc) - timedelta(days=STALE_PATCH_DAYS)).date().isoformat()
    t = [(h, v or {}) for h, v in rows if v]
    old = sorted(h for h, v in t if (v.get("patch") or {}).get("last_installed") and v["patch"]["last_installed"] < cut)
    scan = sorted(h for h, v in t if ((v.get("patch") or {}).get("scan_age_days") or 0) > STALE_SCAN_DAYS)
    plain = sorted(h for h, v in t if encryption and v.get("encrypted") is False)
    names = lambda hs: ", ".join(hs[:200]) + (f" and {len(hs) - 200} more" if len(hs) > 200 else "")  # noqa: E731
    f = [("patch_stale", "tanium:patch:stale", "high", f"Computers with no patch installed in {STALE_PATCH_DAYS} days (Tanium)",
          f"Tanium's patch history shows nothing installed in the last {STALE_PATCH_DAYS} days on: " + names(old), len(old)),
         ("patch_scan_stale", "tanium:patch:scan", "medium", f"Computers with no successful patch scan in {STALE_SCAN_DAYS} days (Tanium)",
          "Tanium can't tell which patches these need until a scan succeeds: " + names(scan), len(scan))]
    if encryption:
        f.append(("disk_unencrypted", "tanium:devices:unencrypted", "high", "Computers with no disk encryption (Tanium)",
                  "Tanium reports no disk encryption on: " + names(plain), len(plain)))
    await _save(db, f, keep=() if encryption else ("tanium:devices:unencrypted",))


async def _save(db: AsyncSession, findings: list[tuple], keep: tuple = ()) -> None:
    from api.models.identity import PostureFinding
    now = datetime.now(timezone.utc)
    have = {p.external_id: p for p in (await db.execute(select(PostureFinding).where(PostureFinding.source == SOURCE))).scalars()}
    live = set()
    for kind, ext, sev, title, desc, count in findings:
        if not count:
            continue
        p = have.get(ext) or PostureFinding(source=SOURCE, external_id=ext, detected_at=now)
        p.finding_type, p.severity, p.title, p.description = kind, sev, title[:512], desc[:4000]
        p.affected_count, p.is_resolved, p.resolved_at, p.app_name = count, False, None, "Tanium"
        db.add(p)
        live.add(ext)
    gone = [e for e in have if e not in live and not e.startswith(keep or ("\0",))]
    if gone:
        await db.execute(update(PostureFinding).where(PostureFinding.source == SOURCE, PostureFinding.external_id.in_(gone),
                                                      PostureFinding.is_resolved.is_(False)).values(is_resolved=True, resolved_at=now))
    await db.commit()
