"""CrowdStrike Falcon connector. Syncs devices + threat detections."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.crowdstrike")

_API_BASE = "https://api.crowdstrike.com"
# Contained hosts still have a working sensor; it just isolates them
_SENSOR_RUNNING = {"normal", "containment_pending", "contained", "lift_containment_pending"}
# Isolated from the network until someone lifts it; pending only means it hasn't taken yet
_CONTAINED = {"contained", "lift_containment_pending"}
_AID = re.compile(r"^[0-9a-fA-F]{32}$")


def falcon_time(v) -> datetime | None:
    """Falcon's last_seen (ISO text from the API, a datetime from the shipper's checked batch), in UTC."""
    if isinstance(v, str) and len(v) <= 40:
        try:
            v = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(v, datetime):
        return None
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


_SERVICE_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}
_SERVICE_NAMES = {"system", "local service", "network service", "localsystem"}


def alert_user_key(detail: dict) -> str | None:
    """A keyed hash of the person behind an alert, so Cyber Threats can tie their alerts together across hosts
    without the name leaving the encrypted detail. Machine and service accounts would tie everything together, so
    they get none."""
    from api.core.encryption import search_hash
    from api.core.user_match import bare
    u = detail.get("user") or {}
    name = u.get("name") or (detail.get("process") or {}).get("user")
    if not isinstance(name, str) or u.get("sid") in _SERVICE_SIDS:
        return None
    b = bare(name)
    if not b or b.endswith("$") or b in _SERVICE_NAMES:
        return None
    return search_hash(f"alert-user:{b}")


def is_hidden(d: dict) -> bool:
    return bool(d.get("hidden")) or str(d.get("host_hidden_status") or "").lower() == "hidden"


def stale_duplicate(dev, aid: str | None, hidden: bool, seen: datetime | None) -> bool:
    """A hidden Falcon record for a name a different, visible Falcon host already holds, and no newer
    than it: usually the old copy left behind by a reimage. It mustn't overwrite the live host's EDR state."""
    if not hidden or not aid or not dev.edr_device_id or dev.edr_device_id == aid or dev.edr_hidden:
        return False
    last = dev.edr_last_seen
    if last is not None and last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return seen is None or last is None or seen <= last


def detected_owner(people, last: str | None, history: list[str]) -> str | None:
    """Last sign-in if it's a person; else the newest real account in the login history; aliases last."""
    alias = None
    for name in [last, *history]:
        uid, via_alias = people.resolve(name)
        if uid and not via_alias:
            return uid
        alias = alias or uid
    return alias



def _where(dev, d: dict) -> None:
    """Falcon's word on where the host is (shipper 1.6.0+); an older shipper sends none of it, which changes nothing."""
    from api.core.encryption import search_hash
    if d.get("site_name"):
        dev.edr_site = d["site_name"][:128]
    if d.get("ou"):
        dev.edr_ou = " | ".join(d["ou"])[:1024]
    if d.get("machine_domain"):
        dev.edr_domain = d["machine_domain"][:253]
    if d.get("external_ip"):
        dev.public_ip, dev.public_ip_hash = d["external_ip"], search_hash(d["external_ip"])
    if d.get("mac") and not dev.mac_address:
        dev.mac_address = d["mac"]
    if d.get("local_ip") and not dev.ip:   # a scanner's address for the host wins; this fills a gap
        dev.ip, dev.ip_hash = d["local_ip"], search_hash(d["local_ip"])

@register(Vendor.crowdstrike)
class CrowdStrikeConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            token = await self._get_token()
            return bool(token)
        except Exception as e:
            log.warning("CrowdStrike test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        token = await self._get_token()
        devices = await self._list_devices(token)
        detections = await self._list_detections(token)
        count = await self._upsert(devices, detections, db)
        await self._cache_threats(detections, db)
        return count

    async def _get_token(self) -> str:
        async with safe_client() as client:
            resp = await client.post(
                f"{_API_BASE}/oauth2/token",
                data={
                    "client_id": self.config["client_id"],
                    "client_secret": self.config["client_secret"],
                },
            )
        resp.raise_for_status()
        return resp.json()["access_token"]

    async def _list_devices(self, token: str) -> list[dict]:
        """Visible hosts, then hidden ones (the normal search leaves hidden hosts out), with their details."""
        auth = {"Authorization": f"Bearer {token}"}
        out: list[dict] = []
        async with safe_client() as client:
            async def ids_from(path: str, optional: bool) -> list[str]:
                ids: list[str] = []
                while len(ids) < 200_000:
                    resp = await client.get(f"{_API_BASE}{path}", headers=auth, params={"limit": 5000, "offset": len(ids)})
                    if optional and resp.status_code in (403, 404):
                        log.warning("CrowdStrike hidden hosts API returned %s; hidden hosts skipped", resp.status_code)
                        return ids
                    resp.raise_for_status()
                    data = resp.json()
                    batch = [i for i in data.get("resources") or [] if isinstance(i, str) and _AID.match(i)]
                    ids.extend(batch)
                    total = ((data.get("meta") or {}).get("pagination") or {}).get("total")
                    if not batch or (isinstance(total, int) and len(ids) >= total):
                        break
                return ids

            visible = await ids_from("/devices/queries/devices/v1", False)
            known = set(visible)
            hidden = [i for i in await ids_from("/devices/queries/devices-hidden/v1", True) if i not in known]
            for group, flag in ((visible, False), (hidden, True)):
                for i in range(0, len(group), 500):
                    detail = await client.post(f"{_API_BASE}/devices/entities/devices/v2", headers=auth,
                                               json={"ids": group[i:i + 500]})
                    detail.raise_for_status()
                    for d in detail.json().get("resources") or []:
                        if isinstance(d, dict):
                            out.append({**d, "hidden": flag or is_hidden(d)})
        return out

    async def _list_detections(self, token: str) -> list[dict]:
        """Alerts (API v2) from the last 30 days in any status, in the shipper's shape. The Detects API is retired."""
        from datetime import datetime, timedelta, timezone

        from api.core.cs_alert import csa
        since = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        out: list[dict] = []
        async with safe_client() as client:
            for offset in range(0, 10000, 1000):   # the query endpoint stops at 10k
                resp = await client.get(
                    f"{_API_BASE}/alerts/queries/alerts/v2",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"limit": 1000, "offset": offset, "sort": "created_timestamp.desc",
                            "filter": f"created_timestamp:>'{since}'"},
                )
                resp.raise_for_status()
                ids = resp.json().get("resources") or []
                for i in range(0, len(ids), 500):
                    detail = await client.post(
                        f"{_API_BASE}/alerts/entities/alerts/v2",
                        headers={"Authorization": f"Bearer {token}"},
                        json={"composite_ids": ids[i:i + 500]},
                    )
                    detail.raise_for_status()
                    out += [x for x in map(csa.summary, detail.json().get("resources") or []) if x]
                if len(ids) < 1000:
                    break
        return out

    async def _upsert(self, devices: list[dict], detections: list[dict], db: AsyncSession) -> int:
        from api.core.device_match import add_source, find_device, type_from_os
        from api.core.encryption import search_hash
        from sqlalchemy import inspect as sa_inspect

        from api.core.user_match import UserIndex, bare
        from api.models.device import Device, DeviceType

        people = await UserIndex.load(db)
        count = 0
        for d in devices:
            hostname = d.get("hostname") or d.get("device_id")
            if not hostname:
                continue
            dev = await find_device(db, hostname)
            if dev is None:
                dev = Device(hostname=hostname, device_type=DeviceType.workstation, source="crowdstrike")
                db.add(dev)
            add_source(dev, "crowdstrike")
            aid = d.get("device_id") if isinstance(d.get("device_id"), str) and _AID.match(d["device_id"]) else None
            hidden = is_hidden(d)
            now = datetime.now(timezone.utc)
            seen = falcon_time(d.get("last_seen"))
            seen = min(seen, now) if seen else None
            if stale_duplicate(dev, aid, hidden, seen):
                count += 1
                continue
            dev.edr_vendor = "crowdstrike"
            dev.edr_hidden = hidden
            if aid:
                dev.edr_device_id = aid
            dev.edr_active = d.get("status") in _SENSOR_RUNNING
            if d.get("status"):
                dev.edr_contained = d["status"] in _CONTAINED
            dev.os = d.get("os_version")
            kind = (d.get("product_type") or d.get("product_type_desc") or "").lower()
            if kind in ("server", "domain controller"):
                dev.device_type = DeviceType.server
            elif kind == "workstation" and dev.device_type in (DeviceType.unknown, None):
                dev.device_type = DeviceType.workstation
            dev.device_type = type_from_os(dev.os, dev.device_type)
            for f in ("firewall_enabled", "usb_storage_blocked"):
                if isinstance(d.get(f), bool):
                    setattr(dev, f, d[f])
            for f, col in (("prevention_policy_id", "edr_prevention_policy"), ("firewall_policy_id", "edr_firewall_policy"),
                           ("usb_policy_id", "edr_usb_policy")):
                if isinstance(d.get(f), str):
                    setattr(dev, col, d[f][:64])   # the policies themselves: api/core/edr_policies.py
            if isinstance(d.get("posture"), dict):
                dev.edr_posture = d["posture"]
            _where(dev, d)
            user = (d.get("last_login_user") or "").strip()
            if any(ord(ch) < 32 for ch in user):
                user = ""
            if user:
                dev.last_login_user = user[:256]
                dev.last_login_user_hash = search_hash(bare(user))
            history = [n for n in (d.get("recent_logins") or []) if isinstance(n, str)][:20]
            if history:
                dev.recent_logins = history
            history = history or dev.recent_logins or []
            if user or history:
                # Detected user; a person's assignment lives in device_assignments and wins over this
                owner = detected_owner(people, user, history)
                if owner != dev.owner_user_id:
                    dev.owner_user_id = owner
                    if dev.id and "owner" not in sa_inspect(dev).unloaded:
                        db.expire(dev, ["owner"])  # don't serve the previous person from the session cache
            dev.edr_last_seen = seen or now   # Falcon's own last contact, so a hidden, long-gone host looks old
            count += 1

        await db.commit()
        return count

    async def _cache_threats(self, detections: list[dict], db: AsyncSession) -> None:
        """One row per alert; the newest copy of an alert replaces the old one, so status changes show."""
        import json
        from datetime import datetime

        from sqlalchemy import select

        from api.core.cs_alert import csa
        from api.core.encryption import encrypt
        from api.models.settings import AppSetting

        rows = {}
        for det in detections:
            if not det.get("detection_id"):
                continue
            when = det.get("detected_at")
            dev = det.get("device") or {}
            rows[f"threat_alert_{det['detection_id']}"] = {
                "source": "crowdstrike",
                "id": det["detection_id"],
                "title": det.get("title"),
                "severity": det.get("max_severity_displayname", ""),
                "status": det.get("status"),
                "detected_at": when.isoformat() if isinstance(when, datetime) else when,
                "tactic": det.get("tactic", ""),
                "tactic_id": det.get("tactic_id"),
                "technique": det.get("technique", ""),
                "technique_id": det.get("technique_id"),
                "hostname": dev.get("hostname"),
                "falcon_device_id": dev.get("device_id"),
                "link": det.get("link"),
                "description": det.get("behaviors", [{}])[0].get("description") if det.get("behaviors") else None,
            }
            # The rest (command lines, users, hashes, network) is sensitive: encrypted, opened only on the detail page
            detail = csa.clean(det.get("detail"))
            if detail:
                rows[f"threat_alert_{det['detection_id']}"].update({
                    "aggregate_id": detail.get("aggregate_id"), "user_key": alert_user_key(detail),
                    "detail_enc": encrypt(json.dumps(detail, separators=(",", ":")))})
        keys = list(rows)
        for i in range(0, len(keys), 500):
            part = keys[i:i + 500]
            have = {r.key: r for r in (await db.execute(select(AppSetting).where(AppSetting.key.in_(part)))).scalars()}
            for k in part:
                setting = have.get(k) or AppSetting(key=k, is_sensitive=False)
                setting.value = json.dumps({x: v for x, v in rows[k].items() if v not in (None, "")})
                db.add(setting)
        await db.commit()
