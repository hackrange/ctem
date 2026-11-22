"""Rapid7 InsightAppSec connector -- web application findings."""
from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import urlsplit

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations import rapid7_common as r7
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.rapid7-appsec")

_SEVERITY_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFORMATIONAL": 0.0}
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
_PAGE = 100


_SECRET_HEADER = re.compile(r"^(cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token|x-csrf-token)\s*:.*$", re.I | re.M)
_TOKENISH = re.compile(r"(?i)((?:password|passwd|pwd|token|secret|api[_-]?key|session|jsessionid|auth)=)[^&\s\"']+")
_TAGS = re.compile(r"<[^>]+>")


def scrub(raw, limit: int = 2500) -> str | None:
    """A request or response kept for evidence, without credentials: auth and cookie headers and token-like
    parameters are replaced, and it is cut to `limit` characters."""
    if not raw:
        return None
    text = _SECRET_HEADER.sub(lambda m: m.group(0).split(":", 1)[0] + ": [removed]", str(raw))
    text = _TOKENISH.sub(r"\1[removed]", text)
    return text[:limit] + ("\n[...]" if len(text) > limit else "")


def plain(html, limit: int = 4000) -> str | None:
    """Scanner documentation as plain text."""
    if not html:
        return None
    return " ".join(_TAGS.sub(" ", str(html)).replace("&nbsp;", " ").replace("&amp;", "&").split())[:limit] or None


def details(v: dict, doc: dict | None) -> dict:
    """What AppSec knows about one finding, so nobody has to open the AppSec portal: where, how it was proven,
    the request and response, the references, and the scanner's explanation and fix."""
    root = v.get("root_cause") or {}
    var = (v.get("variances") or [{}])[0] or {}
    ex = (var.get("attack_exchanges") or [None])[0] or var.get("original_exchange") or {}
    link = v.get("insight_ui_url") if str(v.get("insight_ui_url") or "").startswith("https://") else None
    out = {"kind": "DAST", "engine": "Rapid7 AppSec", "attack_type": v.get("attack_type"), "url": (root.get("url") or "")[:500] or None,
           "method": root.get("method"), "parameter": root.get("parameter"), "severity": v.get("severity"),
           "score": v.get("vulnerability_score"), "vector": (v.get("vector_string") or "")[:256] or None,
           "original_value": (str(var.get("original_value") or ""))[:300] or None, "attack_value": (str(var.get("attack_value") or ""))[:500] or None,
           "message": (str(var.get("message") or ""))[:1000] or None,
           "proof": ((str(var.get("proof_description") or "") + ("\n" if var.get("proof") else "") + str(var.get("proof") or "")).strip())[:1500] or None,
           "references": sorted((var.get("references") or {}).keys())[:20], "cwe": next((k for k in (var.get("references") or {}) if k.upper().startswith("CWE-")), None),
           "request": scrub(ex.get("request")), "response": scrub(ex.get("response")),
           "description": plain((doc or {}).get("description")), "fix": plain((doc or {}).get("recommendation")),
           "scanned_at": v.get("last_discovered"), "link": link}
    return {k: x for k, x in out.items() if x not in (None, [], "")}


_PRIVATE_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home.arpa", ".localdomain", ".intranet")


def internal_domains(raw) -> tuple[str, ...]:
    """'ad.acme.example, corp.acme.example' -> ('.ad.acme.example', '.corp.acme.example')."""
    out = []
    for part in str(raw or "").replace(";", ",").split(","):
        d = part.strip().lower().strip(".")
        if d and len(d) <= 253 and all(c.isalnum() or c in "-." for c in d):
            out.append("." + d)
    return tuple(out[:50])


def public_url(url: str | None, internal: tuple[str, ...] = ()) -> bool | None:
    """Is the scanned URL reachable from the internet? None when there's no usable host. No DNS lookups."""
    try:
        host = (urlsplit(str(url or "")).hostname or "").strip(".").lower()
    except ValueError:
        return None
    if not host:
        return None
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        pass
    if host == "localhost" or "." not in host:
        return False
    dotted = "." + host
    return not any(dotted.endswith(s) for s in _PRIVATE_SUFFIXES + internal)


def _status(raw: str | None):
    from api.models.vuln import FindingStatus
    return {
        "FALSE_POSITIVE": FindingStatus.false_positive,
        "REMEDIATED": FindingStatus.remediated,
        "IGNORED": FindingStatus.risk_accepted,
    }.get((raw or "").upper(), FindingStatus.open)


@register(Vendor.rapid7_appsec)
class InsightAppSecConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(f"{self._base}/apps", headers=r7.headers(self.config), params={"size": 1})
            return resp.status_code == 200
        except Exception as e:
            log.warning("InsightAppSec test failed: %s", type(e).__name__)
            return False

    async def sync(self, db: AsyncSession) -> int:
        apps = {a["id"]: a.get("name") or a["id"] for a in await self._list_apps()}
        vulns = await self._search_vulns()
        return await self._upsert(apps, vulns, db, await self._docs(vulns))

    async def _docs(self, vulns: list[dict]) -> dict:
        """The scanner's description and recommendation for each attack, fetched once per attack (at most 300)."""
        pairs = []
        for v in vulns:
            var = (v.get("variances") or [{}])[0] or {}
            m, a = (var.get("module") or {}).get("id"), (var.get("attack") or {}).get("id")
            if m and a and (m, a) not in pairs:
                pairs.append((m, a))
        out = {}
        async with safe_client() as client:
            for m, a in pairs[:300]:
                if not (re.fullmatch(r"[0-9A-Za-z-]{1,64}", m) and re.fullmatch(r"[0-9A-Za-z-]{1,64}", a)):
                    continue
                try:
                    r = await client.get(f"{self._base}/modules/{m}/attacks/{a}/documentation", headers=r7.headers(self.config))
                    if r.status_code == 200:
                        out[(m, a)] = r.json()
                except Exception as e:  # noqa: BLE001 -- the finding still syncs, just without the write-up
                    log.warning("AppSec documentation unavailable: %s", type(e).__name__)
        return out

    @property
    def _base(self) -> str:
        return f"{r7.platform_base(self.config)}/ias/v1"

    def _min_severities(self) -> list[str]:
        floor = str(self.config.get("min_severity", "HIGH")).upper()
        if floor not in _SEVERITIES:
            floor = "HIGH"
        return list(_SEVERITIES[: _SEVERITIES.index(floor) + 1])

    async def _list_apps(self) -> list[dict]:
        apps, index = [], 0
        async with safe_client() as client:
            while index < 50:  # 5000 apps is plenty for anyone
                resp = await client.get(f"{self._base}/apps", headers=r7.headers(self.config),
                                        params={"size": _PAGE, "index": index})
                resp.raise_for_status()
                body = resp.json()
                apps.extend(body.get("data", []))
                index += 1
                if index >= body.get("metadata", {}).get("total_pages", 0):
                    break
        return apps

    async def _search_vulns(self) -> list[dict]:
        sev = ",".join(f"'{s}'" for s in self._min_severities())
        query = {"type": "VULNERABILITY", "query": f"vulnerability.severity IN [{sev}]"}
        cap = r7.int_cfg(self.config, "max_findings", 0, 0, 10_000_000)  # 0 = no limit
        out, index = [], 0
        async with safe_client() as client:
            while not cap or len(out) < cap:
                resp = await client.post(f"{self._base}/search", headers=r7.headers(self.config),
                                         params={"size": _PAGE, "index": index}, json=query)
                resp.raise_for_status()
                body = resp.json()
                out.extend(body.get("data", []))
                index += 1
                if index >= body.get("metadata", {}).get("total_pages", 0):
                    break
        return out[:cap] if cap else out

    async def _upsert(self, apps: dict, vulns: list[dict], db: AsyncSession, docs: dict | None = None) -> int:
        from sqlalchemy import select

        from api.models.device import Device, DeviceType
        from api.models.vuln import Finding, Vulnerability

        devices: dict[str, Device] = {}
        public: dict[str, bool] = {}       # app id -> any scanned URL internet-facing
        internal = internal_domains(self.config.get("internal_domains"))
        count = 0
        for v in vulns:
            app_id = (v.get("app") or {}).get("id")
            if not app_id or not v.get("id"):
                continue
            dev = devices.get(app_id)
            if dev is None:
                dev = (await db.execute(select(Device).where(
                    Device.source == "rapid7_appsec", Device.source_id == app_id))).scalar_one_or_none()
                if dev is None:
                    dev = Device(hostname=str(apps.get(app_id, app_id))[:253], device_type=DeviceType.server,
                                 source="rapid7_appsec", source_id=app_id)
                    db.add(dev)
                    await db.flush()
                devices[app_id] = dev

            vuln = (await db.execute(select(Vulnerability).where(
                Vulnerability.source == "rapid7_appsec", Vulnerability.source_vuln_id == v["id"]))).scalar_one_or_none()
            root = v.get("root_cause") or {}
            verdict = public_url(root.get("url"), internal)
            if verdict is not None:
                public[app_id] = public.get(app_id, False) or verdict
            sev = (v.get("severity") or "MEDIUM").upper()
            if vuln is None:
                vuln = Vulnerability(source="rapid7_appsec", source_vuln_id=v["id"], title="")
                db.add(vuln)
            vuln.title = f"{v.get('attack_type') or 'AppSec finding'} ({root.get('method') or '?'} {root.get('parameter') or ''})".strip()[:512]
            var = (v.get("variances") or [{}])[0] or {}
            doc = (docs or {}).get(((var.get("module") or {}).get("id"), (var.get("attack") or {}).get("id")))
            vuln.description = plain((doc or {}).get("description")) or f"{root.get('url') or ''}".strip() or None
            vuln.domain = "web"
            vuln.cvss_base = float(v.get("vulnerability_score") or _SEVERITY_CVSS.get(sev, 5.0))
            vuln.cvss_vector = (v.get("vector_string") or "")[:256] or None
            vuln.attack_vector = "network"
            await db.flush()

            finding = (await db.execute(select(Finding).where(
                Finding.device_id == dev.id, Finding.vuln_id == vuln.id))).scalar_one_or_none()
            if finding is None:
                finding = Finding(device_id=dev.id, vuln_id=vuln.id, source="rapid7_appsec", source_id=v["id"])
                db.add(finding)
            finding.status = _status(v.get("status"))
            finding.domain = "web"
            finding.details = details(v, doc)
            finding.first_detected = r7.parse_dt(v.get("first_discovered"))
            finding.last_seen = r7.parse_dt(v.get("last_discovered"))
            count += 1
        for app_id, exposed in public.items():
            devices[app_id].is_internet_exposed = exposed
        await db.commit()
        return count
