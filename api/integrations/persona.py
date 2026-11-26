"""Persona (identity verification, IDV): who has verified their identity, and when.

Reads, with GETs on an allow-list: inquiries (Okta's own verification flow and the service desk's), their templates,
and the device and network each check ran on. Writes, only the calls the owner approved (2026-11-25): start an
inquiry and make its one-time link for the service desk (api/integrations/idv_desk.py), and approve or decline one
from CTEM's IDV page (cyber or admin). Nothing else: no accounts, reports, webhooks, deletes or redactions.

Persona's inquiries carry a lot of personal data. CTEM asks for as little as the API allows (sparse fieldsets) and
keeps only what api/models/idv.py lists; the rest is dropped as soon as it is read (api/integrations/persona_ingest.py).
The inquiry's reference-id is the person's Okta user id (Okta's IDV integration sets it), which is how a check
finds its person."""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from urllib.parse import urlsplit

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.persona")
HOST = "api.withpersona.com"
VERSION = "2023-01-05"
INQ = r"inq_[A-Za-z0-9]{8,40}"
READS = (
    re.compile(r"^/api/v1/inquiries$"),
    re.compile(rf"^/api/v1/inquiries/{INQ}$"),
    re.compile(r"^/api/v1/inquiry-templates$"),
)
WRITES = (
    re.compile(r"^/api/v1/inquiries$"),                                         # the service desk starts one
    re.compile(rf"^/api/v1/inquiries/{INQ}/(approve|decline|generate-one-time-link)$"),
)
_RETRY = (500, 502, 503, 504)
_BACKOFF = (2.0, 8.0, 20.0)
# Only these attributes are asked for. "fields" holds the ID's country, state and type, next to personal data
# that is dropped on arrival; there is no narrower way to ask for those three.
INQUIRY_FIELDS = ("status,reference-id,creator,created-at,updated-at,completed-at,decisioned-at,failed-at,expired-at,"
                  "expires-at,marked-for-review-at,fields,inquiry-template")
SESSION_FIELDS = "created-at,device-type,os-name,browser-name,is-vpn,is-proxy,is-tor,is-datacenter,threat-level"


class PersonaError(RuntimeError):
    pass


def allowed(method: str, url: str) -> bool:
    p = urlsplit(url)
    if p.scheme != "https" or p.hostname != HOST or p.port not in (None, 443) or p.username or p.password:
        return False
    rules = READS if method == "GET" else WRITES if method == "POST" else ()
    return any(r.match(p.path) for r in rules)


def inquiry_id(value: str) -> str:
    if not re.fullmatch(INQ, value or ""):
        raise PersonaError("not a Persona inquiry id")
    return value


@register(Vendor.persona)
class PersonaConnector(BaseConnector):
    """Config: api_key (Persona API key; reads), badge_templates (template ids, comma separated, whose passes earn
    the IDV badge; blank = any template, still only inquiries an API key started), action_api_key (optional: a key for the approved writes; blank =
    api_key), allow_actions (approve, decline and service-desk requests on), template_id (the inquiry template the
    service desk sends, itmpl_...), detail_budget (inquiries whose device facts are read per sync, default 300),
    max_pages (inquiry pages of 100 read per sync, default 50)."""

    def __init__(self, config: dict) -> None:
        super().__init__(config)
        self.calls = 0
        self.warnings: list[str] = []

    def client(self):
        c = safe_client(timeout=30.0)
        c.follow_redirects = False   # a redirect would skip the allow-list
        return c

    def _headers(self, write: bool) -> dict:
        key = (self.config.get("action_api_key") or self.config.get("api_key")) if write else self.config.get("api_key")
        if not key:
            raise PersonaError("no Persona API key")
        return {"Authorization": f"Bearer {key}", "Accept": "application/json", "Persona-Version": VERSION,
                "Key-Inflection": "kebab"}

    async def request(self, method: str, path: str, client, params: dict | None = None, body: dict | None = None):
        url = path if path.startswith("https://") else f"https://{HOST}{path}"
        if not allowed(method, url):
            raise PersonaError(f"CTEM never calls {method} {urlsplit(url).path}")
        write = method != "GET"
        if write and not self.config.get("allow_actions"):
            raise PersonaError("Persona actions are turned off for this integration")
        headers = self._headers(write)
        if write:
            headers["Idempotency-Key"] = str(uuid.uuid4())
        import httpx
        for attempt in range(4):
            try:
                resp = await client.request(method, url, headers=headers, params=params, json=body)
            except httpx.HTTPError as e:
                raise PersonaError(f"Persona didn't answer ({type(e).__name__})") from None
            self.calls += 1
            if resp.status_code == 429 and attempt < 3 and not write:   # a write is never held up or repeated
                try:
                    wait = float(resp.headers.get("retry-after") or 5)
                except ValueError:
                    wait = 5.0
                await asyncio.sleep(min(60.0, max(1.0, wait)))
                continue
            if resp.status_code in _RETRY and attempt < 3 and not write:   # never repeat a write blindly
                await asyncio.sleep(_BACKOFF[attempt])
                continue
            break
        if resp.status_code in (401, 403):
            raise PersonaError(f"Persona refused the API key (HTTP {resp.status_code})")
        if resp.status_code not in (200, 201):
            raise PersonaError(f"Persona answered HTTP {resp.status_code} for {method} {urlsplit(url).path}")
        try:
            out = resp.json()
        except ValueError:
            raise PersonaError("Persona's answer wasn't JSON") from None
        if not isinstance(out, dict):
            raise PersonaError("Persona's answer wasn't an object")
        return out

    async def pages(self, path: str, client, params: dict, max_pages: int):
        """Inquiries newest first, a page of 100 at a time (Persona pages by cursor: page[after])."""
        after = None
        for _ in range(max_pages):
            q = {**params, "page[size]": "100", **({"page[after]": after} if after else {})}
            body = await self.request("GET", path, client, q)
            data = body.get("data") or []
            for item in data:
                yield item
            nxt = (body.get("links") or {}).get("next")
            if not nxt or not data:
                return
            after = str(data[-1].get("id") or "")
            if not re.fullmatch(r"[a-z]+_[A-Za-z0-9]{8,40}", after):
                return
        self.warnings.append(f"inquiries stopped after {max_pages} pages; the rest come next sync")

    async def test_connection(self) -> bool:
        try:
            async with self.client() as client:
                await self.request("GET", "/api/v1/inquiries", client, {"page[size]": "1", "fields[inquiry]": "status"})
            return True
        except Exception as e:  # noqa: BLE001 -- the card shows it failed; the log has why
            log.warning("Persona test failed: %s", type(e).__name__)
            return False

    def _int(self, key: str, default: int, hi: int) -> int:
        try:
            return max(0, min(hi, int(self.config.get(key, default))))
        except (TypeError, ValueError):
            return default

    async def sync(self, db: AsyncSession) -> int:
        from api.integrations import persona_ingest
        self.warnings = []
        async with self.client() as client:
            n = await persona_ingest.sync(self, client, db, self._int("max_pages", 50, 500),
                                          self._int("detail_budget", 300, 5000))
        log.info("Persona sync: %d inquiries, %d API calls", n, self.calls)
        return n

    # ── the approved writes ───────────────────────────────────────────────────
    async def review(self, inquiry: str, approve: bool, comment: str) -> str:
        """Approve or decline an inquiry in Persona; returns Persona's new status."""
        async with self.client() as client:
            body = await self.request("POST", f"/api/v1/inquiries/{inquiry_id(inquiry)}/{'approve' if approve else 'decline'}",
                                      client, body={"meta": {"comment": comment[:500]}})
        return str(((body.get("data") or {}).get("attributes") or {}).get("status") or "")

    async def live_details(self, inquiry: str) -> dict:
        """What an approver needs and CTEM doesn't keep: the name printed on each government ID, and the network
        each session came from (ISP, organization, connection type, country and region by IP, country by GPS).
        Read live and returned, never stored or logged (api/routes/idv_review.py audits that it was looked at).
        Never the IP address itself or GPS coordinates."""
        from api.integrations.persona_checks import ID_CLASS
        params = {"include": "verifications,sessions", "fields[inquiry]": "status",
                  "fields[verification/government-id]": "status,id-class,country-code,name-first,name-middle,name-last",
                  "fields[verification/government-id-nfc]": "status,id-class,country-code,name-first,name-middle,name-last",
                  "fields[inquiry-session]": "created-at,device-type,os-name,browser-name,ip-isp,network-organization,"
                                             "ip-connection-type,country-code,country-name,region-name,gps-country-code"}
        async with self.client() as client:
            body = await self.request("GET", f"/api/v1/inquiries/{inquiry_id(inquiry)}", client, params)
        txt = lambda a, k, n=80: (str(a.get(k))[:n] if isinstance(a.get(k), str) and a.get(k).strip() else None)  # noqa: E731
        ids, sessions = [], []
        for v in body.get("included") or []:
            if not isinstance(v, dict):
                continue
            a, kind = v.get("attributes") or {}, str(v.get("type") or "")
            if kind.startswith("verification/government-id"):
                cls = str(a.get("id-class") or "").lower()
                ids.append({"id_type": ID_CLASS.get(cls, cls.upper() or None), "status": txt(a, "status", 20),
                            "country": txt(a, "country-code", 2), "first": txt(a, "name-first"),
                            "middle": txt(a, "name-middle"), "last": txt(a, "name-last")})
            elif kind == "inquiry-session":
                sessions.append({"at": txt(a, "created-at", 32), "device_type": txt(a, "device-type", 40),
                                 "os": txt(a, "os-name", 40), "browser": txt(a, "browser-name", 40), "isp": txt(a, "ip-isp"),
                                 "organization": txt(a, "network-organization"), "connection": txt(a, "ip-connection-type", 40),
                                 "ip_country": txt(a, "country-name", 60) or txt(a, "country-code", 2),
                                 "ip_region": txt(a, "region-name", 60), "gps_country": txt(a, "gps-country-code", 2)})
        return {"on_id": ids, "sessions": sorted(sessions, key=lambda x: x["at"] or "", reverse=True)[:5]}
