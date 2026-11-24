"""Horizon3.ai NodeZero (autonomous pentesting), GraphQL API: its weaknesses as findings, and what it proves about
reachability.

- Each weakness from a recent completed pentest is a finding under its own source (CVE aliases kept, CISA KEV, proof).
- A weakness NodeZero proved (has_proof) marks the same CVE on that host, from every other source, reachable.
- A network finding a scanner saw listening on a port, on a host NodeZero tested and found without that port open,
  is not reachable by an attacker on NodeZero's path: reachability_source "horizon3_closed" (likelihood zero).
  This uses NodeZero's open services per pentest (services_page, confirmed against the live API); if a tenant
  doesn't answer it, the closed-port check is skipped with a note.
Auth (docs.horizon3.ai): POST {"key": <API key>} to /v1/auth for a token (one hour), then GraphQL with Bearer."""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.horizon3")

REGIONS = {"us": "https://api.gateway.horizon3ai.com", "eu": "https://api.gateway.horizon3ai.eu", "au": "https://api.gateway.horizon3ai.au"}
SOURCE = "horizon3"
PAGE = 100            # the API's maximum
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_PENTESTS = """query q($page_input: PageInput) { pentests_page(page_input: $page_input) { pentests {
  op_id op_type name state launched_at completed_at hosts_count services_count weaknesses_count impacts_count } } }"""
_WEAK = """query q($op_id: String!, $page_input: PageInput) { weaknesses_page(input: {op_id: $op_id}, page_input: $page_input) {
  weaknesses { uuid vuln_id vuln_name vuln_category vuln_aliases vuln_cisa_kev vuln_known_ransomware_campaign_use severity
  score base_score context_score ip host_name has_proof impact_paths_count affected_asset_text } } }"""
# What else a NodeZero pentest knows, per host (field names confirmed against the live API)
_HOSTS = """query q($op_id: String!, $page_input: PageInput) { hosts_page(input: {op_id: $op_id}, page_input: $page_input) {
  hosts { ip ip_addresses host_name host_names os_names is_domain_controller is_in_scope score severity
  services_count weaknesses_count credentials_count cloud_provider } } }"""
_PATHS = """query q($op_id: String!, $page_input: PageInput) { attack_paths_page(input: {op_id: $op_id}, page_input: $page_input) {
  attack_paths { uuid name score severity impact_type impact_title affected_asset_text time_to_finding_s } } }"""
_CREDS = """query q($op_id: String!, $page_input: PageInput) { credentials_page(input: {op_id: $op_id}, page_input: $page_input) {
  credentials { uuid user_name cred_type is_cracked is_injected has_proof is_domain_admin ip host_name time_to_finding_s } } }"""
_STORES = """query q($op_id: String!, $page_input: PageInput) { data_stores_page(input: {op_id: $op_id}, page_input: $page_input) {
  data_stores { name ip host_name port data_store_type } } }"""
# Each open service NodeZero found in a pentest (confirmed against the live API: Service has ip, port, protocol,
# host_name; the API doesn't allow schema introspection)
_SERVICES = """query q($op_id: String!, $page_input: PageInput) { services_page(input: {op_id: $op_id}, page_input: $page_input) {
  services { ip port protocol host_name } } }"""


def read_only(query: str) -> str:
    """CTEM only reads from NodeZero: one query operation, never a mutation or subscription."""
    body = re.sub(r"#[^\n]*", "", str(query)).strip()
    if not body.startswith(("query", "{")) or re.search(r"\b(mutation|subscription)\b", body):
        raise PermissionError("Horizon3: CTEM sends read-only queries only")
    return query


def _dt(v):
    """NodeZero sends times without a zone ("2026-11-10T21:54:42"); they're UTC."""
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00")) if v else None
    except ValueError:
        return None
    return t.replace(tzinfo=timezone.utc) if t is not None and t.tzinfo is None else t


@register(Vendor.horizon3)
class Horizon3Connector(BaseConnector):
    _token: str | None = None
    _born: float = 0.0
    notes: list

    @property
    def _base(self) -> str:
        return REGIONS.get(str(self.config.get("region") or "us").lower(), REGIONS["us"])

    async def _auth(self, client) -> str:
        if self._token and time.time() - self._born < 50 * 60:   # tokens last an hour
            return self._token
        r = await client.post(f"{self._base}/v1/auth", json={"key": self.config["api_key"]})
        if r.status_code == 401:
            raise PermissionError("Horizon3 refused the API key (401)")
        r.raise_for_status()
        self._token, self._born = r.json()["token"], time.time()
        return self._token

    async def _gql(self, client, query: str, variables: dict | None = None) -> dict:
        read_only(query)
        for attempt in range(2):
            tok = await self._auth(client)
            r = await client.post(f"{self._base}/v1/graphql", json={"query": query, "variables": variables or {}},
                                  headers={"Authorization": f"Bearer {tok}"})
            body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            expired = str(body.get("message") or body.get("Message") or "").lower()
            if attempt == 0 and (r.status_code in (401, 403) or "expired" in expired or "unauthorized" in expired):
                self._token = None   # sign in again once
                continue
            if body.get("errors"):   # before the status: a query the API rejects comes back as a 400 with its reasons
                raise ValueError("Horizon3: " + "; ".join(str(e.get("message"))[:200] for e in body["errors"][:3]))
            r.raise_for_status()
            return body.get("data") or {}
        raise PermissionError("Horizon3 refused the token")

    async def test_connection(self) -> bool:
        try:
            async with safe_client(timeout=30.0) as client:
                await self._gql(client, _PENTESTS, {"page_input": {"page_num": 1, "page_size": 1}})
            return True
        except Exception as e:  # noqa: BLE001
            log.warning("Horizon3 test failed: %s", type(e).__name__)
            return False

    async def _pages(self, client, query: str, key: str, inner: str, variables: dict, cap: int = 200,
                     page_extra: dict | None = None) -> list[dict]:
        out = []
        for page in range(1, cap + 1):
            data = await self._gql(client, query, {**variables, "page_input": {"page_num": page, "page_size": PAGE, **(page_extra or {})}})
            rows = ((data.get(key) or {}).get(inner)) or []
            out += rows
            if len(rows) < PAGE:
                break
        return out

    async def _services_query(self, client, op_id: str) -> str | None:
        """The services query, if this API answers it (a page of one); None, with a note, if it doesn't."""
        try:
            await self._gql(client, _SERVICES, {"op_id": op_id, "page_input": {"page_num": 1, "page_size": 1}})
            return _SERVICES
        except ValueError as e:
            log.warning("Horizon3 services query refused: %s", str(e)[:200])
            return None

    async def _extras(self, client, op_id: str) -> dict:
        """Hosts (what was tested, and how NodeZero rates each), attack paths, credentials and data stores; each is
        optional, so one the tenant doesn't answer is just left out."""
        out = {}
        for key, q, page, inner in (("hosts", _HOSTS, "hosts_page", "hosts"), ("paths", _PATHS, "attack_paths_page", "attack_paths"),
                                    ("creds", _CREDS, "credentials_page", "credentials"), ("stores", _STORES, "data_stores_page", "data_stores")):
            try:
                out[key] = await self._pages(client, q, page, inner, {"op_id": op_id}, cap=500)
            except ValueError as e:
                log.warning("Horizon3 %s not available: %s", key, str(e)[:160])
        return out

    async def _paths(self, client, db, ops: list[dict], open_series: list[dict] | None) -> None:
        """Attack paths with their chain, from every pentest that had an impact: read once, then again while recent."""
        from api.integrations import horizon3_apply as apply
        from api.integrations import horizon3_story as story
        from api.integrations.base import load_sync_state, save_sync_state
        state = await load_sync_state(db, getattr(self, "integration_id", None))
        read = set(state.get("paths_read") or [])
        recent = datetime.now(timezone.utc) - timedelta(days=int(self.config.get("op_days") or 30))
        still_open = None if open_series is None else {(s.get("ip"), str(s.get("vuln_id") or "")[:200]) for s in open_series}
        cache: dict = {}
        for op in ops:
            if str(op.get("state") or "").lower() not in ("done", "complete", "completed", "ended") or not op.get("impacts_count"):
                continue
            if op["op_id"] in read and (_dt(op.get("completed_at")) or recent) < recent:
                continue
            try:
                paths = await self._pages(client, story.PATHS_QUERY, "attack_paths_page", "attack_paths", {"op_id": op["op_id"]}, cap=50)
            except ValueError as e:
                self.notes.append("Horizon3 didn't answer the attack path chain, so paths keep their summary only")
                log.warning("Horizon3 attack paths refused: %s", str(e)[:200])
                return
            await story.save_paths(db, op, paths, lambda ip, name: apply._device(db, ip, name, cache, create=False), still_open)
            read.add(op["op_id"])
        await story.refresh_active(db, still_open)
        await save_sync_state(db, getattr(self, "integration_id", None), {**state, "paths_read": sorted(read)[-2000:]})

    async def _open_series(self, client) -> list[dict] | None:
        """Every open weakness series (NodeZero's weaknesses tracked across pentests); None if the API has none."""
        from api.integrations.horizon3_series import OPEN, QUERY
        try:
            return await self._pages(client, QUERY, "weakness_series_page", "weakness_series", {}, cap=500, page_extra=OPEN)
        except ValueError as e:
            self.notes.append("Horizon3's API offered no weakness series, so only the last pentests' weaknesses are read")
            log.warning("Horizon3 weakness series refused: %s", str(e)[:200])
            return None

    async def _apply(self, db, apply, op, weak, services, extra, tries: int = 3, findings: bool = True) -> int:
        """Apply one pentest; a deadlock with another writer to the same assets is retried (the work is idempotent)."""
        import asyncio

        from sqlalchemy.exc import DBAPIError
        for attempt in range(tries):
            try:
                return await apply.op(db, op, weak, services, extra, findings=findings)
            except DBAPIError as e:
                await db.rollback()
                if "deadlock" not in str(e).lower() or attempt == tries - 1:
                    raise
                log.warning("Horizon3: deadlock applying %s; retrying", op.get("op_id"))
                await asyncio.sleep(2 * (attempt + 1))
        return 0

    async def sync(self, db: AsyncSession) -> int:
        self.notes = []
        days = int(self.config.get("op_days") or 30)
        since = datetime.now(timezone.utc) - timedelta(days=days)
        n = 0
        async with safe_client(timeout=60.0) as client:
            ops = await self._pages(client, _PENTESTS, "pentests_page", "pentests", {}, cap=50)
            done = [o for o in ops if str(o.get("state") or "").lower() in ("done", "complete", "completed")
                    and (_dt(o.get("completed_at")) or datetime.min.replace(tzinfo=timezone.utc)) >= since]
            done.sort(key=lambda o: _dt(o.get("completed_at")))   # oldest first, so the newest run has the last word
            svc_q = await self._services_query(client, done[0]["op_id"]) if done else None
            if done and not svc_q:
                self.notes.append("Horizon3's API offered no services query, so findings aren't marked unreachable yet")
            from api.integrations import horizon3_apply as apply
            from api.integrations import horizon3_series as series
            open_series = await self._open_series(client)
            proof = {}
            for op in done:
                weak = await self._pages(client, _WEAK, "weaknesses_page", "weaknesses", {"op_id": op["op_id"]})
                proof.update({(w.get("ip"), str(w.get("vuln_id") or "")[:200]): True for w in weak if w.get("has_proof")})
                # Open services from the pentests that scan the network (an AD password audit doesn't)
                services = (await self._pages(client, svc_q, "services_page", "services", {"op_id": op["op_id"]}, cap=2000)
                            if svc_q and str(op.get("op_type") or "") == "NodeZero" else None)
                extra = await self._extras(client, op["op_id"]) if str(op.get("op_type") or "") == "NodeZero" else {}
                n += await self._apply(db, apply, op, weak, services, extra, findings=open_series is None)
            if open_series is not None:   # every weakness NodeZero still has open, whichever pentest last saw it
                # What each pentest proved, however old: an exploited weakness stays exploited while it's open
                from api.integrations import horizon3_story as story
                for op in (o for o in ops if str(o.get("state") or "").lower() in ("done", "complete", "completed", "ended")):
                    for w in await self._pages(client, series.PROVED_QUERY, "weaknesses_page", "weaknesses",
                                               {"op_id": op["op_id"]}, cap=100, page_extra=series.PROVED):
                        key = (w.get("ip"), str(w.get("vuln_id") or "")[:200])
                        if not isinstance(proof.get(key), dict):   # ops come newest first: the newest proof wins
                            proof[key] = story.proof_of(w, op)
                cache: dict = {}
                wrote, seen = await series.apply(db, open_series, proof, lambda ip: apply._device(db, ip, None, cache))
                closed = await series.close_the_rest(db, seen)
                log.info("Horizon3: %d open weaknesses from %d series, %d closed", wrote, len(open_series), closed)
                n += wrote
            await self._paths(client, db, ops, open_series)
        if self.notes:
            log.info("Horizon3: %s", "; ".join(self.notes))
        return n
