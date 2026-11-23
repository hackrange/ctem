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
  op_id op_type name state launched_at completed_at hosts_count services_count weaknesses_count } } }"""
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
        for attempt in range(2):
            tok = await self._auth(client)
            r = await client.post(f"{self._base}/v1/graphql", json={"query": query, "variables": variables or {}},
                                  headers={"Authorization": f"Bearer {tok}"})
            body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            expired = str(body.get("message") or body.get("Message") or "").lower()
            if attempt == 0 and (r.status_code in (401, 403) or "expired" in expired or "unauthorized" in expired):
                self._token = None   # sign in again once
                continue
            r.raise_for_status()
            if body.get("errors"):
                raise ValueError("Horizon3: " + "; ".join(str(e.get("message"))[:200] for e in body["errors"][:3]))
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

    async def _pages(self, client, query: str, key: str, inner: str, variables: dict, cap: int = 200) -> list[dict]:
        out = []
        for page in range(1, cap + 1):
            data = await self._gql(client, query, {**variables, "page_input": {"page_num": page, "page_size": PAGE}})
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

    async def _apply(self, db, apply, op, weak, services, extra, tries: int = 3) -> int:
        """Apply one pentest; a deadlock with another writer to the same assets is retried (the work is idempotent)."""
        import asyncio

        from sqlalchemy.exc import DBAPIError
        for attempt in range(tries):
            try:
                return await apply.op(db, op, weak, services, extra)
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
            ops = await self._pages(client, _PENTESTS, "pentests_page", "pentests", {}, cap=20)
            done = [o for o in ops if str(o.get("state") or "").lower() in ("done", "complete", "completed")
                    and (_dt(o.get("completed_at")) or datetime.min.replace(tzinfo=timezone.utc)) >= since]
            done.sort(key=lambda o: _dt(o.get("completed_at")))   # oldest first, so the newest run has the last word
            svc_q = await self._services_query(client, done[0]["op_id"]) if done else None
            if done and not svc_q:
                self.notes.append("Horizon3's API offered no services query, so findings aren't marked unreachable yet")
            from api.integrations import horizon3_apply as apply
            for op in done:
                weak = await self._pages(client, _WEAK, "weaknesses_page", "weaknesses", {"op_id": op["op_id"]})
                # Open services from the pentests that scan the network (an AD password audit doesn't)
                services = (await self._pages(client, svc_q, "services_page", "services", {"op_id": op["op_id"]}, cap=2000)
                            if svc_q and str(op.get("op_type") or "") == "NodeZero" else None)
                extra = await self._extras(client, op["op_id"]) if str(op.get("op_type") or "") == "NodeZero" else {}
                n += await self._apply(db, apply, op, weak, services, extra)
        if self.notes:
            log.info("Horizon3: %s", "; ".join(self.notes))
        return n
