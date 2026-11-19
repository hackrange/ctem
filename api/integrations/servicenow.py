"""ServiceNow connector -- ticket creation, search, and CMDB export push."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.servicenow")


@register(Vendor.servicenow)
class ServiceNowConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            async with safe_client() as client:
                resp = await client.get(
                    f"{self._base}/api/now/table/sys_user",
                    auth=self._auth(),
                    params={"sysparm_limit": 1},
                )
            return resp.status_code == 200
        except Exception as e:
            log.warning("ServiceNow test failed: %s", e)
            return False

    async def sync(self, db: AsyncSession) -> int:
        """
        Pull open security incidents/tasks assigned to our integration user.
        Primarily an outbound integration (we push tickets), but we sync back status.
        """
        tickets = await self._get_open_security_tickets()
        return len(tickets)

    async def create_ticket(
        self,
        title: str,
        description: str,
        severity: str,
        affected_device: str | None = None,
        cve_id: str | None = None,
        assignment_group: str | None = None,
    ) -> dict:
        """Create a security incident in ServiceNow."""
        priority_map = {"critical": "1", "high": "2", "medium": "3", "low": "4"}
        body = {
            "short_description": title,
            "description": description,
            "category": "security",
            "subcategory": "vulnerability",
            "priority": priority_map.get(severity.lower(), "3"),
            "assignment_group": assignment_group or self.config.get("default_assignment_group", ""),
            "u_affected_device": affected_device or "",
            "u_cve_id": cve_id or "",
            "u_source": "open-ctem",
        }
        async with safe_client() as client:
            resp = await client.post(
                f"{self._base}/api/now/table/incident",
                auth=self._auth(),
                json=body,
            )
        resp.raise_for_status()
        result = resp.json().get("result", {})
        return {
            "sys_id": result.get("sys_id"),
            "number": result.get("number"),
            "url": f"{self._base}/nav_to.do?uri=incident.do?sys_id={result.get('sys_id')}",
        }

    async def search_tickets(self, query: str, limit: int = 20) -> list[dict]:
        """Full-text search ServiceNow incidents."""
        async with safe_client() as client:
            resp = await client.get(
                f"{self._base}/api/now/table/incident",
                auth=self._auth(),
                params={
                    "sysparm_query": f"short_descriptionLIKE{query}^ORdescriptionLIKE{query}",
                    "sysparm_limit": limit,
                    "sysparm_fields": "number,short_description,priority,state,sys_id,opened_at",
                },
            )
        resp.raise_for_status()
        return resp.json().get("result", [])

    async def push_cmdb_records(self, ci_records: list[dict]) -> int:
        """Push CMDB CI records via ServiceNow Import Set API."""
        table = self.config.get("import_set_table", "u_ctem_ci_import")
        count = 0
        # Batch in chunks of 100 to avoid timeouts
        for i in range(0, len(ci_records), 100):
            batch = ci_records[i:i + 100]
            async with safe_client() as client:
                for record in batch:
                    resp = await client.post(
                        f"{self._base}/api/now/import/{table}",
                        auth=self._auth(),
                        json=record,
                        timeout=30.0,
                    )
                    if resp.status_code in (200, 201):
                        count += 1
        return count

    async def _get_open_security_tickets(self) -> list[dict]:
        async with safe_client() as client:
            resp = await client.get(
                f"{self._base}/api/now/table/incident",
                auth=self._auth(),
                params={
                    "sysparm_query": "u_source=open-ctem^state!=6",  # not closed
                    "sysparm_limit": 500,
                    "sysparm_fields": "number,short_description,state,priority,sys_id",
                },
            )
        if resp.status_code != 200:
            return []
        return resp.json().get("result", [])

    def _auth(self):
        return (self.config["username"], self.config["password"])

    @property
    def _base(self) -> str:
        instance = self.config["instance"]  # e.g. "acmecorp"
        return f"https://{instance}.service-now.com"
