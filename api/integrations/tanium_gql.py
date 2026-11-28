"""Read-only client for Tanium's API Gateway (GraphQL): GET requests, read queries, named sensors only."""
from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urlsplit

from api.core.ssrf import safe_client

log = logging.getLogger("open-ctem.tanium")

PATH = "/plugin/products/gateway/graphql"
# Only these sensors are ever read. Never "BitLocker Key" (recovery keys) or anything that runs an action.
SENSORS = {
    "Patch Installation History": [("iAge", "90"), ("showDate", "1"), ("showOther", "1")],
    "Patch Installation History - Linux": [],
    "Patch - Scan Age": [],
    "Reboot Required": [],
    "Last Reboot": [],
    "BitLocker Details": [],
    "Running Processes": [],   # only when the integration's "Pull running processes" is on (api/integrations/tanium_processes.py)
}
_WRITE = re.compile(r"\b(mutation|subscription)\b", re.I)
_RETRY = {429, 502, 503, 504}


class TaniumError(RuntimeError):
    pass


def base_url(raw: str | None) -> str:
    """https://<tenant>-api.cloud.tanium.com (or an on-prem server), without a path."""
    u = urlsplit(str(raw or "").strip())
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise TaniumError("Set the API URL to https://<your tenant>-api.cloud.tanium.com")
    return f"https://{u.hostname}" + (f":{u.port}" if u.port else "")


def sensor_args(names: list[str]) -> str:
    """The sensorReadings argument for allow-listed sensors."""
    parts = []
    for n in names:
        if n not in SENSORS:
            raise TaniumError(f"sensor not allowed: {n}")
        params = ", ".join(f'{{name: "{k}", value: "{v}"}}' for k, v in SENSORS[n])
        parts.append(f'{{name: "{n}"' + (f", params: [{params}]" if params else "") + "}")
    return "[" + ", ".join(parts) + "]"


class Gateway:
    def __init__(self, url: str, token: str, timeout: float = 120.0):
        self.url = base_url(url) + PATH
        if not token or len(token) > 512:
            raise TaniumError("Set the API token")
        self._headers = {"session": token, "Accept": "application/json"}
        self._timeout = timeout

    async def query(self, q: str) -> dict:
        if _WRITE.search(q):
            raise TaniumError("only read queries are sent to Tanium")
        async with safe_client(timeout=self._timeout) as client:
            for attempt in range(3):
                resp = await client.get(self.url, params={"query": q}, headers=self._headers)
                if resp.status_code not in _RETRY:
                    break
                await asyncio.sleep(2 ** attempt * 3)
        if resp.status_code in (401, 403):
            raise TaniumError(f"Tanium refused the token (HTTP {resp.status_code}): check it is valid, not expired, "
                              "and that this server's address is in its trusted IP addresses")
        if resp.status_code != 200:
            raise TaniumError(f"Tanium answered HTTP {resp.status_code}")
        body = resp.json()
        if body.get("errors") and not body.get("data"):
            raise TaniumError("Tanium: " + str((body["errors"][0] or {}).get("message") or "query failed")[:200])
        return body.get("data") or {}

    async def pages(self, field: str, fields: str, size: int, args: str = ""):
        """Each page of a connection (endpoints, discoverInterfaces...), one query shape throughout: Tanium's
        cursors only work with the query that made them."""
        cursor = None
        while True:
            after = f', after: "{cursor}"' if cursor else ""
            data = (await self.query(f"{{ {field}(first: {size}{after}{args}) {{ pageInfo {{ hasNextPage endCursor }} "
                                     f"edges {{ node {{ {fields} }} }} }} }}")).get(field) or {}
            yield [e["node"] for e in data.get("edges") or [] if e.get("node")]
            info = data.get("pageInfo") or {}
            if not info.get("hasNextPage") or not info.get("endCursor"):
                return
            cursor = str(info["endCursor"])
            if not re.fullmatch(r"[A-Za-z0-9+/=_\-]{1,200}", cursor):
                raise TaniumError("unexpected page cursor from Tanium")
