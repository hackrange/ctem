"""Azure: VMs, their public IPs, and what the NIC and subnet network security groups let in. Read-only.

Credentials: an app registration (tenant ID, client ID, client secret) with the Reader role on the
subscriptions to cover. Only Azure's own endpoints are called (public or US Government cloud); paging links
are followed only on the same management host."""
from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit

from sqlalchemy.ext.asyncio import AsyncSession

from api.cloud.exposure import Instance, Opening, is_any, proto, store
from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.cloud.azure")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
CLOUDS = {"public": ("https://login.microsoftonline.com", "https://management.azure.com"),
          "usgov": ("https://login.microsoftonline.us", "https://management.usgovcloudapi.net")}
_API = {"compute": "2024-07-01", "network": "2024-05-01", "subs": "2022-12-01"}
_INTERNET_TAGS = ("internet",)


def check(config: dict) -> None:
    for k in ("tenant_id", "client_id"):
        if not _GUID.match(str(config.get(k) or "")):
            raise ValueError(f"{k.replace('_', ' ')} must be a GUID")
    if not config.get("client_secret"):
        raise ValueError("give the client secret")
    if str(config.get("azure_cloud") or "public") not in CLOUDS:
        raise ValueError("cloud must be public or usgov")
    for s in subscriptions_of(config):
        if not _GUID.match(s):
            raise ValueError(f"{s!r} isn't a subscription ID")


def subscriptions_of(config: dict) -> list[str]:
    return [s.strip() for s in str(config.get("subscriptions") or "").replace(";", ",").split(",") if s.strip()][:50]


class _Api:
    def __init__(self, config: dict, client):
        self.login, self.base = CLOUDS[str(config.get("azure_cloud") or "public")]
        self.config, self.client, self.token = config, client, None

    async def auth(self):
        r = await self.client.post(f"{self.login}/{self.config['tenant_id']}/oauth2/v2.0/token", data={
            "grant_type": "client_credentials", "client_id": self.config["client_id"],
            "client_secret": self.config["client_secret"], "scope": f"{self.base}/.default"})
        r.raise_for_status()
        self.token = r.json()["access_token"]

    async def list(self, path: str, api: str) -> list[dict]:
        out, url, host = [], f"{self.base}{path}?api-version={api}", urlsplit(self.base).hostname
        for _ in range(500):
            r = await self.client.get(url, headers={"Authorization": f"Bearer {self.token}"})
            r.raise_for_status()
            body = r.json()
            out += body.get("value", [])
            url = body.get("nextLink")
            if not url or urlsplit(url).hostname != host or not url.startswith("https://"):
                break
        return out


def _ports(rule: dict) -> list[tuple[int | None, int | None]]:
    p = rule.get("properties", rule)
    raw = ([p["destinationPortRange"]] if p.get("destinationPortRange") else []) + list(p.get("destinationPortRanges") or [])
    out = []
    for r in raw or ["*"]:
        r = str(r)
        if r == "*":
            out.append((None, None))
        elif "-" in r:
            a, b = r.split("-", 1)
            out.append((int(a), int(b)))
        elif r.isdigit():
            out.append((int(r), int(r)))
    return out


def _sources(rule: dict) -> list[str]:
    p = rule.get("properties", rule)
    src = ([p["sourceAddressPrefix"]] if p.get("sourceAddressPrefix") else []) + list(p.get("sourceAddressPrefixes") or [])
    src += [a.get("id", "").rsplit("/", 1)[-1] for a in p.get("sourceApplicationSecurityGroups") or []]
    return [str(s) for s in src if s]


def _inbound(nsg: dict | None) -> list[dict]:
    if not nsg:
        return []
    p = nsg.get("properties", {})
    rules = [r for r in p.get("securityRules", []) + p.get("defaultSecurityRules", [])
             if r.get("properties", {}).get("direction") == "Inbound"]
    return sorted(rules, key=lambda r: r["properties"].get("priority", 65500))


def _first(rules: list[dict], pr: str, port: int | None, internet: bool) -> str | None:
    """Allow or Deny from the first rule (by priority) that matches this protocol, port and kind of source."""
    for r in rules:
        p = r["properties"]
        rp = proto(p.get("protocol"))
        if rp not in ("all", pr) and pr != "all":
            continue
        if port is not None and not any(lo is None or lo <= port <= hi for lo, hi in _ports(r)):
            continue
        srcs = _sources(r)
        covers = any(is_any(s) or s.lower() in _INTERNET_TAGS for s in srcs)
        if internet and covers:
            return p.get("access")
    return None


def openings(nic_nsg: dict | None, subnet_nsg: dict | None) -> list[Opening]:
    """Inbound openings both NSGs allow: internet ones need an Allow from each NSG present; specific sources
    are listed from the Allow rules themselves."""
    out = []
    groups = [g for g in (nic_nsg, subnet_nsg) if g]
    if not groups:   # no NSG at all: Azure lets everything in
        return [Opening("all", None, None, ["0.0.0.0/0"], "no network security group")]
    label = " + ".join(g.get("name", "nsg") for g in groups)
    seen = set()
    for g in groups:
        for r in _inbound(g):
            p = r["properties"]
            if p.get("access") != "Allow":
                continue
            pr = proto(p.get("protocol"))
            for lo, hi in _ports(r):
                srcs = _sources(r)
                internet = any(is_any(s) or s.lower() in _INTERNET_TAGS for s in srcs)
                if internet:
                    ok = all(_first(_inbound(x), pr, lo, True) == "Allow" for x in groups)
                    key = (pr, lo, hi, "internet")
                    if ok and key not in seen:
                        seen.add(key)
                        out.append(Opening(pr, lo, hi, ["0.0.0.0/0"], f"{label} ({p.get('priority')})"))
                elif r["name"] not in ("AllowVnetInBound", "AllowAzureLoadBalancerInBound"):
                    key = (pr, lo, hi, tuple(srcs))
                    if key not in seen:
                        seen.add(key)
                        out.append(Opening(pr, lo, hi, srcs or ["(unspecified)"], f"{g.get('name', 'nsg')} rule {r['name']}"))
    return out


async def collect(config: dict) -> list[Instance]:
    async with safe_client(timeout=60.0) as client:
        api = _Api(config, client)
        await api.auth()
        subs = subscriptions_of(config) or [s["subscriptionId"] for s in await api.list("/subscriptions", _API["subs"])
                                            if s.get("state") == "Enabled"]
        out = []
        for sub in subs:
            if not _GUID.match(sub):
                continue
            net = f"/subscriptions/{sub}/providers/Microsoft.Network"
            vms = await api.list(f"/subscriptions/{sub}/providers/Microsoft.Compute/virtualMachines", _API["compute"])
            nics = {n["id"].lower(): n for n in await api.list(f"{net}/networkInterfaces", _API["network"])}
            nsgs = {n["id"].lower(): n for n in await api.list(f"{net}/networkSecurityGroups", _API["network"])}
            pips = {p["id"].lower(): p for p in await api.list(f"{net}/publicIPAddresses", _API["network"])}
            subnet_nsg = {}
            for vnet in await api.list(f"{net}/virtualNetworks", _API["network"]):
                for s in vnet.get("properties", {}).get("subnets", []):
                    ref = (s.get("properties", {}).get("networkSecurityGroup") or {}).get("id")
                    if ref:
                        subnet_nsg[s["id"].lower()] = nsgs.get(ref.lower())
            for vm in vms:
                props = vm.get("properties", {})
                os_name = (props.get("osProfile") or {}).get("computerName")
                inst = Instance("azure", vm["id"], name=vm.get("name"), account=sub, region=vm.get("location"), hostname=os_name,
                                tags=dict(vm.get("tags") or {}))
                for ref in (props.get("networkProfile") or {}).get("networkInterfaces", []):
                    nic = nics.get(str(ref.get("id", "")).lower())
                    if not nic:
                        continue
                    np = nic.get("properties", {})
                    nic_nsg = nsgs.get(str((np.get("networkSecurityGroup") or {}).get("id", "")).lower())
                    for ipc in np.get("ipConfigurations", []):
                        ip = ipc.get("properties", {})
                        if ip.get("privateIPAddress"):
                            inst.private_ips.append(ip["privateIPAddress"])
                        pip = pips.get(str((ip.get("publicIPAddress") or {}).get("id", "")).lower())
                        if pip and pip.get("properties", {}).get("ipAddress"):
                            inst.public_ips.append(pip["properties"]["ipAddress"])
                        sn = subnet_nsg.get(str((ip.get("subnet") or {}).get("id", "")).lower())
                        for g, where in ((nic_nsg, "network interface"), (sn, "subnet")):
                            if g:
                                inst.add_firewall(f"Azure NSG ({where})", g.get("id"), g.get("name"))
                        if not nic_nsg and not sn:
                            inst.add_firewall("Azure NSG", "none", "no network security group: everything is allowed in")
                        inst.openings += openings(nic_nsg, sn)
                out.append(inst)
        return out


@register(Vendor.azure)
class AzureConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            check(self.config)
            async with safe_client(timeout=30.0) as client:
                await _Api(self.config, client).auth()
            return True
        except Exception as e:
            log.warning("Azure test failed: %s", type(e).__name__)
            return False

    async def sync(self, db: AsyncSession) -> int:
        check(self.config)
        return await store(db, self.integration_id or "azure", await collect(self.config),
                           bool(self.config.get("create_devices", True)))
