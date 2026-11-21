"""Oracle Cloud (OCI): instances, their public IPs, and what subnet security lists and NSGs let in. Read-only.

Credentials: an API signing key for a user in a group with read access (for example
"Allow group ctem-readers to read all-resources in tenancy"): tenancy OCID, user OCID, key fingerprint,
the private key (PEM) and the regions. Requests are signed with RSA-SHA256 as OCI documents; only
*.oraclecloud.com endpoints built from an allow-listed region name are called."""
from __future__ import annotations

import base64
import logging
import re
from email.utils import formatdate
from urllib.parse import quote, urlsplit

from sqlalchemy.ext.asyncio import AsyncSession

from api.cloud.exposure import Instance, Opening, proto, store
from api.core.ssrf import safe_client
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.cloud.oci")
_OCID = re.compile(r"^ocid1\.[a-z]+\.oc\d+\.[a-z0-9-]*\.[a-z0-9]{20,}$")
_FP = re.compile(r"^([0-9a-f]{2}:){15}[0-9a-f]{2}$")
_REGION = re.compile(r"^[a-z]{2,3}-[a-z]+-\d$")
_ID = re.compile(r"^ocid1\.[a-z]+\.oc\d+\.[a-z0-9-]*\.[a-z0-9]+$")


def regions_of(config: dict) -> list[str]:
    return [r.strip().lower() for r in str(config.get("regions") or "").replace(";", ",").split(",") if r.strip()][:20]


def check(config: dict) -> None:
    for k in ("tenancy_ocid", "user_ocid"):
        if not _OCID.match(str(config.get(k) or "")):
            raise ValueError(f"{k.replace('_', ' ')} doesn't look like an OCID (ocid1....)")
    if not _FP.match(str(config.get("fingerprint") or "").lower()):
        raise ValueError("the fingerprint looks like 12:34:...:ef (16 pairs)")
    if "PRIVATE KEY" not in str(config.get("private_key") or ""):
        raise ValueError("paste the API signing private key (PEM)")
    if not regions_of(config) or any(not _REGION.match(r) for r in regions_of(config)):
        raise ValueError("give the regions, for example us-ashburn-1, us-phoenix-1")


class _Api:
    def __init__(self, config: dict, client):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        pw = config.get("key_passphrase") or None
        self.key = load_pem_private_key(config["private_key"].encode(), password=pw.encode() if pw else None)
        self.key_id = f"{config['tenancy_ocid']}/{config['user_ocid']}/{config['fingerprint'].lower()}"
        self.client = client

    def _sign(self, method: str, url: str) -> dict:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        u = urlsplit(url)
        date = formatdate(usegmt=True)
        target = f"{method.lower()} {u.path}{'?' + u.query if u.query else ''}"
        text = f"date: {date}\n(request-target): {target}\nhost: {u.hostname}"
        sig = base64.b64encode(self.key.sign(text.encode(), padding.PKCS1v15(), hashes.SHA256())).decode()
        return {"date": date, "authorization": f'Signature version="1",keyId="{self.key_id}",algorithm="rsa-sha256",'
                                               f'headers="date (request-target) host",signature="{sig}"'}

    async def get(self, url: str):
        r = await self.client.get(url, headers=self._sign("GET", url))
        r.raise_for_status()
        return r

    async def list(self, url: str) -> list[dict]:
        out, page = [], None
        for _ in range(500):
            full = url + (f"&page={quote(page, safe='')}" if page else "")
            r = await self.get(full)
            out += r.json()
            page = r.headers.get("opc-next-page")
            if not page:
                break
        return out


def _ports(rule: dict) -> tuple[int | None, int | None]:
    opts = rule.get("tcpOptions") or rule.get("udpOptions") or {}
    rng = opts.get("destinationPortRange")
    return (rng.get("min"), rng.get("max")) if rng else (None, None)


def rule_openings(rules: list[dict], label: str) -> list[Opening]:
    out = []
    for r in rules:
        if r.get("direction", "INGRESS") != "INGRESS":
            continue
        src = r.get("source")
        if not src:
            continue
        lo, hi = _ports(r)
        out.append(Opening(proto(r.get("protocol")), lo, hi, [src], label))
    return out


async def collect(config: dict) -> list[Instance]:
    tenancy = config["tenancy_ocid"]
    async with safe_client(timeout=60.0) as client:
        api = _Api(config, client)
        out = []
        for region in regions_of(config):
            if not _REGION.match(region):
                continue
            iaas, ident = f"https://iaas.{region}.oraclecloud.com/20160918", f"https://identity.{region}.oci.oraclecloud.com/20160918"
            comps = [tenancy] + [c["id"] for c in await api.list(
                f"{ident}/compartments?compartmentId={quote(tenancy)}&compartmentIdInSubtree=true&accessLevel=ACCESSIBLE&lifecycleState=ACTIVE")
                if _ID.match(c.get("id", ""))]
            seclists, nsgrules, subnets = {}, {}, {}
            for comp in comps:
                q = quote(comp)
                instances = [i for i in await api.list(f"{iaas}/instances?compartmentId={q}")
                             if i.get("lifecycleState") not in ("TERMINATED", "TERMINATING")]
                if not instances:
                    continue
                atts = await api.list(f"{iaas}/vnicAttachments?compartmentId={q}")
                by_inst: dict[str, list[str]] = {}
                for a in atts:
                    if a.get("lifecycleState") == "ATTACHED" and _ID.match(a.get("vnicId", "")):
                        by_inst.setdefault(a.get("instanceId"), []).append(a["vnicId"])
                for i in instances:
                    inst = Instance("oci", i["id"], name=i.get("displayName"), account=tenancy, region=region)
                    for vid in by_inst.get(i["id"], [])[:8]:
                        v = (await api.get(f"{iaas}/vnics/{vid}")).json()
                        inst.hostname = inst.hostname or v.get("hostnameLabel")
                        inst.private_ips += [v.get("privateIp")] if v.get("privateIp") else []
                        inst.public_ips += [v.get("publicIp")] if v.get("publicIp") else []
                        sid = v.get("subnetId")
                        if sid and _ID.match(sid) and sid not in subnets:
                            subnets[sid] = (await api.get(f"{iaas}/subnets/{sid}")).json()
                        for sl in (subnets.get(sid) or {}).get("securityListIds", []):
                            if _ID.match(sl) and sl not in seclists:
                                body = (await api.get(f"{iaas}/securityLists/{sl}")).json()
                                seclists[sl] = rule_openings(body.get("ingressSecurityRules", []),
                                                             f"security list {body.get('displayName', sl[-8:])}")
                            inst.openings += seclists.get(sl, [])
                        for nsg in v.get("nsgIds") or []:
                            if _ID.match(nsg) and nsg not in nsgrules:
                                rules = await api.list(f"{iaas}/networkSecurityGroups/{nsg}/securityRules?direction=INGRESS")
                                nsgrules[nsg] = rule_openings(rules, f"NSG {nsg[-8:]}")
                            inst.openings += nsgrules.get(nsg, [])
                    out.append(inst)
        return out


@register(Vendor.oci)
class OciConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            check(self.config)
            region = regions_of(self.config)[0]
            async with safe_client(timeout=30.0) as client:
                await _Api(self.config, client).get(
                    f"https://identity.{region}.oci.oraclecloud.com/20160918/tenancies/{quote(self.config['tenancy_ocid'])}")
            return True
        except Exception as e:
            log.warning("OCI test failed: %s", type(e).__name__)
            return False

    async def sync(self, db: AsyncSession) -> int:
        check(self.config)
        return await store(db, self.integration_id or "oci", await collect(self.config),
                           bool(self.config.get("create_devices", True)))
