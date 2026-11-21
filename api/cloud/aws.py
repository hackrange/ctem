"""AWS: EC2 instances, their public IPs, and what their security groups and network ACLs let in. Read-only.

Credentials: an access key (optionally with a role to assume, for other accounts). IAM needs only
ec2:DescribeRegions, ec2:DescribeInstances, ec2:DescribeNetworkInterfaces, ec2:DescribeSecurityGroups and
ec2:DescribeNetworkAcls (plus sts:AssumeRole when a role is given). Endpoints are AWS's own, chosen by the
SDK from an allow-listed region name."""
from __future__ import annotations

import asyncio
import logging
import re

from sqlalchemy.ext.asyncio import AsyncSession

from api.cloud.exposure import Instance, Opening, is_any, proto, store
from api.integrations.base import BaseConnector, register
from api.models.integration import Vendor

log = logging.getLogger("open-ctem.cloud.aws")
_REGION = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")
_ROLE = re.compile(r"^arn:aws(-us-gov|-cn)?:iam::\d{12}:role/[\w+=,.@/-]{1,512}$")
_KEY_ID = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")


def check(config: dict) -> None:
    """Refuse a config that can't be right before it's stored."""
    if not _KEY_ID.match(str(config.get("access_key_id") or "")) or not config.get("secret_access_key"):
        raise ValueError("give an access key ID (AKIA...) and its secret access key")
    if config.get("role_arn") and not _ROLE.match(str(config["role_arn"])):
        raise ValueError("the role ARN looks like arn:aws:iam::123456789012:role/name")
    for r in regions_of(config):
        if not _REGION.match(r):
            raise ValueError(f"{r!r} isn't an AWS region name")


def regions_of(config: dict) -> list[str]:
    raw = str(config.get("regions") or "").replace(";", ",")
    return [r.strip().lower() for r in raw.split(",") if r.strip()][:30]


def _session(config: dict):
    import boto3
    s = boto3.session.Session(aws_access_key_id=config["access_key_id"], aws_secret_access_key=config["secret_access_key"])
    if config.get("role_arn"):
        creds = s.client("sts", region_name="us-east-1").assume_role(
            RoleArn=config["role_arn"], RoleSessionName="open-ctem", DurationSeconds=3600)["Credentials"]
        s = boto3.session.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                                  aws_session_token=creds["SessionToken"])
    return s


def _pages(client, op: str, key: str, **kw):
    for page in client.get_paginator(op).paginate(**kw, PaginationConfig={"PageSize": 500}):
        yield from page.get(key, [])


def _sg_openings(sg: dict) -> list[Opening]:
    out, label = [], f"{sg.get('GroupId')} ({sg.get('GroupName', '')})"
    for perm in sg.get("IpPermissions", []):
        pr = proto(perm.get("IpProtocol"))
        lo, hi = (None, None) if pr == "all" else (perm.get("FromPort"), perm.get("ToPort"))
        if lo == -1:
            lo = hi = None
        sources = [r.get("CidrIp") for r in perm.get("IpRanges", [])] + [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
        sources += [r.get("PrefixListId") for r in perm.get("PrefixListIds", [])]
        sources += [r.get("GroupId") for r in perm.get("UserIdGroupPairs", [])]
        sources = [s for s in sources if s]
        if sources:
            out.append(Opening(pr, lo, hi, sources, label))
    return out


def _nacl_blocks_internet(nacl: dict | None, op: Opening) -> bool:
    """Does the subnet's network ACL deny the internet on this opening? First matching /0 rule decides."""
    if not nacl:
        return False
    port = op.lo
    for e in sorted((e for e in nacl.get("Entries", []) if not e.get("Egress")), key=lambda e: e.get("RuleNumber", 32767)):
        if not is_any(e.get("CidrBlock") or e.get("Ipv6CidrBlock")):
            continue
        ep = proto(e.get("Protocol"))
        if ep not in ("all", op.proto):
            continue
        rng = e.get("PortRange")
        if rng and port is not None and not (rng.get("From", 0) <= port <= rng.get("To", 65535)):
            continue
        return e.get("RuleAction") == "deny"
    return True   # nothing allows it: the ACL's final rule denies


def _collect(config: dict) -> list[Instance]:
    s = _session(config)
    account = s.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
    regions = regions_of(config) or [r["RegionName"] for r in s.client("ec2", region_name="us-east-1")
                                     .describe_regions(AllRegions=False)["Regions"]]
    out: list[Instance] = []
    for region in regions:
        if not _REGION.match(region):
            continue
        ec2 = s.client("ec2", region_name=region)
        sgs = {g["GroupId"]: g for g in _pages(ec2, "describe_security_groups", "SecurityGroups")}
        nacls = {}
        for n in _pages(ec2, "describe_network_acls", "NetworkAcls"):
            for a in n.get("Associations", []):
                nacls[a.get("SubnetId")] = n
        enis: dict[str, list[dict]] = {}
        for e in _pages(ec2, "describe_network_interfaces", "NetworkInterfaces"):
            iid = (e.get("Attachment") or {}).get("InstanceId")
            if iid:
                enis.setdefault(iid, []).append(e)
        for r in _pages(ec2, "describe_instances", "Reservations"):
            for i in r.get("Instances", []):
                if (i.get("State") or {}).get("Name") in ("terminated", "shutting-down"):
                    continue
                tags = {t.get("Key"): t.get("Value") for t in i.get("Tags", [])}
                inst = Instance("aws", i["InstanceId"], name=tags.get("Name") or i["InstanceId"], account=account,
                                region=region, hostname=(i.get("PrivateDnsName") or None), tags=tags)
                for e in enis.get(i["InstanceId"], []) or [{"PrivateIpAddresses": [{"PrivateIpAddress": i.get("PrivateIpAddress")}],
                                                             "Groups": i.get("SecurityGroups", []), "SubnetId": i.get("SubnetId")}]:
                    inst.private_ips += [p.get("PrivateIpAddress") for p in e.get("PrivateIpAddresses", []) if p.get("PrivateIpAddress")]
                    inst.public_ips += [p["Association"]["PublicIp"] for p in e.get("PrivateIpAddresses", [])
                                        if (p.get("Association") or {}).get("PublicIp")]
                    nacl = nacls.get(e.get("SubnetId"))
                    for g in e.get("Groups", []):
                        inst.add_firewall("AWS security group", g.get("GroupId"), (sgs.get(g.get("GroupId")) or {}).get("GroupName"))
                    if nacl:
                        inst.add_firewall("AWS network ACL", nacl.get("NetworkAclId"),
                                          "default (allows everything)" if nacl.get("IsDefault") else None)
                    for g in e.get("Groups", []):
                        for op in _sg_openings(sgs.get(g.get("GroupId"), {})):
                            if any(is_any(x) for x in op.sources) and _nacl_blocks_internet(nacl, op):
                                op = Opening(op.proto, op.lo, op.hi, [x for x in op.sources if not is_any(x)] or ["(blocked by network ACL)"],
                                             op.via + " / NACL denies the internet")
                            inst.openings.append(op)
                if i.get("PublicIpAddress"):
                    inst.public_ips.append(i["PublicIpAddress"])
                inst.public_ips = sorted(set(inst.public_ips))
                out.append(inst)
    return out


@register(Vendor.aws)
class AwsConnector(BaseConnector):

    async def test_connection(self) -> bool:
        try:
            check(self.config)
            await asyncio.to_thread(lambda: _session(self.config).client("sts", region_name="us-east-1").get_caller_identity())
            return True
        except Exception as e:
            log.warning("AWS test failed: %s", type(e).__name__)
            return False

    async def sync(self, db: AsyncSession) -> int:
        check(self.config)
        instances = await asyncio.to_thread(_collect, self.config)
        return await store(db, self.integration_id or "aws", instances, bool(self.config.get("create_devices", True)))
