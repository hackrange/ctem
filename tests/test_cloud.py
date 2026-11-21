"""Cloud exposure: AWS, Azure and OCI firewall facts -> per-port reach -> device exposure and finding scores."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from api.cloud import aws, azure, oci
from api.cloud.exposure import Instance, Opening, ports, reach_of, store
from api.scoring.compensating import ControlContext, reachability


def test_aws_security_groups_and_nacl():
    sg = {"GroupId": "sg-0abc", "GroupName": "web", "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "203.0.113.5/32"}],
         "UserIdGroupPairs": [{"GroupId": "sg-bastion"}]},
        {"IpProtocol": "-1", "IpRanges": [], "UserIdGroupPairs": []}]}   # no sources: not an opening
    ops = aws._sg_openings(sg)
    assert [(o.proto, o.lo, o.sources) for o in ops] == [("tcp", 443, ["0.0.0.0/0"]), ("tcp", 22, ["203.0.113.5/32", "sg-bastion"])]
    deny = {"Entries": [{"Egress": False, "RuleNumber": 100, "Protocol": "6", "CidrBlock": "0.0.0.0/0",
                         "PortRange": {"From": 443, "To": 443}, "RuleAction": "deny"},
                        {"Egress": False, "RuleNumber": 32767, "Protocol": "-1", "CidrBlock": "0.0.0.0/0", "RuleAction": "deny"}]}
    allow = {"Entries": [{"Egress": False, "RuleNumber": 100, "Protocol": "-1", "CidrBlock": "0.0.0.0/0", "RuleAction": "allow"}]}
    assert aws._nacl_blocks_internet(deny, ops[0]) and not aws._nacl_blocks_internet(allow, ops[0])
    assert not aws._nacl_blocks_internet(None, ops[0])
    with pytest.raises(ValueError):
        aws.check({"access_key_id": "nope", "secret_access_key": "x"})
    with pytest.raises(ValueError):
        aws.check({"access_key_id": "AKIAABCDEFGHIJKLMNOP", "secret_access_key": "x", "regions": "us-east-1, mars-1"})
    aws.check({"access_key_id": "AKIAABCDEFGHIJKLMNOP", "secret_access_key": "x", "regions": "us-east-1,us-west-2"})


def test_reach_needs_a_public_ip_for_internet():
    inst = Instance("aws", "i-1", public_ips=["203.0.113.10"], openings=[
        Opening("tcp", 443, 443, ["0.0.0.0/0"], "sg-web"), Opening("tcp", 22, 22, ["198.51.100.7/32"], "sg-ssh"),
        Opening("icmp", None, None, ["0.0.0.0/0"], "sg-ping")])
    p = ports(inst)
    assert reach_of(p, 443, "tcp")[0] == "internet" and reach_of(p, 22, "tcp")[0] == "restricted"
    assert reach_of(p, 8080, "tcp")[0] == "closed" and all(x["proto"] != "icmp" for x in p)
    inst.public_ips = []
    assert reach_of(ports(inst), 443, "tcp")[0] == "any_internal"


def test_azure_both_nsgs_must_allow_the_internet():
    def rule(name, prio, access, src, port, proto="Tcp"):
        return {"name": name, "properties": {"direction": "Inbound", "priority": prio, "access": access, "protocol": proto,
                                             "sourceAddressPrefix": src, "destinationPortRange": port}}
    defaults = [rule("AllowVnetInBound", 65000, "Allow", "VirtualNetwork", "*", "*"),
                rule("DenyAllInBound", 65500, "Deny", "*", "*", "*")]
    nic = {"name": "nic-nsg", "properties": {"securityRules": [rule("https", 100, "Allow", "Internet", "443"),
                                                               rule("ssh", 110, "Allow", "198.51.100.7", "22")],
                                             "defaultSecurityRules": defaults}}
    closed_subnet = {"name": "subnet-nsg", "properties": {"securityRules": [], "defaultSecurityRules": defaults}}
    open_subnet = {"name": "subnet-nsg", "properties": {"securityRules": [rule("https", 200, "Allow", "*", "443")],
                                                        "defaultSecurityRules": defaults}}
    blocked = azure.openings(nic, closed_subnet)
    assert not any("0.0.0.0/0" in o.sources for o in blocked)              # the subnet NSG denies the internet
    assert any(o.lo == 22 and o.sources == ["198.51.100.7"] for o in blocked)
    allowed = azure.openings(nic, open_subnet)
    assert any(o.lo == 443 and o.sources == ["0.0.0.0/0"] for o in allowed)
    assert azure.openings(None, None)[0].sources == ["0.0.0.0/0"]          # no NSG at all lets everything in
    with pytest.raises(ValueError):
        azure.check({"tenant_id": "x", "client_id": "y", "client_secret": "z"})


def test_oci_rules_and_signing():
    rules = [{"direction": "INGRESS", "protocol": "6", "source": "0.0.0.0/0", "tcpOptions": {"destinationPortRange": {"min": 443, "max": 443}}},
             {"direction": "INGRESS", "protocol": "all", "source": "10.0.0.0/16"},
             {"direction": "EGRESS", "protocol": "6", "destination": "0.0.0.0/0"}]
    ops = oci.rule_openings(rules, "security list web")
    assert [(o.proto, o.lo, o.sources) for o in ops] == [("tcp", 443, ["0.0.0.0/0"]), ("all", None, ["10.0.0.0/16"])]
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    cfg = {"tenancy_ocid": "ocid1.tenancy.oc1..aaaaaaaaexampleexampleexample", "user_ocid": "ocid1.user.oc1..aaaaaaaaexampleexampleexample",
           "fingerprint": ":".join(["ab"] * 16), "private_key": pem, "regions": "us-ashburn-1"}
    with pytest.raises(ValueError, match="doesn't belong to this private key"):
        oci.check(cfg)
    cfg["fingerprint"] = oci.key_fingerprint(oci.load_key(cfg))
    oci.check(cfg)
    oci.check({**cfg, "key_passphrase": "not-needed"})   # a passphrase for an unencrypted key is ignored
    h = oci._Api(cfg, None)._sign("GET", "https://iaas.us-ashburn-1.oraclecloud.com/20160918/instances?compartmentId=x")
    assert h["authorization"].startswith('Signature version="1",keyId="ocid1.tenancy') and 'headers="date (request-target) host"' in h["authorization"]
    with pytest.raises(ValueError):
        oci.check({**cfg, "regions": "us-ashburn-1; ../evil"})


@pytest.mark.asyncio
async def test_store_matches_devices_sets_exposure_and_forgets_terminated(db):
    from api.core.encryption import search_hash
    from api.models.cloud import CloudAsset
    from api.models.device import Device, DeviceType
    n = uuid.uuid4().hex[:6]
    ip = f"10.{int(n[:2], 16)}.{int(n[2:4], 16)}.{int(n[4:6], 16)}"
    dev = Device(hostname=f"revproxy-{n}.acme.example", device_type=DeviceType.server, ip=ip, ip_hash=search_hash(ip))
    db.add(dev)
    await db.commit()
    iid = f"int-{n}"
    web = Instance("aws", f"i-{n}", name="revproxy", private_ips=[ip], public_ips=["203.0.113.9"],
                   openings=[Opening("tcp", 443, 443, ["0.0.0.0/0"], "sg-web")])
    web.add_firewall("AWS security group", "sg-web", "web")
    web.add_firewall("AWS security group", "sg-web", "web")   # attached twice through two interfaces: listed once
    new = Instance("aws", f"i-new-{n}", name=f"newbox-{n}", private_ips=["192.0.2.77"], openings=[])
    assert await store(db, iid, [web, new]) == 2
    await db.refresh(dev)
    assert dev.is_internet_exposed and ",aws," in dev.sources
    from api.cloud.exposure import for_device
    rec = (await for_device(db, dev.id))[0]
    assert rec["firewalls"] == [{"type": "AWS security group", "id": "sg-web", "name": "web"}]
    assert rec["public_ips"] == ["203.0.113.9"]
    made = (await db.execute(select(Device).where(Device.hostname == f"newbox-{n}"))).scalar_one()
    assert made.device_type == DeviceType.cloud_instance and not made.is_internet_exposed
    # Next sync: the web instance is gone (terminated), so its device is no longer exposed through AWS
    assert await store(db, iid, [new]) == 1
    await db.refresh(dev)
    assert not dev.is_internet_exposed
    assert (await db.execute(select(CloudAsset).where(CloudAsset.integration_id == iid))).scalars().all()[0].resource_id == f"i-new-{n}"


def test_scoring_reads_the_cloud_firewall_per_port():
    cloud = ports(Instance("aws", "i-1", public_ips=["203.0.113.10"], openings=[
        Opening("tcp", 443, 443, ["0.0.0.0/0"], "sg-web"), Opening("tcp", 22, 22, ["sg-bastion"], "sg-ssh")]))
    ctx = lambda p: ControlContext(exposure="listening", ports=p, cloud_ports=cloud)  # noqa: E731
    f, why = reachability(ctx("443/tcp"))
    assert f == 1.0 and why.startswith("Open to the internet on 443/tcp")
    f, why = reachability(ctx("22/tcp"))
    assert f == 0.6 and "only from sg-bastion" in why
    f, why = reachability(ctx("8080/tcp"))
    assert f == 0.4 and why.startswith("No cloud firewall rule allows")
    # CVSS local access still wins, and a non-cloud device is unaffected
    assert reachability(ControlContext(exposure="listening", ports="443/tcp", cloud_ports=cloud, attack_vector="local"))[0] == 0.5
    assert reachability(ControlContext(exposure="listening", ports="8080/tcp"))[0] == 1.0


@pytest.mark.asyncio
async def test_cloud_configs_are_checked_before_saving(client_admin):
    r = await client_admin.post("/api/v1/integrations", json={"vendor": "aws", "name": "AWS prod", "config": {
        "access_key_id": "bad", "secret_access_key": "x"}})
    assert r.status_code == 400
    r = await client_admin.post("/api/v1/integrations", json={"vendor": "oci", "name": "OCI", "config": {
        "tenancy_ocid": "ocid1.tenancy.oc1..aaaaaaaaexampleexampleexample", "base_url": "https://evil.example"}})
    assert r.status_code == 400


def test_every_cloud_secret_is_redacted_on_read():
    from api.routes.integrations import _SECRET_RE
    for k in ("secret_access_key", "client_secret", "private_key", "key_passphrase"):
        assert _SECRET_RE.search(k), k
    for k in ("access_key_id", "tenant_id", "client_id", "tenancy_ocid", "fingerprint", "regions"):
        assert not _SECRET_RE.search(k), k



@pytest.mark.asyncio
async def test_device_detail_shows_public_ips_and_firewalls(db, client_admin):
    from api.core.encryption import search_hash
    from api.models.device import Device, DeviceType
    n = uuid.uuid4().hex[:6]
    ip = f"10.{int(n[:2], 16)}.{int(n[2:4], 16)}.{int(n[4:6], 16)}"
    dev = Device(hostname=f"pub-{n}.acme.example", device_type=DeviceType.server, ip=ip, ip_hash=search_hash(ip),
                 edr_vendor="crowdstrike", firewall_enabled=True)
    db.add(dev)
    await db.commit()
    inst = Instance("aws", f"i-pub-{n}", name="pub", private_ips=[ip], public_ips=["198.51.100.20"],
                    openings=[Opening("tcp", 443, 443, ["0.0.0.0/0"], "sg-web (web)")])
    inst.add_firewall("AWS security group", "sg-web", "web")
    await store(db, f"int-pub-{n}", [inst])
    d = (await client_admin.get(f"/api/v1/devices/{dev.id}")).json()
    assert d["public_ips"] == [{"ip": "198.51.100.20", "source": "AWS"}]
    assert d["cloud"][0]["firewalls"][0]["id"] == "sg-web" and d["firewall_enabled"] is True


@pytest.mark.asyncio
async def test_cloud_tags_become_device_tags_and_follow_the_cloud(db):
    from sqlalchemy import select as sel

    from api.cloud.exposure import tag_names
    from api.models.device import Device, DeviceTag
    from api.models.tag import Tag
    inst = Instance("aws", "i-t", tags={"ITOwner": "Jeff Davis", "Environment": "prod", "aws:cloudformation:stack-id": "arn:x",
                                        "Flag": "", "Bad\x07Key": "v"})
    assert tag_names(inst) == {"aws:ITOwner:Jeff Davis", "aws:Environment:prod", "aws:Flag", "aws:BadKey:v"}
    n = uuid.uuid4().hex[:6]
    inst = Instance("aws", f"i-tag-{n}", name=f"tagbox-{n}", private_ips=["192.0.2.99"], tags={"ITOwner": "Pat", "App": "web"})
    await store(db, f"int-tag-{n}", [inst])
    dev = (await db.execute(sel(Device).where(Device.hostname == f"tagbox-{n}"))).scalar_one()
    names = lambda: db.execute(sel(Tag.name).join(DeviceTag, DeviceTag.tag_id == Tag.id).where(DeviceTag.device_id == dev.id))  # noqa: E731
    assert set((await names()).scalars()) == {"aws:ITOwner:Pat", "aws:App:web"}
    inst.tags = {"ITOwner": "Lee"}   # changed and removed in AWS: CTEM follows
    await store(db, f"int-tag-{n}", [inst])
    assert set((await names()).scalars()) == {"aws:ITOwner:Lee"}


def test_auto_migrate_skips_python_side_defaults():
    """A column with default=list must be added without a DEFAULT clause, not 'DEFAULT <function list>'."""
    from sqlalchemy import JSON, Column, Integer, MetaData, Table, create_engine, text

    from api.core.db import _evolve
    eng = create_engine("sqlite://")
    with eng.begin() as conn:
        conn.execute(text("CREATE TABLE t_mig (id INTEGER PRIMARY KEY)"))
        md = MetaData()
        Table("t_mig", md, Column("id", Integer, primary_key=True), Column("items", JSON, default=list, nullable=False))
        _evolve(conn, md)
        cols = [r[1] for r in conn.execute(text("PRAGMA table_info(t_mig)"))]
    assert "items" in cols
