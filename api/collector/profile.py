"""Shipper profile rules shared by the admin and agent routes: settings, destinations, sealed envelopes."""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

Host = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")]
Port = Annotated[int, Field(ge=1, le=65535)]
Short = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256, pattern=r"^[^\x00-\x1f]+$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# Per-source "run every N minutes"; blank falls back to the shipper's schedule
SOURCE_SCHEDULES = (5, 10, 15, 30, 60, 120, 240, 300, 360, 720, 1440)
Every = Literal[SOURCE_SCHEDULES] | None


class _Source(_Strict):
    schedule_minutes: Every = None


class LdapSettings(_Source):
    host: Host
    port: Port | None = None
    tls: Literal["ldaps", "starttls"] | None = None
    bind_user: Short
    base_dn: Annotated[str, StringConstraints(strip_whitespace=True, max_length=1024)] | None = None


class Rapid7Settings(_Source):
    host: Host
    port: Port = 3780
    username: Short
    vuln_catalog_hours: int = Field(24, ge=1, le=168)
    software_hours: int = Field(24, ge=0, le=168)   # 0 turns software collection off


OnOff = Literal["on", "off"]


class CrowdStrikeSettings(_Source):
    cloud: Literal["us-1", "us-2", "eu-1", "us-gov-1"] = "us-1"
    client_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{32}$")]
    # Falcon products, each optional: "off" skips it; "on" with no license or scope skips it with a note on the card
    policies: OnOff = "on"      # prevention, firewall, device control
    posture: OnOff = "on"       # Zero Trust Assessment
    spotlight: OnOff = "on"     # Spotlight / Exposure Management vulnerabilities
    discover: OnOff = "on"      # Discover installed applications
    alerts: OnOff = "on"        # endpoint, identity and other Falcon alerts
    intel: OnOff = "on"         # Falcon Intel high-confidence indicators, matched against telemetry
    event_stream: OnOff = "on"  # the real-time event stream (detections, response sessions, console activity)
    fdr: OnOff = "off"          # Falcon Data Replicator telemetry as fleet stacks; needs the FDR queue and key
    fdr_queue_url: Annotated[str, StringConstraints(max_length=300, pattern=r"^https://sqs\.[a-z0-9-]+\.amazonaws\.com/[0-9]{12}/[A-Za-z0-9_-]{1,80}$")] | None = None
    fdr_region: Annotated[str, StringConstraints(pattern=r"^[a-z]{2}(-gov)?-[a-z]+-[0-9]$")] | None = None
    fdr_access_key_id: Annotated[str, StringConstraints(pattern=r"^[A-Z0-9]{16,128}$")] | None = None


class SplunkSettings(_Source):
    host: Host
    port: Port = 8089
    username: Short
    query: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)] = (
        "search index=wineventlog OR index=crowdstrike OR index=guardicore | table _time, host, source, _raw")
    max_events: int = Field(5000, ge=1, le=50000)
    # CTEM's high-fidelity alert feed, delivered on the box: to the local HEC, to a file a Universal Forwarder reads,
    # or both (api/core/alert_feed.py)
    forward_alerts: Literal["off", "hec", "file", "both"] = "off"
    hec_host: Host | None = None
    hec_port: Port = 8088
    hec_index: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,80}$")] | None = None


def _cron_ok(expr: str) -> str:
    """Five fields (minute hour day month weekday) of numbers, *, lists, ranges and steps, each within range."""
    parts = expr.split()
    if len(parts) != 5:
        raise ValueError("a cron schedule has five fields, like '30 2 * * *'")
    for spec, (lo, hi) in zip(parts, ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))):
        for part in spec.split(","):
            base, _, step = part.partition("/")
            if step and (not step.isdigit() or int(step) < 1):
                raise ValueError(f"bad step in {spec!r}")
            if base == "*":
                continue
            a, _, b = base.partition("-")
            if not a.isdigit() or (b and not b.isdigit()) or not lo <= int(a) <= int(b or a) <= hi:
                raise ValueError(f"{spec!r} is out of range")
    return " ".join(parts)


class NetProbeSettings(_Source):
    """Network discovery: ping and a TCP connect to common ports, on addresses nothing manages and their /24s."""
    cron: Annotated[str, StringConstraints(strip_whitespace=True, max_length=100, pattern=r"^[0-9*,/ -]+$")] = "0 2 * * *"
    ports: Annotated[str, StringConstraints(strip_whitespace=True, max_length=300, pattern=r"^[0-9, ]*$")] = (
        "21,22,23,25,53,80,110,135,139,143,443,445,1433,1521,3306,3389,5432,5900,5985,6379,8080,8443,9200")
    sweep_subnets: OnOff = "on"   # also try every address of those /24s, to find devices no tool knows
    exclude_cidrs: Annotated[str, StringConstraints(strip_whitespace=True, max_length=4000, pattern=r"^[0-9./,; ]*$")] = ""
    timeout_ms: int = Field(600, ge=100, le=3000)
    concurrency: int = Field(32, ge=4, le=64)
    max_hosts: int = Field(4096, ge=1, le=20000)

    @field_validator("cron")
    @classmethod
    def _cron(cls, v):
        return _cron_ok(v)

    @field_validator("ports")
    @classmethod
    def _ports(cls, v):
        got = [p for p in (x.strip() for x in v.split(",")) if p]
        if len(got) > 40 or any(not 0 < int(p) < 65536 for p in got):
            raise ValueError("up to 40 ports, each 1-65535")
        return ",".join(dict.fromkeys(got))

    @field_validator("exclude_cidrs")
    @classmethod
    def _nets(cls, v):
        import ipaddress
        nets = [c.strip() for c in v.replace(";", ",").split(",") if c.strip()]
        for c in nets:
            ipaddress.ip_network(c, strict=False)   # raises on anything that isn't a network
        return ",".join(nets)


SETTINGS = {"ldap": LdapSettings, "rapid7_console": Rapid7Settings,
            "crowdstrike": CrowdStrikeSettings, "splunk": SplunkSettings, "netprobe": NetProbeSettings}
# Anything that decides where a password goes, or what runs with it, needs a yes on the box
DEST_KEYS = {"ldap": ("host", "port", "tls"), "rapid7_console": ("host", "port"),
             "crowdstrike": ("cloud",), "splunk": ("host", "port", "query"),
             # what the network probe may touch and how: only ever changed with a yes on the box
             "netprobe": ("exclude_cidrs", "ports", "sweep_subnets")}
# Destinations added later count only once set, so existing approvals stay valid (the agent has the same rule)
DEST_EXTRA = {"crowdstrike": {"fdr_queue_url": ("fdr_queue_url",)}, "splunk": {"hec_host": ("hec_host", "hec_port")}}
SECRET_FIELDS = {"ldap": ("password",), "rapid7_console": ("password",),
                 "crowdstrike": ("client_secret", "fdr_secret_key"), "splunk": ("password", "hec_token"), "netprobe": ()}
SCHEDULES = (15, 30, 60, 120, 240, 360, 720, 1440)


def dest_digest(kind: str, settings: dict) -> str:
    # Must match the agent's copy byte for byte; tests check both
    dest = {k: settings.get(k) for k in DEST_KEYS[kind]}
    for anchor, keys in DEST_EXTRA.get(kind, {}).items():
        if settings.get(anchor):
            dest.update({k: settings.get(k) for k in keys})
    return hashlib.sha256(json.dumps([kind, dest], sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_settings(kind: str, raw: dict) -> dict:
    return SETTINGS[kind].model_validate(raw).model_dump()


def key_fingerprint(pem: str) -> str:
    """Validate a shipper public key and return the SHA-256 of its SubjectPublicKeyInfo."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072 or key.public_numbers().e != 65537:
        raise ValueError("shipper key must be RSA-3072 or larger")
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _b64(val, lo: int, hi: int) -> bytes:
    if not isinstance(val, str) or len(val) > 16384:
        raise ValueError("bad envelope")
    raw = base64.b64decode(val, validate=True)
    if not lo <= len(raw) <= hi:
        raise ValueError("bad envelope")
    return raw


def check_envelope(envelope: str, key_fp: str) -> None:
    """Shape check only; CTEM has no way to open it, which is the point."""
    if len(envelope) > 16384:
        raise ValueError("bad envelope")
    env = json.loads(envelope)
    if not isinstance(env, dict) or set(env) != {"v", "kid", "ek", "iv", "ct"} or env["v"] != 1:
        raise ValueError("bad envelope")
    if env["kid"] != key_fp:
        raise ValueError("sealed to a different shipper key")
    _b64(env["ek"], 384, 1024)
    _b64(env["iv"], 12, 12)
    _b64(env["ct"], 17, 8192)


def aad(collector_id: str, kind: str, field: str) -> str:
    # Binds a sealed secret to one shipper, source, and field so CTEM can't shuffle them around
    return f"octem-secret-v1|{collector_id}|{kind}|{field}"
