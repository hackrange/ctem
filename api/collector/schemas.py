"""Wire format for collector pushes. Unknown fields are dropped, everything is length-capped."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

MAX_BATCH = 1000

Short = Annotated[str, StringConstraints(strip_whitespace=True, max_length=256)]
DN = Annotated[str, StringConstraints(strip_whitespace=True, max_length=1024)]
Version = Annotated[str, StringConstraints(pattern=r"^[0-9A-Za-z.+-]{1,32}$")]
HostName = Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Za-z0-9._-]{1,253}$")]


class _Lax(BaseModel):
    model_config = ConfigDict(extra="ignore")


UPN = Annotated[str, StringConstraints(strip_whitespace=True, max_length=256, pattern=r"^[^\s@\x00-\x1f]+@[^\s@\x00-\x1f]+$")]


class LdapUser(_Lax):
    username: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256, pattern=r"^[^\x00-\x1f]+$")]
    email: Annotated[str, StringConstraints(strip_whitespace=True, max_length=320)] | None = None
    display_name: Short | None = None
    ad_dn: DN | None = None
    groups: list[DN] = Field(default_factory=list, max_length=5000)
    disabled: bool = False
    # AD account health; None means an older shipper didn't send it, so CTEM keeps what it had
    last_logon: datetime | None = None
    pwd_last_set: datetime | None = None
    pwd_expires: datetime | None = None
    pwd_expired: bool | None = None
    pwd_never_expires: bool | None = None
    locked_out: bool | None = None
    first_name: Short | None = None
    upn: UPN | None = None
    last_name: Short | None = None
    title: Short | None = None
    phone: Annotated[str, StringConstraints(strip_whitespace=True, max_length=64, pattern=r"^[^\x00-\x1f]+$")] | None = None
    mobile: Annotated[str, StringConstraints(strip_whitespace=True, max_length=64, pattern=r"^[^\x00-\x1f]+$")] | None = None
    country: Annotated[str, StringConstraints(pattern=r"^[A-Za-z]{2}$")] | None = None


class LdapComputer(_Lax):
    hostname: HostName
    fqdn: Annotated[str, StringConstraints(strip_whitespace=True, max_length=512)] | None = None
    ad_dn: DN | None = None
    os: Annotated[str, StringConstraints(strip_whitespace=True, max_length=128)] | None = None
    last_logon: datetime | None = None

    @field_validator("hostname", mode="before")
    @classmethod
    def _strip_dollar(cls, v):
        # AD machine accounts end in $, the hostname does not
        return v.rstrip("$") if isinstance(v, str) else v


class R7Os(_Lax):
    name: Short | None = None


class R7Tag(_Lax):
    type: Literal["custom", "location", "owner", "criticality"] = "custom"
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]


class R7Asset(_Lax):
    hostName: Annotated[str, StringConstraints(strip_whitespace=True, max_length=253)] | None = None
    ip: Annotated[str, StringConstraints(strip_whitespace=True, max_length=45)] | None = None
    os: Short | R7Os | None = None
    tags: list[R7Tag] | None = Field(None, max_length=100)  # None: an older shipper, keep existing tags


class R7Software(_Lax):
    """One software version the console found, and the assets it's on (hostnames or IPs)."""
    vendor: Annotated[str, StringConstraints(strip_whitespace=True, max_length=256)] | None = None
    product: Annotated[str, StringConstraints(strip_whitespace=True, max_length=256)] | None = None
    family: Annotated[str, StringConstraints(strip_whitespace=True, max_length=256)] | None = None
    version: Annotated[str, StringConstraints(strip_whitespace=True, max_length=128)] | None = None
    type: Annotated[str, StringConstraints(strip_whitespace=True, max_length=64)] | None = None
    cpe: Annotated[str, StringConstraints(strip_whitespace=True, max_length=256)] | None = None
    publisher: Annotated[str, StringConstraints(strip_whitespace=True, max_length=256)] | None = None
    install_path: Annotated[str, StringConstraints(strip_whitespace=True, max_length=512)] | None = None
    sha256: Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Fa-f0-9]{64}$")] | None = None
    md5: Annotated[str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Fa-f0-9]{32}$")] | None = None
    hosts: list[Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=253)]] = Field(
        default_factory=list, max_length=5000)


class R7Score(_Lax):
    score: float | None = Field(None, ge=0, le=10)


class R7Cvss(_Lax):
    v2: R7Score | None = None
    v3: R7Score | None = None


class R7Desc(_Lax):
    text: Annotated[str, StringConstraints(max_length=20000)] | None = None


class R7Vuln(_Lax):
    id: Annotated[str, StringConstraints(max_length=256)] | None = None
    title: Annotated[str, StringConstraints(max_length=512)] | None = None
    cves: list[Annotated[str, StringConstraints(pattern=r"^CVE-\d{4}-\d{4,}$")]] = Field(default_factory=list, max_length=200)
    cvss: R7Cvss | None = None
    description: Annotated[str, StringConstraints(max_length=20000)] | R7Desc | None = None


class _Signal(_Lax):
    kind: Literal["os", "sensor"]
    name: Annotated[str, StringConstraints(max_length=128, pattern=r"^[^<>\x00-\x1f]+$")]
    group: Annotated[str, StringConstraints(max_length=64, pattern=r"^[^<>\x00-\x1f]*$")] | None = None
    criteria: Annotated[str, StringConstraints(max_length=256, pattern=r"^[^<>\x00-\x1f]*$")] | None = None
    meets: Annotated[str, StringConstraints(max_length=16, pattern=r"^[A-Za-z_ -]*$")] | None = None


class CsPosture(_Lax):
    overall: Annotated[int, Field(ge=0, le=100)] | None = None
    os: Annotated[int, Field(ge=0, le=100)] | None = None
    sensor_config: Annotated[int, Field(ge=0, le=100)] | None = None
    at: Annotated[str, StringConstraints(max_length=40, pattern=r"^[0-9T:.+Z -]*$")] | None = None
    signals: list[_Signal] = Field(default_factory=list, max_length=120)


class CsDevice(_Lax):
    device_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{32}$")] | None = None
    hostname: Annotated[str, StringConstraints(strip_whitespace=True, max_length=253)] | None = None
    status: Annotated[str, StringConstraints(max_length=32)] | None = None
    last_seen: datetime | None = None   # when Falcon last heard from the sensor
    hidden: bool | None = None          # hidden in the Falcon console
    os_version: Annotated[str, StringConstraints(strip_whitespace=True, max_length=128)] | None = None
    last_login_user: Annotated[str, StringConstraints(strip_whitespace=True, max_length=256, pattern=r"^[^\x00-\x1f]+$")] | None = None
    product_type: Annotated[str, StringConstraints(strip_whitespace=True, max_length=64, pattern=r"^[^\x00-\x1f]+$")] | None = None
    firewall_enabled: bool | None = None
    usb_storage_blocked: bool | None = None
    prevention_policy_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{32}$")] | None = None
    firewall_policy_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{32}$")] | None = None
    usb_policy_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{32}$")] | None = None
    posture: CsPosture | None = None    # Falcon Zero Trust Assessment, every few hours
    recent_logins: list[Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256, pattern=r"^[^\x00-\x1f]+$")]] | None = Field(None, max_length=20)

    @field_validator("last_seen", mode="before")
    @classmethod
    def _seen(cls, v):
        """An unreadable time is dropped, not a reason to refuse the whole batch."""
        if not isinstance(v, str) or len(v) > 40:
            return None
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None


class CsHost(_Lax):
    hostname: Annotated[str, StringConstraints(strip_whitespace=True, max_length=253)] | None = None
    device_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{32}$")] | None = None


class CsBehavior(_Lax):
    description: Annotated[str, StringConstraints(max_length=2000)] | None = None


class CsDetection(_Lax):
    detection_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9:_.-]{1,200}$")]
    max_severity_displayname: Annotated[str, StringConstraints(max_length=32)] | None = None
    tactic: Annotated[str, StringConstraints(max_length=128)] | None = None
    technique: Annotated[str, StringConstraints(max_length=128)] | None = None
    title: Annotated[str, StringConstraints(max_length=300, pattern=r"^[^\x00-\x1f]+$")] | None = None
    status: Annotated[str, StringConstraints(max_length=32, pattern=r"^[A-Za-z_ -]+$")] | None = None
    detected_at: datetime | None = None
    tactic_id: Annotated[str, StringConstraints(pattern=r"^TA\d{4}$")] | None = None
    technique_id: Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")] | None = None
    link: Annotated[str, StringConstraints(max_length=1000, pattern=r"^https://falcon(\.[a-z0-9-]+)*\.crowdstrike\.com/[^\s\"'<>]*$")] | None = None
    device: CsHost | None = None
    behaviors: list[CsBehavior] = Field(default_factory=list, max_length=20)
    # Process tree, actions taken, IOCs, network and DNS; rebuilt key by key by collector_cs_alert.clean()
    detail: dict | None = None

    @field_validator("detail")
    @classmethod
    def _detail_size(cls, v):
        import json
        if v is not None and len(json.dumps(v, default=str)) > 200_000:
            raise ValueError("alert detail too large")
        return v


FieldKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")]
FieldVal = Annotated[str, StringConstraints(max_length=8192)]


class SplunkIndex(_Lax):
    name: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,80}$")]
    totalEventCount: int | None = Field(None, ge=0)
    currentDBSizeMB: float | None = Field(None, ge=0)
    minTime: Annotated[str, StringConstraints(max_length=40)] | None = None
    maxTime: Annotated[str, StringConstraints(max_length=40)] | None = None


Warning = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300,
                                           pattern=r"^[^<>\x00-\x1f]*$")]


class _Batch(_Lax):
    run_id: uuid.UUID
    final: bool = False
    warnings: list[Warning] = Field(default_factory=list, max_length=10)   # shown on the integration card


class LdapBatch(_Batch):
    kind: Literal["ldap"]
    users: list[LdapUser] = Field(default_factory=list, max_length=MAX_BATCH)
    computers: list[LdapComputer] = Field(default_factory=list, max_length=MAX_BATCH)


class Rapid7Batch(_Batch):
    kind: Literal["rapid7_console"]
    assets: list[R7Asset] = Field(default_factory=list, max_length=MAX_BATCH)
    vulnerabilities: list[R7Vuln] = Field(default_factory=list, max_length=MAX_BATCH)
    software: list[R7Software] = Field(default_factory=list, max_length=MAX_BATCH)   # newer shippers


Txt = lambda n: Annotated[str, StringConstraints(strip_whitespace=True, max_length=n, pattern=r"^[^<>\x00-\x1f]*$")]  # noqa: E731
Hex32 = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{32}$")]
Word = Annotated[str, StringConstraints(max_length=48, pattern=r"^[A-Za-z0-9_ .:-]*$")]


class _PolicySetting(_Lax):
    name: Txt(96) | None = None
    category: Txt(64) | None = None
    value: bool | Word | None = None


class _FwRule(_Lax):
    name: Txt(128) | None = None
    description: Txt(256) | None = None
    enabled: bool = False
    action: Word | None = None
    direction: Word | None = None
    protocol: Word | None = None
    local_address: list[Annotated[str, StringConstraints(max_length=49, pattern=r"^[0-9a-fA-F:.*/]+$")]] = Field(default_factory=list, max_length=50)
    remote_address: list[Annotated[str, StringConstraints(max_length=49, pattern=r"^[0-9a-fA-F:.*/]+$")]] = Field(default_factory=list, max_length=50)
    local_port: list[tuple[Annotated[int, Field(ge=0, le=65535)], Annotated[int, Field(ge=0, le=65535)]]] = Field(default_factory=list, max_length=50)
    remote_port: list[tuple[Annotated[int, Field(ge=0, le=65535)], Annotated[int, Field(ge=0, le=65535)]]] = Field(default_factory=list, max_length=50)
    monitor_only: bool = False


class _UsbAllowed(_Lax):
    match: Word | None = None
    vendor_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{1,8}$")] | None = None
    vendor: Txt(128) | None = None
    product_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{1,8}$")] | None = None
    product: Txt(128) | None = None
    serial: Txt(128) | None = None
    action: Word | None = None
    description: Txt(256) | None = None
    expires: Annotated[str, StringConstraints(max_length=40, pattern=r"^[0-9T:.+Z -]*$")] | None = None


class _UsbClass(_Lax):
    id: Word
    action: Word | None = None
    allowed: list[_UsbAllowed] = Field(default_factory=list, max_length=500)


class EdrPolicyIn(_Lax):
    """A prevention, firewall or device control policy, sent once per run; hosts point at it by id."""
    id: Hex32
    kind: Literal["prevention", "firewall", "device_control"]
    name: Txt(128) | None = None
    enabled: bool = False
    platform: Txt(32) | None = None
    settings: dict[Annotated[str, StringConstraints(max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")], _PolicySetting] = Field(default_factory=dict, max_length=120)
    enforce: bool | None = None
    test_mode: bool | None = None
    default_inbound: Word | None = None
    default_outbound: Word | None = None
    rules: list[_FwRule] = Field(default_factory=list, max_length=2000)
    enforcement: Word | None = None
    classes: list[_UsbClass] = Field(default_factory=list, max_length=40)


CveId = Annotated[str, StringConstraints(pattern=r"^CVE-\d{4}-\d{4,}$")]
Long = Annotated[str, StringConstraints(max_length=4000, pattern=r"^[^<>\x00-\x08\x0b-\x1f]*$")]


class SpotlightCve(_Lax):
    id: CveId
    name: Txt(512) | None = None
    description: Long | None = None
    base_score: Annotated[float, Field(ge=0, le=10)] | None = None
    severity: Word | None = None
    vector: Annotated[str, StringConstraints(max_length=256, pattern=r"^[A-Za-z0-9:/.]*$")] | None = None
    exprt_rating: Word | None = None
    exploit_status: Annotated[int, Field(ge=0, le=1000)] | None = None
    is_kev: bool = False
    published: Annotated[str, StringConstraints(max_length=40, pattern=r"^[0-9T:.+Z -]*$")] | None = None
    actors: list[Txt(128)] = Field(default_factory=list, max_length=20)
    cwes: list[Word] = Field(default_factory=list, max_length=10)


class _Remedy(_Lax):
    title: Txt(256) | None = None
    action: Annotated[str, StringConstraints(max_length=1000, pattern=r"^[^<>\x00-\x08\x0b-\x1f]*$")] | None = None
    link: Annotated[str, StringConstraints(max_length=500, pattern=r"^https://[^\s<>\"']+$")] | None = None


class SpotlightVuln(_Lax):
    id: Annotated[str, StringConstraints(max_length=128, pattern=r"^[A-Za-z0-9_:.-]+$")] | None = None
    aid: Hex32
    hostname: Annotated[str, StringConstraints(strip_whitespace=True, max_length=253, pattern=r"^[^<>\x00-\x1f]+$")] | None = None
    status: Word | None = None
    cve_id: CveId
    created: Annotated[str, StringConstraints(max_length=40, pattern=r"^[0-9T:.+Z -]*$")] | None = None
    updated: Annotated[str, StringConstraints(max_length=40, pattern=r"^[0-9T:.+Z -]*$")] | None = None
    closed: Annotated[str, StringConstraints(max_length=40, pattern=r"^[0-9T:.+Z -]*$")] | None = None
    apps: list[Txt(200)] = Field(default_factory=list, max_length=5)
    remediation: list[_Remedy] = Field(default_factory=list, max_length=3)

    @field_validator("remediation", mode="before")
    @classmethod
    def _links(cls, v):
        """A remediation link that isn't plain https is dropped, not a reason to refuse the batch."""
        out = []
        for r in v or []:
            if isinstance(r, dict) and r.get("link") and not str(r["link"]).startswith("https://"):
                r = {**r, "link": None}
            out.append(r)
        return out


Stamp = Annotated[str, StringConstraints(max_length=40, pattern=r"^[0-9T:.+Z -]*$")]
Val = Annotated[str, StringConstraints(max_length=512, pattern=r"^[^\x00-\x1f]+$")]
_Flat = dict[Annotated[str, StringConstraints(max_length=64, pattern=r"^[A-Za-z0-9_]+$")],
             Annotated[str, StringConstraints(max_length=1000, pattern=r"^[^\x00-\x08\x0b-\x1f]*$")] | None]


class IntelIn(_Lax):
    value: Val
    type: Word
    confidence: Word | None = None
    actors: list[Txt(128)] = Field(default_factory=list, max_length=10)
    malware: list[Txt(128)] = Field(default_factory=list, max_length=10)
    labels: list[Txt(64)] = Field(default_factory=list, max_length=10)
    published: Stamp | None = None
    updated: Stamp | None = None


class StreamEventIn(_Lax):
    partition: Annotated[str, StringConstraints(pattern=r"^[0-9a-zA-Z]{1,16}$")]
    offset: Annotated[int, Field(ge=0, le=2**62)]
    type: Word
    at: Stamp | None = None
    hostname: Txt(253) | None = None
    user: Txt(256) | None = None
    severity: Word | None = None
    summary: Annotated[str, StringConstraints(max_length=500, pattern=r"^[^\x00-\x08\x0b-\x1f]*$")] | None = None
    event: _Flat = Field(default_factory=dict, max_length=60)


class HuntStackIn(_Lax):
    day: Annotated[str, StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}$")]
    kind: Literal["process", "dns", "network", "logon", "logon_failed"]
    key: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    value: Val
    sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")] | None = None
    fields: _Flat = Field(default_factory=dict, max_length=10)
    hosts: list[Hex32] = Field(default_factory=list, max_length=200)
    events: Annotated[int, Field(ge=0, le=10**9)] = 0
    first_seen: Stamp | None = None
    last_seen: Stamp | None = None


class CrowdStrikeBatch(_Batch):
    kind: Literal["crowdstrike"]
    devices: list[CsDevice] = Field(default_factory=list, max_length=MAX_BATCH)
    detections: list[CsDetection] = Field(default_factory=list, max_length=MAX_BATCH)
    edr_policies: list[EdrPolicyIn] = Field(default_factory=list, max_length=500)
    spotlight_cves: list[SpotlightCve] = Field(default_factory=list, max_length=MAX_BATCH)
    spotlight: list[SpotlightVuln] = Field(default_factory=list, max_length=MAX_BATCH)
    spotlight_mode: Literal["full", "incremental"] | None = None
    software: list[R7Software] = Field(default_factory=list, max_length=MAX_BATCH)   # Discover applications
    intel: list[IntelIn] = Field(default_factory=list, max_length=5000)
    stream_events: list[StreamEventIn] = Field(default_factory=list, max_length=MAX_BATCH)
    hunt: list[HuntStackIn] = Field(default_factory=list, max_length=5000)


class SplunkBatch(_Batch):
    kind: Literal["splunk"]
    events: list[dict[FieldKey, FieldVal]] = Field(default_factory=list, max_length=MAX_BATCH)
    indexes: list[SplunkIndex] | None = Field(None, max_length=1000)


Kind = Literal["ldap", "rapid7_console", "crowdstrike", "splunk"]
PublicKey = Annotated[str, StringConstraints(min_length=200, max_length=4096, pattern=r"^-----BEGIN PUBLIC KEY-----[A-Za-z0-9+/=\s]+-----END PUBLIC KEY-----\s*$")]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class EnrollRequest(_Lax):
    code: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    hostname: HostName
    agent_version: Version
    public_key: PublicKey


class LoginCheckRequest(_Lax):
    username: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=1024)]


class LoginEnrollRequest(LoginCheckRequest):
    """Generic installer path: the box describes its own profile, then enrolls."""
    totp: Annotated[str, StringConstraints(pattern=r"^[0-9]{6,8}$")] | None = None
    name: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]{1,64}$")]
    hostname: HostName
    agent_version: Version
    public_key: PublicKey
    schedule_minutes: int = 60
    modules: dict[Kind, dict] = Field(min_length=1, max_length=4)


class CheckinRequest(_Lax):
    hostname: HostName
    agent_version: Version
    approved: dict[Kind, Digest] = Field(default_factory=dict, max_length=4)
    errors: dict[Kind, Annotated[str, StringConstraints(max_length=300)]] = Field(default_factory=dict, max_length=4)
    ran: bool = False  # true only on the check-in that follows a real run


class SealedSecret(_Lax):
    kind: Kind
    field: Annotated[str, StringConstraints(pattern=r"^[a-z_]{1,32}$")]
    envelope: Annotated[str, StringConstraints(min_length=20, max_length=16384)]


class SecretsUpload(_Lax):
    secrets: list[SealedSecret] = Field(min_length=1, max_length=8)
