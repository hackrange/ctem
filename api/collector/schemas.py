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


class LdapUser(_Lax):
    username: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256, pattern=r"^[^\x00-\x1f]+$")]
    email: Annotated[str, StringConstraints(strip_whitespace=True, max_length=320)] | None = None
    display_name: Short | None = None
    ad_dn: DN | None = None
    groups: list[DN] = Field(default_factory=list, max_length=5000)
    disabled: bool = False


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


class R7Asset(_Lax):
    hostName: Annotated[str, StringConstraints(strip_whitespace=True, max_length=253)] | None = None
    ip: Annotated[str, StringConstraints(strip_whitespace=True, max_length=45)] | None = None
    os: Short | R7Os | None = None


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


class CsDevice(_Lax):
    device_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{32}$")] | None = None
    hostname: Annotated[str, StringConstraints(strip_whitespace=True, max_length=253)] | None = None
    status: Annotated[str, StringConstraints(max_length=32)] | None = None
    os_version: Annotated[str, StringConstraints(strip_whitespace=True, max_length=128)] | None = None
    last_login_user: Annotated[str, StringConstraints(strip_whitespace=True, max_length=256, pattern=r"^[^\x00-\x1f]+$")] | None = None
    product_type: Annotated[str, StringConstraints(strip_whitespace=True, max_length=64, pattern=r"^[^\x00-\x1f]+$")] | None = None


class CsHost(_Lax):
    hostname: Annotated[str, StringConstraints(strip_whitespace=True, max_length=253)] | None = None


class CsBehavior(_Lax):
    description: Annotated[str, StringConstraints(max_length=2000)] | None = None


class CsDetection(_Lax):
    detection_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9:_.-]{1,200}$")]
    max_severity_displayname: Annotated[str, StringConstraints(max_length=32)] | None = None
    tactic: Annotated[str, StringConstraints(max_length=128)] | None = None
    technique: Annotated[str, StringConstraints(max_length=128)] | None = None
    device: CsHost | None = None
    behaviors: list[CsBehavior] = Field(default_factory=list, max_length=20)


FieldKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")]
FieldVal = Annotated[str, StringConstraints(max_length=8192)]


class SplunkIndex(_Lax):
    name: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,80}$")]
    totalEventCount: int | None = Field(None, ge=0)
    currentDBSizeMB: float | None = Field(None, ge=0)
    minTime: Annotated[str, StringConstraints(max_length=40)] | None = None
    maxTime: Annotated[str, StringConstraints(max_length=40)] | None = None


class _Batch(_Lax):
    run_id: uuid.UUID
    final: bool = False


class LdapBatch(_Batch):
    kind: Literal["ldap"]
    users: list[LdapUser] = Field(default_factory=list, max_length=MAX_BATCH)
    computers: list[LdapComputer] = Field(default_factory=list, max_length=MAX_BATCH)


class Rapid7Batch(_Batch):
    kind: Literal["rapid7_console"]
    assets: list[R7Asset] = Field(default_factory=list, max_length=MAX_BATCH)
    vulnerabilities: list[R7Vuln] = Field(default_factory=list, max_length=MAX_BATCH)


class CrowdStrikeBatch(_Batch):
    kind: Literal["crowdstrike"]
    devices: list[CsDevice] = Field(default_factory=list, max_length=MAX_BATCH)
    detections: list[CsDetection] = Field(default_factory=list, max_length=MAX_BATCH)


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
