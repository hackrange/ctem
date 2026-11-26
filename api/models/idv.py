"""Identity verification (IDV) requests: one row per Persona inquiry, whether Okta's own verification flow or the
service desk started it (api/integrations/persona.py).

Only what the person approved is kept: the state, the dates, the template, where the ID is from (state or province,
country), what kind of ID it was, and the device and network the check ran on (device type, OS and browser names,
VPN, proxy, Tor and datacenter flags, Persona's threat level). Never a name, birth date, address, ID number, photo,
selfie, IP address or GPS position: those stay in Persona."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from api.core.encryption import EncryptedJSON, EncryptedString
from api.models.base import Base, UUIDPrimaryKey

# Where a request stands in CTEM. "review" waits for cyber: Persona failed it or flagged it for a person to decide.
STATES = ("pending", "review", "approved", "rejected", "expired")


class IdvRequest(UUIDPrimaryKey, Base):
    __tablename__ = "idv_requests"

    inquiry_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)   # Persona's inq_...
    integration_id: Mapped[str | None] = mapped_column(String(36), index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    okta_id: Mapped[str | None] = mapped_column(String(40), index=True)             # Persona's reference-id
    state: Mapped[str] = mapped_column(String(16), index=True, default="pending")
    persona_status: Mapped[str | None] = mapped_column(String(32))
    template: Mapped[str | None] = mapped_column(String(256))
    template_id: Mapped[str | None] = mapped_column(String(64))
    # Persona's "creator": "API" when an API key started it (Okta's integration, CTEM's service desk). Only those
    # earn the IDV badge; one started from a hosted link could carry anyone's Okta id
    created_via: Mapped[str | None] = mapped_column(String(32))
    check_kind: Mapped[str | None] = mapped_column(String(12))   # what CTEM sent: id_selfie (government ID + selfie) or selfie
    facts: Mapped[dict | None] = mapped_column(EncryptedJSON)    # the approved fields above, nothing else
    origin: Mapped[str] = mapped_column(String(16), default="persona")   # persona (Okta's flow) | service_desk
    requested_by: Mapped[str | None] = mapped_column(String(36))          # the CTEM account or API token behind it
    channels: Mapped[list | None] = mapped_column(EncryptedJSON)          # how the link went out, and each result
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # A cyber or admin decision from CTEM's IDV page (also sent to Persona as approve or decline)
    reviewed_by: Mapped[str | None] = mapped_column(String(36))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    review_note: Mapped[str | None] = mapped_column(EncryptedString)
    review_reason: Mapped[str | None] = mapped_column(String(32))   # a code from api/integrations/persona_checks.py
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DeskEmbed(UUIDPrimaryKey, Base):
    """One place the caller verification panel may be shown (an admin makes it on the IDV page: Iframe Code).

    It names the exact site that may frame the panel, the server ranges its API token works from, and the network
    ranges analysts' browsers must use. Its token (ApiToken, IP-bound) belongs to the IDV desk service account and is
    shown once. Revoking it turns the token off and ends its open sessions."""
    __tablename__ = "idv_desk_embeds"

    name: Mapped[str] = mapped_column(String(80))
    frame_origin: Mapped[str] = mapped_column(String(256))
    server_ips: Mapped[list | None] = mapped_column(EncryptedJSON)
    client_ips: Mapped[list | None] = mapped_column(EncryptedJSON)
    token_id: Mapped[str | None] = mapped_column(String(36), index=True)
    created_by: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(String(128))


class DeskSession(UUIDPrimaryKey, Base):
    """One caller verification in the service desk's embedded panel (api/routes/desk_embed.py).

    ServiceNow's server starts it with an IP-bound API token and gets a one-time launch token (2 minutes, used once).
    The framed page trades that for a session key (30 minutes) usable only from the browser address that traded it.
    Only hashes of both are kept. The ticket and analyst come from ServiceNow's server, which the token vouches for."""
    __tablename__ = "idv_desk_sessions"

    launch_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_hash: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)
    token_id: Mapped[str | None] = mapped_column(String(36))          # the API token that started it
    embed_id: Mapped[str | None] = mapped_column(String(36), index=True)   # the embed that token belongs to
    started_by: Mapped[str | None] = mapped_column(String(36))        # that token's service account
    analyst: Mapped[str | None] = mapped_column(String(128))          # as ServiceNow names them (email or user id)
    ticket: Mapped[str | None] = mapped_column(String(40))
    caller_hint: Mapped[str | None] = mapped_column(EncryptedString)  # the ticket's caller, to prefill the search
    frame_origin: Mapped[str | None] = mapped_column(String(256))     # the ServiceNow origin the result is posted to
    client_ip: Mapped[str | None] = mapped_column(String(45))         # the analyst's browser, fixed at the exchange
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))   # the caller, once picked
    request_id: Mapped[str | None] = mapped_column(ForeignKey("idv_requests.id", ondelete="SET NULL"))
    lookups: Mapped[int] = mapped_column(default=0)
    launch_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    exchanged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
