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
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
