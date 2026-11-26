from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str
    redis_url: str = "redis://redis:6379/0"

    # ── Secrets (all required -- no defaults so we fail loud at startup) ──────
    secret_key: str
    encryption_key: str
    encryption_search_key: str

    # ── Auth mode ─────────────────────────────────────────────────────────────
    auth_mode: Literal["oidc_only", "local_only", "both"] = "both"
    mfa_required: bool = True

    # ── OIDC ──────────────────────────────────────────────────────────────────
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_redirect_uri: str | None = None
    oidc_scopes: str = "openid profile email groups"
    oidc_group_claim: str = "groups"

    # ── JWT / sessions ────────────────────────────────────────────────────────
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    # A browser sign-in renews while in use and ends after access_token_expire_minutes idle, but never lasts longer
    # than this from sign-in
    session_max_hours: int = 12

    # ── TOTP lockout ──────────────────────────────────────────────────────────
    totp_lockout_threshold_1: int = 5
    totp_lockout_minutes_1: int = 5
    totp_lockout_threshold_2: int = 10
    totp_lockout_minutes_2: int = 30
    totp_lockout_threshold_3: int = 15
    initial_password_hours: int = 72   # how long a password an admin set works before its first sign-in replaces it
    # above threshold_3: account hard-locked, admin must unlock

    # IP-level rate limit: max auth attempts per window
    ip_auth_max_attempts: int = 20
    ip_auth_window_seconds: int = 600

    # ── Admin > Maintenance (the host agent's folders are mounted here) ──────
    maintenance_dir: str = "/srv/ctem"
    maintenance_ui_restore: bool = True       # MAINTENANCE_UI_RESTORE=false keeps restores on the command line
    maintenance_upload_max_gb: int = Field(50, ge=1, le=1024)

    # ── App ───────────────────────────────────────────────────────────────────
    app_env: Literal["development", "production"] = "production"
    debug: bool = False
    allowed_hosts: str = "localhost"
    # Public https URL baked into collector installers; falls back to the first allowed host
    public_url: str | None = None
    # The reverse proxy whose X-Forwarded-For / -Proto are believed (a hostname; empty = none). See api/core/trusted_proxy.py
    trusted_proxy_host: str = Field("", max_length=253, pattern=r"^[A-Za-z0-9.-]*$")
    app_version: str = "1.15.0"
    # Country assumed for directory phone numbers with no country of their own (ISO 3166 alpha-2)
    phone_default_region: str = Field("US", pattern=r"^[A-Za-z]{2}$")
    # Comma-separated prefixes of admin/alt accounts that belong to a person (sulocal_jdoe -> jdoe)
    account_alias_prefixes: str = Field("sulocal_", max_length=512, pattern=r"^[A-Za-z0-9_.,-]*$")
    # A host no tool has seen in this many days, that doesn't answer the network probe either, loses its findings
    stale_host_days: int = Field(30, ge=7, le=365)

    # ── Email ─────────────────────────────────────────────────────────────────
    # EMAIL_MODE: smtp | ms365 | disabled
    email_mode: Literal["smtp", "ms365", "disabled"] = "disabled"

    # SMTP settings (used when email_mode=smtp)
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "open-ctem@example.com"
    smtp_tls: bool = True                      # True=STARTTLS, port 465 uses implicit TLS

    # Microsoft 365 Graph API (used when email_mode=ms365)
    ms365_tenant_id: str | None = None
    ms365_client_id: str | None = None
    ms365_client_secret: str | None = None
    ms365_from_address: str | None = None      # UPN of the mailbox to send from

    # ServiceNow inbound email (optional -- used when creating tickets via email)
    servicenow_inbound_email: str | None = None

    # ── AI ────────────────────────────────────────────────────────────────────
    ai_api_key: str | None = None
    ai_model: str = "claude-haiku-5-5"

    # ── Threat intel enrichment (CISA KEV + FIRST EPSS); off for air-gapped installs
    threat_feeds_enabled: bool = True

    # ── Default branding (overridden per-deployment via DB settings) ──────────
    default_app_name: str = "open-ctem"

    # ── First-boot seeding (cleared / left as-is after first run) ────────────
    initial_admin_user: str | None = None
    initial_admin_pass: str | None = None

    @field_validator("encryption_key", "encryption_search_key")
    @classmethod
    def _must_be_32_bytes_hex(cls, v: str) -> str:
        # 32 bytes = 64 hex chars -- bail early so the error is obvious
        clean = v.strip()
        if len(clean) != 64:
            raise ValueError("must be 64 hex characters (32 bytes)")
        try:
            bytes.fromhex(clean)
        except ValueError:
            raise ValueError("must be valid hexadecimal")
        return clean

    @field_validator("oidc_issuer", mode="before")
    @classmethod
    def _require_oidc_when_needed(cls, v: str | None, info: object) -> str | None:
        # Actual check at startup in main.py where auth_mode is also available
        return v

    @property
    def allowed_hosts_list(self) -> list[str]:
        return [h.strip() for h in self.allowed_hosts.split(",") if h.strip()]

    @property
    def encryption_key_bytes(self) -> bytes:
        return bytes.fromhex(self.encryption_key)

    @property
    def encryption_search_key_bytes(self) -> bytes:
        return bytes.fromhex(self.encryption_search_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
