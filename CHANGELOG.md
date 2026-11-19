# Changelog

All notable changes to open-ctem are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

### Security
- Client IPs can no longer be spoofed with `X-Forwarded-For`; API token IP binding and sign-in rate limits use the address nginx vetted. Upstream load balancers get a dedicated listener (`LB_BIND_IP:8085`)
- CSRF: Origin check on every cookie-authenticated write
- MFA: self-enrollment needs a verified code before it turns on, replacing an authenticator needs a current code, and MFA/password changes are browser-session only
- `MFA_REQUIRED=true` now enrolls users without TOTP at sign-in instead of locking them out
- Per-account cool-off after 10 failed passwords; no timing difference between unknown users and wrong passwords
- Locked accounts can no longer use their API tokens
- Stored XSS closed in hunt results, dashboard, CMDB, admin, and token views
- SSRF: AI model lookup goes through the guarded client; the vetted IP is pinned for every hop
- XML from Qualys and Palo Alto is parsed with defusedxml
- Ticket creation requires `findings:write`; vulnerability findings honor device-level access
- Integration secrets masked by name pattern; changing an endpoint requires re-entering credentials
- Errors no longer echo exception text or internal IPs; API docs hidden unless `DEBUG=true`
- Input validation on users, roles, branding, profile, hunt, and integration schedules
- Dependencies upgraded to clear all known advisories (FastAPI/Starlette, Authlib, cryptography, Pillow, Jinja2, python-multipart); python-jose replaced with PyJWT

### Fixed
- Celery worker had no database connection, so integrations never synced
- Splunk sync crashed on blank form fields; blank connector settings now mean "use the default"
- Threat page showed no alerts from any connector; Hunt catalog and AI answers never displayed
- Token revoke, GRC exceptions, and vulnerability/device findings returned 500s
- Sign-in after a typo failed CSRF; MFA users could not sign in at all
- Profile password change silently did nothing; profile and admin form fields were unstyled
- Chain scores pinned at 100, hiding pentest confirmation
- Beat container healthcheck always failed

### Changed
- Test and SBOM tooling moved to `requirements-dev.txt` so they no longer ship in the image
- CycloneDX SBOM added at `sbom.cdx.json`
- Example credentials declared in `.github/secret_scanning.yml` and `.gitleaks.toml`

### Added
- Cyber Threat module (cyber role only): aggregates alerts from all connected tools and uses AI to surface active threats
- GRC / FairTPRM integration: outbound risk export and inbound compliance evidence ingestion
- Zscaler ZIA/ZPA connector: network segmentation data feeds compensating control scoring
- Dashboard filter bar: Executive Owner, Technical Owner, Application, Environment all driven by tags
- Threat analysis AI endpoint: async Celery task, batched and cached to minimize token usage
- Push-to-SIEM endpoint: push enriched risk context back to Splunk or any configured SIEM via webhook
- Tanium connector: endpoint inventory, patch status, and Comply finding sync
- Splunk connector: notable event pull and HEC push for enriched risk data
- CrowdStrike connector: device sync and detection alert caching for the threat module
- LDAP connector: full user, computer, and group sync with tag assignment
- Vulnerabilities API: list, filter by KEV/CVSS, finding status updates with object-level authz
- Routes: auth, admin, devices, vulns, integrations, cmdb, threat, grc -- all wired into main.py
- Web UI templates: base layout with topbar/sidebar, login page, executive dashboard
- CSS theme system: fully customizable accent color via CSS variable, light/dark mode

## [1.0.1] - 2026-11-19

### Added
- Initial release of open-ctem
- FastAPI REST API with auto-generated OpenAPI docs at `/api/docs`
- OIDC/PKCE authentication supporting Okta, Entra ID, Keycloak, Google
- Break glass auth modes: `oidc_only`, `local_only`, `both` (env-controlled)
- Local login with Argon2id password hashing and TOTP (RFC 6238)
- TOTP brute force protection with progressive lockout and admin unlock
- Role-based access control with tag-scoped permissions
- Custom role creation and duplication
- AES-256-GCM column-level encryption for all PII and credentials
- HMAC-SHA256 indexed search on encrypted fields
- PostgreSQL 16 + TimescaleDB for telemetry and risk history
- Celery + Redis task queue for async integration sync jobs
- Security headers middleware (HSTS, CSP, X-Frame-Options, etc.)
- Timing-safe CSRF token protection
- Redis-backed rate limiting per IP and per user
- SSRF-safe outbound HTTP client with DNS pinning
- Risk scoring engine: composite score (EPSS + KEV + CVSS + reachability + controls)
- A-F risk grades for users and devices with percentage display
- CVE chain detection with MITRE ATT&CK technique correlation
- Compensating control score modifiers (firewall, EDR, NodeZero validation)
- Tag system pulling from LDAP OUs, Qualys groups, CrowdStrike host groups, manual
- Tag-based RBAC scope: groups see only assets matching their assigned tags
- ServiceNow integration: ticket creation, search, CMDB JSON export
- CMDB export endpoint for ServiceNow import sets
- Integration framework with connectors for 18+ security vendors
- Responsive web UI with light/dark theme
- Fully customizable branding: name, logo, favicon, accent color
- Docker Compose deployment with PostgreSQL, Redis, Celery, Nginx
- CycloneDX SBOM generation
- Pre-commit security and functional validation script
