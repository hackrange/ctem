# Changelog

All notable changes to open-ctem are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

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
