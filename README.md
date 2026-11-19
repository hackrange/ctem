# open-ctem

**Continuous Threat Exposure Management** -- open source, risk-based, built to outclass every commercial CTEM product.

> Author: Tim Rice &lt;tim.j.rice@hackrange.com&gt;  
> Version: 1.0.1  
> License: MIT

---

## What it does

open-ctem continuously discovers, prioritizes, validates, and mobilizes remediation of real exposure across your entire environment. Unlike compliance scanners that report CVE counts, open-ctem scores **reachability** -- whether an attacker can actually exploit a finding given your compensating controls, network segmentation, and EDR posture.

**Risk score formula:**

```
score = (CVSS × 0.25) + (EPSS × 0.30) + (KEV × 0.20) + (asset_criticality × 0.15) + (reachability × 0.10)
```

Multipliers applied for: NodeZero-confirmed exploitability, internet exposure, no EDR, Zscaler/firewall segmentation, offline status.

---

## Features

| Capability | Detail |
|---|---|
| Risk grades | A-F with % for every device and user |
| CVE chaining | MITRE ATT&CK technique correlation detects multi-CVE attack paths |
| Compensating controls | Firewall, EDR, Zscaler, Guardicore policies auto-adjust scores |
| CISA KEV override | KEV findings always floor at 75/100 |
| NodeZero reachability | ×2.0 if confirmed exploitable, ×0.3 if confirmed safe |
| Identity blast radius | Privileged AD group membership raises user risk score |
| Tag-based RBAC | Groups see only assets matching their assigned tags |
| Object-level authz | Every GET-by-ID returns 404 for forbidden -- no enumeration oracle |
| AES-256-GCM encryption | All PII and credentials encrypted per-record with unique nonce |
| OIDC/PKCE + TOTP | Full SSO with break glass local auth and progressive lockout |
| Cyber Threat module | Aggregates alerts from all tools; AI analysis (async, cached) |
| Hunt module | Natural language AI queries across all telemetry sources |
| GRC / FairTPRM | Risk export and compliance evidence ingestion |
| CMDB export | ServiceNow import set format JSON |
| Full REST API | OpenAPI docs at `/api/docs` |
| Customizable branding | Logo, accent color, app title all configurable |

---

## Integrations

| Vendor | Type | Data pulled |
|---|---|---|
| LDAP / Active Directory | Identity | Users, computers, groups, GPOs |
| Qualys | Vulnerability | Findings, CVSS, asset data |
| Rapid7 InsightVM | Vulnerability | Findings, risk scores |
| Rapid7 AppSec | Vulnerability | Web app findings |
| Rapid7 CloudSec/CSPM | Cloud | Cloud posture findings |
| Horizon3 NodeZero | Pentest | Reachability validation |
| CrowdStrike Falcon | EDR + Threat | Devices, detections |
| SentinelOne | EDR | Devices, threat data |
| Tanium | Endpoint | Inventory, patch status, Comply findings |
| Guardicore | Microsegmentation | Block events, lateral movement |
| Splunk | SIEM | Notable events, SPL catalog |
| Microsoft Defender | EDR | Devices, alerts |
| Palo Alto Cortex XDR | EDR + Threat | Incidents, findings |
| Palo Alto NGFW | Firewall | Policy data, block events |
| Fortinet | Firewall | Policy data |
| Zscaler ZIA/ZPA | Network | Segmentation, access policy |
| Grip Security | SaaS | Shadow IT, SaaS risk |
| ServiceNow | ITSM + CMDB | Ticket creation, CMDB export |
| Snyk | AppSec | Code and container findings |
| GitHub Advanced Security | AppSec | SAST/secret scan findings |
| ForgeRepo | SCM | Repository security findings |
| AI (Anthropic) | Analysis | Risk narratives, threat analysis, hunt |

---

## Authentication modes

Set `AUTH_MODE` in `.env`:

| Mode | Behavior |
|---|---|
| `oidc_only` | Immediately redirects to IdP -- no login page shown |
| `local_only` | Username + password + TOTP only |
| `both` | Login page shows local form + SSO button |

TOTP brute force protection: 5 fails = 5 min lockout, 10 = 30 min, 15+ = hard lock with admin unlock required.

---

## Quick start

```bash
cp .env.example .env
# Edit .env with real values (generate keys with: python3 -c "import secrets; print(secrets.token_hex(32))")

cd docker
docker compose up -d

# App:   https://localhost
# Docs:  https://localhost/api/docs
```

Requirements: Docker 24+, Docker Compose v2.

---

## Role-based access

| Role | Access |
|---|---|
| `admin` | Everything -- user management, config, all data |
| `cyber` | All risk data, threat module, hunt, integrations (read) |
| `it_user` | Devices and findings scoped to their assigned tags |
| `business_stakeholder` | Dashboard and risk summary scoped to their tags |
| `read_only` | Dashboard only |

Roles are fully customizable -- create new ones, duplicate existing ones, assign granular permissions.

---

## Dashboards

The executive dashboard filters by tag category: **Executive Owner**, **Technical Owner**, **Application**, **Environment**, **Severity** -- all driven by the tag system. Each filter narrows the entire view to assets matching that tag combination.

---

## Security design

- No IDOR: every object fetch verifies ownership or tag-based access; returns 404 (not 403) for forbidden
- No BFLA: all state-changing routes re-check server-side role and permission
- No SQL injection: parameterized queries only via SQLAlchemy ORM
- No SSRF: DNS-pinned httpx transport blocks RFC 1918, loopback, link-local, and metadata IPs
- No secret leakage: generic error handler returns message + request ID only; details go to server logs
- CSRF: HMAC double-submit token on all browser POST routes
- Encryption: AES-256-GCM column encryption with per-record nonce; HMAC-SHA256 for indexed lookups
- Headers: HSTS, CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff

---

## Project layout

```
api/
  auth/        OIDC, local login, TOTP, RBAC middleware
  core/        Config, DB, encryption, SSRF client, Celery tasks, security middleware
  integrations/ Vendor connectors (one file per vendor)
  models/      SQLAlchemy ORM models
  routes/      FastAPI route handlers
  scoring/     Risk engine: compensating controls, CVE chains, device/user scores
  web/         Jinja2 templates + static assets
docker/        Dockerfile, docker-compose.yml, nginx.conf
```

---

## Contributing

Pre-ship checks run from `.claude/precheck.sh` (never committed). All contributions must pass the security precheck (0 failures) before merging.
