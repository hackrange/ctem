# open-ctem

A risk-based Continuous Threat Exposure Management platform.

**Author:** Tim Rice \<tim.j.rice@hackrange.com\>
**Version:** 1.0.1
**License:** MIT

---

## What it is

open-ctem is not another CVE list. It answers: *"Which of my vulnerabilities can actually be exploited right now, by a real attacker, against a real asset that matters?"*

It pulls data from your vulnerability scanners, EDR, firewalls, Active Directory, penetration testing tools, and SaaS security platforms, then fuses them into a risk score that accounts for reachability, compensating controls, CVE chaining, and identity blast radius.

Each user and device gets an A-F grade. The score explains itself -- hover to see exactly what drove it up or down.

---

## Quick start

```bash
# 1. Copy and fill in environment variables
cp .env.example .env
# Edit .env with your real values (database, secrets, OIDC config)

# 2. Generate encryption keys
python3 -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_hex(32))"
python3 -c "import secrets; print('ENCRYPTION_SEARCH_KEY=' + secrets.token_hex(32))"
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"

# 3. Start
docker compose -f docker/docker-compose.yml up -d

# 4. App is available at https://localhost
```

---

## Authentication modes

Set `AUTH_MODE` in `.env`:

| Mode | Behavior |
|------|----------|
| `oidc_only` | Login page immediately redirects to your IdP. No form, no button. |
| `local_only` | Username + password + TOTP only. Use as break glass when IdP is down. |
| `both` | Local form + OIDC option. Default. |

The env var always wins over any database setting -- useful when OIDC is broken and you need to bypass it without touching the DB.

---

## REST API

API documentation is auto-generated at `/api/docs` (Swagger UI) and `/api/redoc`.

All endpoints are under `/api/v1/`. Authentication via Bearer JWT.

```bash
# Get a token
curl -X POST /api/v1/auth/token \
  -d '{"username": "admin", "password": "...", "totp_code": "123456"}'

# Use it
curl -H "Authorization: Bearer <token>" /api/v1/devices
```

---

## Integrations

Configure integrations at **Settings > Integrations**. Supported:

- **Vulnerability scanners:** Qualys, Rapid7 InsightVM, Rapid7 InsightAppSec, Rapid7 InsightCloudSec, Microsoft Defender
- **EDR / XDR:** CrowdStrike, SentinelOne, Palo Alto Cortex XDR, Tanium, Horizon3 NodeZero
- **Network / Firewall:** Palo Alto NGFW, Fortinet, Guardicore
- **Identity:** LDAPS / Active Directory (users, computers, GPOs), Grip Security
- **Code security:** Snyk, GitHub Advanced Security, ForgeRepo
- **ITSM:** ServiceNow (tickets + CMDB export)
- **SIEM:** Splunk
- **AI analysis:** Anthropic Claude, OpenAI

---

## Risk scoring

```
Score = (CVSS * 0.25) + (EPSS * 0.30) + (KEV * 0.20) + (asset_criticality * 0.15) + (reachability * 0.10)
```

Multipliers:
- x2.0 if NodeZero confirms exploitable chain
- x1.5 if internet-exposed
- x0.5 if host firewall blocks the attack vector
- x0.3 if NodeZero confirms NOT exploitable

| Grade | Score | Action |
|-------|-------|--------|
| A | 0-20 | Monitor |
| B | 21-40 | Remediate in 90 days |
| C | 41-60 | Remediate in 30 days |
| D | 61-80 | Remediate in 7 days |
| F | 81-100 | Immediate action |

---

## Security

This platform assumes the database can be breached. All PII, credentials, and sensitive fields are AES-256-GCM encrypted before they touch the database. The application key is required to read them.

Security headers, CSRF protection, rate limiting, SSRF-safe outbound fetches, and object-level authorization are enforced by default.

---

## SBOM

A CycloneDX SBOM is generated at build time: `sbom.cyclonedx.json`

---

## Development

```bash
pip install -r requirements.txt
uvicorn api.main:app --reload
```

Tests:
```bash
pytest tests/
```
