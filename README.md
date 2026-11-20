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
| KEV + EPSS enrichment | Daily CISA KEV flags and FIRST EPSS scores, refreshed again after every sync (`THREAT_FEEDS_ENABLED=false` to turn off) |
| Drill-down lists | Device and vulnerability lists with server-side paging, sorting, search, and detail pages (devices -> findings, vulnerabilities -> affected devices) |
| CSV export | Every list exports all matching rows with its current filters and sort; formula-injection safe |
| No indexing | `X-Robots-Tag` noindex/noai on every response, robots meta on every page, `/robots.txt` disallows all crawlers including AI crawlers |
| NodeZero reachability | ×2.0 if confirmed exploitable, ×0.3 if confirmed safe |
| Identity blast radius | Privileged AD group membership raises user risk score |
| Tag-based RBAC | Groups see only assets matching their assigned tags |
| Object-level authz | Every GET-by-ID returns 404 for forbidden -- no enumeration oracle |
| AES-256-GCM encryption | All PII and credentials encrypted per-record with unique nonce |
| OIDC/PKCE + TOTP | Full SSO with break glass local auth and progressive lockout |
| Cyber Threat module | Aggregates alerts from all tools; AI analysis (async, cached) |
| Hunt module | Natural language AI queries across all telemetry sources |
| GRC / FairTPRM | Risk export and compliance evidence ingestion |
| CMDB | Every device, server-side paged with search, type filter and sorting; full ServiceNow import set JSON export |
| Full REST API | OpenAPI docs at `/api/docs` (served only when `DEBUG=true`) |
| Customizable branding | Logo, accent color, app title all configurable |

---

## Integrations

Every source is matched to the same device row by host name, however it spells it: `DESKTOP001` (CrowdStrike, AD), `desktop001.ad.acme.example` (Rapid7) and `desktop001$` all land on one device, so EDR, AD, vulnerability and last-user data show up together. A parent and child domain count as one (`ad.acme.example` ~ `acme.example`). A bare short name goes to the AD-joined record, or else the fleet's main domain. Two hosts with the same short name in unrelated domains stay separate. The inventory shows one uppercase short host name per device with a **Sources** column (CS, R7, AD, ...) and a type icon; the FQDN is on the device page and the CSV export has both Hostname and FQDN columns. Hosts that CrowdStrike has network-contained are flagged **Contained**: their findings show as info with a zero score until containment is lifted, with the original score shown beside the adjusted one. After upgrading, run `docker compose exec app python -m api.maintenance.backfill_sources` once to fill Sources for existing devices. Web apps and cloud resources are never matched to hosts by name. Upgrading from an earlier build that already made duplicates? Run `docker compose exec app python -m api.maintenance.merge_devices` to preview, then add `--apply` (back up the database first).

| Vendor | Type | Data pulled |
|---|---|---|
| LDAP / Active Directory | Identity | Users (incl. last logon, password age/expiry, lockout, disabled), computers, groups, GPOs |
| Qualys | Vulnerability | Findings, CVSS, asset data |
| Rapid7 InsightVM | Vulnerability | Assets and per-asset findings (cloud v4 API or on-prem console) |
| Rapid7 InsightAppSec | Vulnerability | Web app findings with triage status |
| Rapid7 InsightCloudSec | Cloud | Cloud posture findings |
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

### Rapid7 endpoints

One Insight Platform API key (an organization or user key) can cover several Rapid7 products. Pick the region your org lives in; the connectors only talk to `https://<region>.api.insight.rapid7.com` for `us`, `us2`, `us3`, `eu`, `ca`, `au`, or `ap`.

| Product | Base URL | Auth |
|---|---|---|
| InsightAppSec | `https://<region>.api.insight.rapid7.com/ias/v1` | `X-Api-Key` |
| InsightVM (cloud) | `https://<region>.api.insight.rapid7.com/vm/v4/integration` | `X-Api-Key` |
| InsightVM (on-prem console) | `https://<console-host>:3780/api/3` | Basic (console user) |
| InsightCloudSec (CSPM) | Your tenant host, e.g. `https://us1.cloudsec.insight.rapid7.com` (Command Platform tenants; older standalone installs use their own URL). `/v2` is added for you | `Api-Key` (a Cloud Security key: Command Platform > Administration > Cloud Security > Profile, or an API-only user; Insight Platform keys are not accepted, and a bad key gets a 302 to the Rapid7 logout page) |

Quick key check: `GET https://<region>.api.insight.rapid7.com/validate` returns 200 for any valid key, in any region, so use a product call (e.g. `GET /ias/v1/apps?size=1`) to confirm the region and product access. Syncs pull every record by default. InsightVM's first sync is a full import; after that each sync asks only for assets scanned since the last successful sync and only their new and remediated findings, with a full refresh every `full_sync_days` (default 7). Set `full_sync: true` on the integration to force one. InsightVM streams assets 250 at a time, so a large tenant (10k+ assets, millions of findings) never sits in memory at once; the first full sync of a big tenant can take a while. "Max Assets / Findings / Insights per Sync" are optional limits (blank = all). The Command Platform key needs InsightVM access for the InsightVM connector; a 401 "does not have permission" means the key lacks that product.

---

## On-prem shippers (internal LDAP, Rapid7 console, CrowdStrike, Splunk)

When CTEM is hosted outside your network it can't reach your domain controllers, Rapid7 Security Console, or Splunk search head. A **shipper** is a small agent on one internal box that reads those sources locally and pushes the data to CTEM's REST API over outbound HTTPS. Nothing inside your network has to accept a connection from CTEM.

**Setting one up**

1. In CTEM go to **Settings > Shippers > + New shipper**. Pick the sources (LDAP / AD, Rapid7 InsightVM console, CrowdStrike Falcon, Splunk), enter hosts, users, SPL, and the schedule. No passwords yet.
2. Click **Download installer**. The script holds a one-time enrollment code (24 hours, optionally limited to source CIDRs) and no secrets.
3. Copy it to the internal box and run `sudo bash open-ctem-shipper-NAME.sh`. It asks:
   - **Local script mode** (Python venv + systemd + cron; the box key is sealed with `systemd-creds`, TPM-backed when available) or **self-contained Docker** (read-only, cap-dropped container that restarts on its own). Docker is optional.
   - Whether each source's TLS certificate matches (self-signed consoles get their fingerprint pinned), and to approve each destination.
   - Optionally the source passwords, which it tests and then seals.
4. Set or rotate passwords any time under **Shippers > Rotate**.

A **generic installer** (no code inside) is also available: the box signs in once with an admin account (+ MFA code), and you pick the sources in the wizard. The admin password is used for that one request and never stored.

**How credentials stay safe**

- The box generates an RSA-3072 key pair at install. The private key never leaves the box. CTEM only stores the public key and a hash of the box's push token, which is pinned to the box's source IP.
- Passwords are sealed **in your browser** (WebCrypto, RSA-OAEP-256 + AES-256-GCM, bound to the shipper, source, and field) before they're sent. CTEM stores the envelope, wrapped again with its own key, and can't decrypt it. A database dump or a read-only compromise of CTEM exposes no internal credentials. The shipper unseals in memory only.
- Destinations (host, port, TLS mode, certificate pin, Splunk SPL, Falcon cloud) only take effect after `open-ctem-collector approve` on the box, so even a compromised CTEM can't point a shipper at an attacker's server to harvest a password. The GUI shows "waiting for approve on the box" until then.
- Compare the key fingerprint the installer prints with the one CTEM shows before typing passwords.
- Every batch is staged to a private spool (mode 0600) on the box and deleted as soon as CTEM confirms it. Unsent batches retry on the next run, and anything older than 7 days is purged.

**Day two** (on the box): `open-ctem-collector approve | secrets [--all] | run-now | test | test-ctem | status | logs`. To pick up new shipper code, download a fresh installer and run it on the box: when a shipper is already installed it upgrades in place (`--upgrade` does the same explicitly), replacing the code only and keeping the box key, sealed passwords, approved destinations and every source setting, so nothing is re-entered. `--reinstall` forces a fresh enrollment. The shipper checks in every 5 minutes. Each source has its own **Run every** setting (5 minutes to a day; blank follows the shipper's default), so LDAP can run every 30 minutes, Rapid7 every 5 hours and Splunk every 5 minutes. Schedule changes apply at the next check-in and don't need approval on the box. `sudo bash open-ctem-shipper-NAME.sh --uninstall` removes it (revoke it in CTEM too).

**Troubleshooting:** `open-ctem-collector logs` showing `203/EXEC Permission denied` means the venv isn't readable by the service user (installs before this fix); re-run the installer. If LDAP syncs succeed with 0 records, run `open-ctem-collector test`, which now says when the bind works but no users are visible to that account. Shippers keep each request under 768 KB, so a load balancer with nginx's default 1 MB body limit is fine.

**Notes:** Set `PUBLIC_URL=https://ctem.acme.example` so installers carry the right default address. A shipper-fed Splunk supplies notable events and the index catalog, but Hunt can't run live SPL through it (it's push-only). The CrowdStrike API client needs *Hosts: Read* and *Alerts: Read*; add *Firewall management: Read* and *Device control policies: Read* for the inventory's firewall and USB-blocking columns (they reflect the Falcon policies applied to each host).

---

## Authentication modes

Set `AUTH_MODE` in `.env`:

| Mode | Behavior |
|---|---|
| `oidc_only` | Immediately redirects to IdP -- no login page shown |
| `local_only` | Username + password + TOTP only |
| `both` | Login page shows local form + SSO button |

TOTP brute force protection: 5 fails = 5 min lockout, 10 = 30 min, 15+ = hard lock with admin unlock required.

Password brute force protection: 10 failed passwords on one account = 15 min cool-off, plus a per-IP limit on every sign-in endpoint.

With `MFA_REQUIRED=true`, a local user without TOTP is walked through enrollment (QR code + first code) on their next sign-in. Users can also enroll or replace their authenticator from **My Profile**; replacing one requires a current code.

---

## Quick start

```bash
cp .env.example .env
# Edit .env with real values (generate keys with: python3 -c "import secrets; print(secrets.token_hex(32))")

docker compose -f docker/docker-compose.yml --env-file .env up -d

# App:   https://localhost
# Docs:  https://localhost/api/docs  (DEBUG=true only)
```

Requirements: Docker 24+, Docker Compose v2.

### Behind an upstream load balancer

Set `LB_BIND_IP` in `.env` to the private IP your load balancer reaches this host on. nginx publishes a dedicated listener on `LB_BIND_IP:8085` that trusts only the client IP the load balancer appends to `X-Forwarded-For`. Leave it unset and the listener binds to loopback only. The public `:80` and `:443` listeners never trust client-supplied forwarding headers.

---

## Testing

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

Runtime dependencies live in `requirements.txt`; test and SBOM tooling live in `requirements-dev.txt` and never ship in the image.

---

## SBOM

A CycloneDX Software Bill of Materials for the runtime image ships at `sbom.cdx.json`. Regenerate it whenever `requirements.txt` changes:

```bash
python3 -m venv /tmp/sbom-env && /tmp/sbom-env/bin/pip install -r requirements.txt
.venv/bin/cyclonedx-py environment /tmp/sbom-env/bin/python --of JSON -o sbom.cdx.json
```

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

**AI usage** (Admin > AI Usage): month-to-date AI cost and tokens against optional monthly limits (dollars and/or tokens), with a forecast and per-model / per-feature breakdowns. Claude models are priced from Anthropic list prices; custom or OpenAI-compatible providers use the input/output/cache prices you enter there.

Counts are server-side totals across every device you can see. Click a risk card (Critical, High, Medium, KEV, Total) to open the device list with that filter applied. Scores refresh after every integration sync and every two hours.

---

## Security design

- No IDOR: every object fetch verifies ownership or tag-based access; returns 404 (not 403) for forbidden
- No BFLA: all state-changing routes re-check server-side role and permission
- No SQL injection: parameterized queries only via SQLAlchemy ORM
- No SSRF: DNS-pinned httpx transport blocks RFC 1918, loopback, link-local, and metadata IPs
- No secret leakage: generic error handler returns message + request ID only; details go to server logs
- No XSS from data: every API value rendered into the page goes through an HTML escape helper
- CSRF: Origin check on every cookie-authenticated write, plus an HMAC token on the sign-in forms
- Spoof-proof client IPs: API token IP binding and rate limits use the address nginx vetted, never a raw header
- Encryption: AES-256-GCM column encryption with per-record nonce; HMAC-SHA256 for indexed lookups
- Headers: HSTS, CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff

---

## Project layout

```
api/
  auth/        OIDC, local login, TOTP, RBAC middleware
  core/        Config, DB, encryption, SSRF client, Celery tasks, security middleware
  collector/   On-prem shipper: ingest + profile rules (server) and agent/ (the code installed on the box)
  integrations/ Vendor connectors (one file per vendor)
  maintenance/ One-off data repair commands (device merge, sources backfill)
  models/      SQLAlchemy ORM models
  routes/      FastAPI route handlers
  scoring/     Risk engine: compensating controls, CVE chains, device/user scores
  web/         Jinja2 templates + static assets
docker/        Dockerfile, docker-compose.yml, nginx.conf
```

---

## Contributing

Every commit runs local pre-ship checks first: secrets scan, SAST (Bandit), dependency audit (pip-audit), and the full test suite. Nothing merges with a failure.

Example credentials in tests and `.env.example` are fake and are declared in `.github/secret_scanning.yml` and `.gitleaks.toml` so scanners skip them.
