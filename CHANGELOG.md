# Changelog

All notable changes to open-ctem are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

### Added
- AD user profile: first name, last name, title, office phone and mobile from the directory (encrypted at rest), shown on **Discovered Users**. Phone numbers are normalized to E.164 (`+15550100199`, with `;ext=N` for extensions) using the user's AD country, falling back to `PHONE_DEFAULT_REGION` (default US); anything that isn't a real number is kept as entered. New dependency: `phonenumbers` (SBOM updated)
- Rapid7 InsightVM asset tags (cloud API and console shipper) become CTEM device tags: custom tags as `r7:<name>`, plus `location:`, `owner:` and `criticality:`. Each sync replaces them, so tags removed in Rapid7 disappear here; tags from other sources are untouched. Criticality (Very High to Very Low) sets the device's asset-criticality weight in risk scoring, and the CMDB gains Location and Criticality columns, takes Owner from the Rapid7 owner tag before the last signed-in user, and reads Environment from Rapid7 custom tags like "Production". A console account that can't read tags leaves existing tags alone
- CrowdStrike containment: a host Falcon has network-contained is marked **Contained** in the inventory, on its device page (with a banner) and in each vulnerability's affected-device list. While contained its findings can't be exploited, so they show as **info**, greyed out, and score 0 / grade A; the original score and grade stay visible beside the adjusted one, e.g. `(F 87.3 → A 0)`. Lifting containment restores normal scoring at the next sync. Device finding exports gain a Severity column
- AD account health from the shipper: last logon (`lastLogonTimestamp`), password last set, password expiry (`msDS-UserPasswordExpiryTimeComputed`), expired, never-expires, locked out, and disabled. Shown on **Discovered Users** (AD status chips, AD last logon, password set) and fed into user risk: dormant enabled accounts (no logon in 90 days; doubled for privileged ones), passwords older than a year, never-expiring and expired passwords, and lockouts add risk; disabled accounts count for 30%. Values an older shipper doesn't send are kept, not blanked
- CrowdStrike firewall and USB storage telemetry: each host's applied Falcon firewall policy (enabled and enforcing) and device-control policy (enforced with mass storage set to block all) show as **FW** and **USB block** columns, on the device page, and in the CSV export. Needs *Firewall management: Read* and *Device control policies: Read* on the API client; without them the columns stay blank instead of guessing
- Per-source shipper schedules: each source (LDAP, Rapid7 console, CrowdStrike, Splunk) has its own **Run every** (5 minutes to 1 day, validated server-side; blank uses the shipper default). The box checks in every 5 minutes and ships only the sources that are due; Splunk's look-back follows its own schedule. Schedule changes need no approval on the box
- Running a shipper installer on a box that already has one now upgrades in place instead of re-enrolling, so the key, sealed passwords, approvals and source settings all survive; `--reinstall` forces a fresh enrollment. Upgrades also move the box's cron check-in to every 5 minutes
- Device inventory shows one normalized, uppercase short host name per device (DESKTOP001); the FQDN (also uppercase) is on the device page, in a tooltip, and in its own CSV column
- Sources column lists every feed that reported a device (CS, R7, AD, QL, MDE, ...), and the source filter matches any of them. `python -m api.maintenance.backfill_sources` fills it for existing devices
- Type column shows a server / workstation / network / cloud icon. CrowdStrike's product type (Server, Domain Controller, Workstation) and server operating systems now set the device type; before, every CrowdStrike and AD host was a workstation
- `--upgrade` for the shipper installer: replaces the shipper code (local or Docker mode) and keeps the box key, sealed passwords and approved destinations, so no re-enrollment
- CrowdStrike now records each host's last signed-in user (direct connector and shipper), so the device inventory's User column fills in and Hunt can find a user's computers
- On-prem shippers: an agent for an internal box that reads LDAP / AD, the Rapid7 InsightVM Security Console, CrowdStrike Falcon, and a local Splunk, then pushes to CTEM over outbound HTTPS. Managed under **Settings > Shippers**
- One-file installer generated per shipper (one-time enrollment code, optional CIDR lock), with local script mode (systemd + cron) or a self-contained Docker container, plus a generic installer that enrolls with an admin sign-in
- Central shipper config: sources, hosts, SPL, and schedule are edited in CTEM and picked up at the next 15-minute check-in
- End-to-end sealed secrets: source passwords are encrypted in the browser to the shipper's own key; CTEM stores them but can't read them. Rotate once in the GUI
- Destination changes (host, port, TLS, cert pin, SPL, Falcon cloud) need `open-ctem-collector approve` on the box before use
- Staged batches are deleted as soon as CTEM confirms receipt; unsent ones retry next run
- `PUBLIC_URL` setting for installer defaults
- The shipper's LDAP reader pages through the whole directory (AD stops a single search at 1,000 entries) and selects users with `objectCategory=person`, so computer accounts aren't counted as users. The direct LDAP connector still does a single search

### Security
- Collector API: hashed, IP-pinned push tokens scoped to one profile's integrations; single-use, atomically claimed enrollment codes; rate-limited enrollment and sign-in; payloads parsed only after auth, with nothing echoed back or logged
- Directory pushes (and direct LDAP syncs) no longer overwrite local break-glass accounts
- Hunt never tries live SPL against a shipper-fed Splunk
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
- A slow Rapid7 console (or a proxy in front of it) failed the whole run with "The read operation timed out": the shipper asked for 500 assets per page with a 2-minute limit. It now starts at 200 per page with a 5-minute limit and, on a timeout, retries the same position with 100, 50, then 25 rows instead of giving up
- CMDB looked empty: the hostname sort put bare-IP scanner assets (no FQDN, no OS) first, Owner only used an explicit owner (never set), and Environment only read `env:` tags. Named hosts now sort before bare IPs, Owner falls back to the last signed-in user, Environment comes from an `env:` tag or the AD OU path (Prod, Dev, QA, Stg, UAT, Test), and the FQDN is filled from Rapid7's full host name where it was missing (`backfill_sources` repairs existing rows)
- CMDB showed only the first 200 devices and reported that as the total. The page now pages server-side (25 to 200 per page) with the real total, search (hostname, FQDN, OS), type filter and sorting; tag-scoped users no longer see devices counted twice; the ServiceNow JSON export is no longer cut off at 10,000 CIs and carries the normalized name, FQDN, sources, firewall and USB fields
- Devices were duplicated across sources because every connector matched on the exact host name: CrowdStrike and AD report `DESKTOP001`, Rapid7 reports `desktop001.ad.acme.example`. The Rapid7 copy showed EDR as missing and no user. Devices now match on a normalized host key (short name, case-insensitive; parent and child domains count as one, a bare short name goes to the AD-joined record or the main domain, unrelated domains stay apart), Rapid7 fills in the FQDN, and `python -m api.maintenance.merge_devices` folds existing duplicates together (dry run by default)
- CrowdStrike hosts under network containment were shown as having no working EDR
- Shipper batches over the load balancer's body limit (a 500-user AD batch with group memberships easily passes 1 MB) failed with HTTP 413 and stayed spooled, so every later run hit the same wall. Batches, including ones already spooled, are now split to stay under 768 KB per request
- Shipper LDAP read Active Directory as plain OpenLDAP (ldap3 files `supportedCapabilities` under `supported_features`), so it searched for `inetOrgPerson`/`device` and shipped zero users and computers while reporting success. AD is now detected correctly, and `open-ctem-collector test` fails when the bind works but no users are visible
- Local-mode shipper installs on boxes where the installer's `umask 077` left `/opt/open-ctem-collector/venv` root-only, so the service user failed with `203/EXEC Permission denied` and nothing ever shipped. The venv is now built world-readable (root-owned), re-running the installer repairs an existing one, and the install stops if the service user can't run it
- Two syncs of the same integration could run at once (Sync Now during a scheduled run) and insert duplicate rows; a per-integration lock now makes the second one skip. FairTPRM suppliers without a security rating show as "unrated" instead of grade A
- FairTPRM integration imported nothing while reporting success: it called a `/api/v1/suppliers` endpoint with an `X-API-Key` header, but FairTPRM's API is `/api/v2` with Bearer tokens. The connector now uses `/api/v2/vendors`, takes the latest security rating per vendor (risk score, grade, open high/critical issues) and FAIR loss estimates, accepts a base URL with or without `/api/v2`, and fails the sync with a clear reason on 401/403 (bad token or CTEM's IP not on the token's whitelist)
- Grip's `fairtprm_grip_passthrough` option silently skipped the Grip sync on the assumption FairTPRM relays Grip data; it doesn't, so the option is now ignored. ITDR, posture, shadow SaaS and shadow AI come from CTEM's Grip integration only
- Admin audit log never loaded (the page called a URL that does not exist) and its "Load more" paging used random ids as a time cursor
- Browsers kept day-old JavaScript and CSS after a deploy (static files are cached for a day); every static URL now carries a content hash
- Startup schema migration raced when app, worker, and beat booted together, and one failed `ALTER TABLE` aborted the whole boot transaction; migrations now take a Postgres advisory lock and run each statement in a savepoint
- Device list pager restyled to match the app: right-aligned numbered pages, rows-per-page, and inherited fonts
- Device and vulnerability lists: paging never worked (the API ignored the page offset and returned no total), search was ignored, and the IP and OS columns were always blank
- Dashboard counted only the first 200 devices it loaded; totals, grade cards, and the environment table now come from server-side counts, and the owner/app/environment filters (which sent parameters the API never read) now filter by tag
- Device links went to a missing page (404)
- Risk scores never appeared after a sync: scoring only ran on a 2-hour timer that restarts with the containers; it now also runs after every successful sync
- Nothing set the CISA KEV or EPSS fields, so the KEV panel was always empty and scores ignored exploit data
- Per-finding scores were computed but never saved
- Vulnerability affected-device list was cut to 50 before the access check, so restricted users got a short, wrong total
- InsightVM cloud sync held every asset and finding in memory and refetched vulnerability details it had already trimmed; it now streams page by page and records each asset's last assessment time
- Rapid7 connectors no longer cap records by default (assets, findings, insights); a limit is optional
- Rapid7 connectors were never registered, so every Rapid7 test and sync failed
- InsightAppSec: pulled every vulnerability once per app and overflowed the CVE column; now one filtered search, findings tied to an app device with triage status (false positive, ignored, remediated)
- InsightCloudSec: rewritten against the public v2 API (Insights list + resource query per Insight, cursor paging). It used a bogus base URL and endpoint, sent the wrong auth header, crashed on an unknown device type, and counted a login-page redirect as a passing connection test
- InsightCloudSec: examples and errors now show the Command Platform tenant host form (`https://us1.cloudsec.insight.rapid7.com`)
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
- LDAPS now validates server certificates by default; "Skip certificate check (lab only)" opts out

### Added
- AI usage metering: every AI call records provider, model, purpose, and token counts (input, output, cache read/write; never prompt text). Admin > AI Usage shows month-to-date cost and tokens against the limits, a month-end forecast, a daily chart, and breakdowns by model and feature
- Monthly AI limits in dollars and/or tokens (blank = no limit, 0 = AI off). When reached, hunts fall back to keyword searches and alert analysis is skipped until the 1st (UTC)
- Claude models are priced from Anthropic list prices per model; custom and OpenAI-compatible providers use admin-entered input/output/cache prices. Cost is computed on read, so a price change reprices past usage
- InsightVM incremental sync: after a full baseline, each sync asks Rapid7 only for assets scanned since the last success and only their new and remediated findings, and fetches vulnerability details only for ones not already stored. A full refresh runs weekly (`full_sync_days`, default 7); remediated findings are now closed
- After a sync, only devices that changed are rescored; the full rescore runs daily instead of every 2 hours
- Ticket dialog: copy the ticket subject and text for a manual email; only configured delivery methods (ServiceNow API, inbound email) are offered, and with none set up the dialog says so. Affected devices on a vulnerability page have a Ticket button for that exact finding
- Audit log CSV export (downloads as a file; the export itself is audited)
- Search engines and AI crawlers are kept out: `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet, noimageindex, noai, noimageai` on every response, a robots meta tag on every page, and a `/robots.txt` that disallows everything (with the major AI crawlers named)
- Device detail page: details, owner/last user, and every finding with status filter, search, sort, paging, and CSV export
- Vulnerability detail page: click a CVE or title to see every affected device (scoped to what you may see), with search, sort, paging, and CSV export
- Device list: User column, open and KEV finding counts, last seen, source; sortable columns; paging at top and bottom with page jump and page size; filters kept in the URL
- Vulnerability list: partial, case-insensitive search across title, CVE, and scanner ID; KEV, CVSS, source, and affected-only filters; sortable columns including affected count
- CSV export for the device list, vulnerability list, a device's findings, and a vulnerability's affected devices. Exports follow the current filters and sort, include every matching row, and neutralize spreadsheet formulas (CWE-1236)
- Dashboard risk cards link to the matching filtered device list
- Vulnerability affected-device counts are stored per vulnerability and refreshed by each scoring run, so sorting thousands of vulnerabilities by affected count stays fast; tag-restricted users still get a live count of only their devices
- Daily CISA KEV and FIRST EPSS enrichment (fixed feed URLs through the SSRF-guarded client); set `THREAT_FEEDS_ENABLED=false` for air-gapped installs
- Rapid7 InsightVM cloud mode (Insight Platform v4 Integration API): assets, per-asset Critical/Severe findings, remediation tracking; the on-prem console mode stays
- Rapid7 region picker (us, us2, us3, eu, ca, au, ap) and per-product form fields for InsightAppSec, InsightVM, and InsightCloudSec
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
