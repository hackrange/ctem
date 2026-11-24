# open-ctem: project overview

What open-ctem covers, how it scores risk, and how it has been reviewed and hardened. For setup and day-to-day use, see the [README](../README.md). For every change by version, see the [CHANGELOG](../CHANGELOG.md).

## History

- **About May 2025:** open-ctem started as a PHP application, roughly 18 months before this repository existed.
- **The Python rewrite:** the PHP application was then rewritten from PHP to Python, as FastAPI, async SQLAlchemy on PostgreSQL with TimescaleDB, Celery and Redis.
- **This repository:** it starts at the Python version, **1.0.1 on 2026-11-19**. The PHP versions are not in this repository's history, and the dates in this repository are when each change was actually made.

| Version | Date | Theme |
|---|---|---|
| 1.0.1 | 2026-11-19 | First Python release: API, SSO and local sign-in with MFA, RBAC, column encryption, scoring engine, connector framework |
| 1.1.0 | 2026-11-19 | All connectors, identity risk, attack paths, GRC, ServiceNow, installer; first hardening pass |
| 1.2.0 | 2026-11-20 | On-prem shippers with sealed secrets, one device per host across sources, AD account health, SSO wizard, Cyber Threats |
| 1.3.0 | 2026-11-21 | Vulnerability exceptions, vulnerability dashboard, dashboard builder with AI, cloud exposure (AWS, Azure, OCI), Bedrock |
| 1.4.0 | 2026-11-22 | Code and web app assets (GitHub Code Review), per-user data access, SLAs, software inventory, EDR policy scoring, Horizon3 |
| 1.5.0 | 2026-11-23 | NodeZero across all pentests, encrypted backups and restore, admin-only admin areas, read-only vendor tenants, cloud findings |
| 1.6.0 | 2026-11-24 | Asset locations and Sites, network discovery, data retention, Threat Curated Rules |
| 1.7.0 | 2026-11-24 | View as, stale AD user export, cloud finding grades, security review fixes, CVE de-duplication across scanner and pentest |
| 1.8.0 | 2026-11-24 | CrowdStrike alert updates from CTEM, interactive attack maps for alerts, hunts and pentests, AI alert reads, PDF hunt reports, built-in hunt rules, stricter headers |
| 1.8.1 | 2026-11-24 | Logon and identity details on alerts and in hunt rule findings, more of the Falcon console in CTEM, old alerts fetched again, shipper approval fix |
| 1.8.2 | 2026-11-24 | Every connector loaded; Grip verified against a real tenant |
| 1.9.0 | 2026-11-24 | Zscaler read-only posture and coverage, Grip extensions and credential risk, alert allow list, process and file in hunt findings, alert PDF, database upkeep |

The on-prem shipper has its own version numbers (1.0 to 1.7.x), separate from the application's.

## Scope

open-ctem is a Continuous Threat Exposure Management platform. It brings asset, vulnerability, identity, EDR, cloud and pentest data into one inventory, scores what an attacker can actually reach, and tracks remediation through to evidence.

| Area | What it does |
|---|---|
| Inventory | One device per real host across every source, whatever each source calls it; repositories, web apps and cloud resources as their own asset types; assignment and shipping status; inferred office, city and state; CMDB export |
| Vulnerabilities | Infrastructure, code, web app and cloud findings with age against SLA, one line per CVE per asset however many tools found it, exceptions and false positives with approval, reasons and end dates, and fixes ranked by the risk they remove |
| Validation | Horizon3 NodeZero results attached to the findings they prove, with how it got in, the proof and the impact; reachability from scanner facts; a network probe confirms hosts that have gone |
| Identity | Directory users with account health (logon, password age and expiry, lockout), privileged groups, the devices each person uses, and identity risk |
| Threat | Alerts from every tool in one list, AI analysis, natural-language hunting, and curated rules learned from the AI's findings |
| Cloud | AWS, Azure and OCI instances with their internet reachability and effective firewall rules; CSPM findings graded on their own terms |
| GRC | Control checks as evidence, two-way risk with FairTPRM, supplier risk, a risk register |
| Dashboards | Drag-and-drop builder with about 50 widgets, filters, AI drafting and editing, sharing with approval, CSV export |
| Operations | One-line install, upgrades, encrypted full backups and restore onto a clean server, utilization monitoring, data retention |
| Access | Built-in and custom roles, tag- and rule-based data scoping, read-only "View as" for admins, IP-bound API tokens |

## Integrations

There are about 30 connectors. Each one reads from the vendor; none changes anything in a vendor's tenant. The exceptions are the tools CTEM is meant to send data to (FairTPRM, GitHub Code Review, ServiceNow tickets and the AI providers) and CrowdStrike alert updates: cyber and admin can close, reopen, classify and comment on a Falcon alert from CTEM, and nothing else in Falcon is ever changed. Which connectors have been checked against a real vendor API is tracked in [integration-validation.md](integration-validation.md).

| Category | Connectors |
|---|---|
| Vulnerability scanning | Rapid7 InsightVM (cloud and on-prem console), Rapid7 InsightAppSec, Qualys, Tanium, CrowdStrike Spotlight |
| Cloud | Rapid7 InsightCloudSec (CSPM), AWS, Azure, Oracle Cloud (read-only, allow-listed actions) |
| Pentest | Horizon3 NodeZero (GraphQL queries only) |
| EDR and threat | CrowdStrike Falcon (hosts, alerts, policies, Discover, event streams, Data Replicator), SentinelOne, Microsoft Defender, Palo Alto Cortex XDR |
| Identity | LDAP and Active Directory, Grip Security |
| Network | Palo Alto NGFW, Fortinet, Zscaler ZIA/ZPA, Guardicore, plus the shipper's own network discovery |
| AppSec | GitHub Code Review, GitHub Advanced Security, Snyk, ForgeRepo |
| SIEM | Splunk (search, and a feed of CTEM's high-fidelity alerts) |
| GRC and ITSM | FairTPRM, ServiceNow, email |
| AI | Anthropic, Claude on Amazon Bedrock, OpenAI-compatible and custom providers, with metered cost and limits |

Sources inside the network (LDAP, an on-prem scanner console, CrowdStrike Data Replicator, Splunk) are read by an **on-prem shipper**:

- Its secrets are sealed end to end.
- A destination is approved on the box itself.
- Its push tokens are hashed, pinned to the box's IP and scoped to one profile.

## Scoring model

Every score is 0 to 100 and every grade is A to F: A up to 20, B up to 40, C up to 60, D up to 80, F above 80. Each asset type is scored on terms that make sense for it, and every score carries its reasons.

**Host findings** combine severity, exploit likelihood and context:

```
base = 0.25 × CVSS + 0.30 × EPSS + 0.20 × KEV + 0.15 × asset criticality + 0.10 × reachability
```

- **Known exploited:** a CISA KEV finding never scores below 75.
- **Reachability** comes only from facts:
  - physical access ×0.3, local ×0.5, adjacent network ×0.8;
  - found by a local check with no listening service tied to it ×0.75;
  - a NodeZero-confirmed exploit is never discounted, and NodeZero-confirmed safe is ×0.3.
- **Compensating controls** move the score only when a host's policies actually enforce them: EDR prevention (not just detection), exploit mitigations, host firewall rules on the finding's port, USB blocking and segmentation.
- **Out of scope:** a host that is EDR-contained or marked Not In Scope counts nothing, but its findings stay visible next to the raw score.
- **Device score:** the average of its worst 10% of findings, so one stray finding doesn't decide the grade.

**Code and web app findings:** severity and exploitability are combined as a geometric mean, so a finding scores high only when it is both serious and exploitable. That result is then scaled by the asset's impact (criticality, the data it holds, its environment) and its exposure (a live internet-facing site, or the code behind one).

**Cloud configuration findings** start from the tool's own severity:

| Severity | Base |
|---|---|
| Critical | 70 |
| High | 50 |
| Medium | 30 |
| Low | 15 |
| Info | 5 |

What the check is about then moves it: +20 for public or internet-facing, +10 for identity or admin rights, −10 for logging or housekeeping.

**Users** are scored on their account health, their devices and privileged group membership; a service account adds +30 for its blast radius. **CVE chains** linked through MITRE ATT&CK techniques are scored as a path, not as separate findings.

## Security reviews

- **Every change:** the code is checked against a set of secure-design rules:
  - authorization re-checked on the server at the action, and object-level access on every id;
  - parameterized queries only;
  - SSRF-safe fetches with the vetted IP pinned to the connection;
  - formula-safe exports, leak-proof errors, and no secrets in code or client files.
- **Every release:** a pre-ship check has to pass. It covers:
  - a secrets scan;
  - Bandit SAST;
  - pip-audit for vulnerable dependencies;
  - OWASP pattern checks (raw SQL, shell calls, id routes without an access check);
  - file size limits;
  - the full test suite: more than 900 tests, covering access control, CSRF, sessions, SSRF, exports and every connector.
- **UI review (1.3.0):** every page was checked in light mode, dark mode and phone width.
- **Independent security review (1.7.0):** an outside AI code review produced a list of recommendations.
  - Each one was checked against the running system and its compensating controls.
  - The ones with real security value were fixed without changing intended behavior.
  - The rest were declined, each with the reason: little security value given the controls already in place, or a fix that would break intended behavior.

## Hardening

Grouped by area; the version each landed in is in the CHANGELOG.

- **Authentication:**
  - OIDC with PKCE, with ID tokens verified against the provider's signing keys (asymmetric algorithms only).
  - Break-glass local sign-in with Argon2id and TOTP, and MFA that has to be verified before it turns on.
  - A per-account cool-off after failed passwords, and no timing difference between unknown users and wrong passwords.
  - Case-insensitive usernames; locked accounts lose their API tokens.
- **Sessions:**
  - `__Host-` cookies with a sliding expiry.
  - Signing out ends the session on the server, and a new password signs the account out everywhere else.
  - With sign-in set to SSO only, passwords are refused for shipper enrollment too.
- **Authorization:**
  - Server-side role checks on every action; only admins see admin areas.
  - Tag- and rule-scoped data access, with 404 for both forbidden and absent.
  - Scoped caches that follow access changes at once.
  - Approved all-data dashboards that can't be widened by changing their filters.
  - "View as" is read-only, time-limited and audited.
- **Network trust:**
  - The client address comes only from the reverse proxy, so token IP binding, shipper pins and sign-in throttling can't be spoofed.
  - The SSRF-safe outbound client pins the vetted IP for every hop.
- **Data:**
  - AES-256-GCM column encryption with a nonce per record, and HMAC indexes for search.
  - Encrypted backups, with a key check after restore.
  - Retention that removes only what a network probe confirms has gone, on CTEM's own clock.
- **Web:**
  - CSRF origin checks and tokens.
  - Every value escaped in the page.
  - A strict Content Security Policy, with the CDN allowed only on the API docs page.
  - HSTS, frame denial, nosniff and noindex.
  - Formula-injection-safe CSV.
- **Vendors:** the tenant APIs are read-only by design:
  - AWS can run only seven allow-listed actions.
  - Horizon3 refuses mutations.
  - InsightCloudSec uses GET only.
  - CrowdStrike scopes are read-only, except Alerts: Write for alert updates: only status, comment and `ctem_` classification tags, built from an allow-list and checked again on the shipper's box, which has to approve turning it on.
  - Integration secrets are masked, and changing an endpoint requires re-entering its credentials.
- **Supply chain:**
  - Dependencies are kept clear of known advisories, with current pip in the image.
  - XML is parsed with defusedxml.
  - A CycloneDX SBOM ships with every release.
