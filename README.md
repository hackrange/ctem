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

**Cloud Inventory.** The Cloud page lists every AWS, Azure and OCI instance with its internet reachability (ports and the firewall that allows them), scanner and EDR coverage and findings, and singles out the ones breachable now.

**Utilization.** Admin > Utilization shows CPU, memory and disk live and over a year, where storage goes (databases, biggest tables, WAL, Redis), and warns before the disk fills.

**Rule exceptions.** Admins can except whatever a rule describes (for example hostnames `can*` with an OS starting with `Cisco IOS`, all vulnerabilities or a filtered set), drafted from plain English by the AI and previewed before creation. They need a reason, compensating controls and an end date, and stay current as devices and findings change.

**Tag mapping.** Admin > Tag mapping tells CTEM what your tags mean: map prefixes such as `owner:E-O:` to Executive owner or `env:` to Environment. Suggestions come from your own tags; the dashboard filters, tag-focus chips and CMDB owner and environment read the mapping.

**Reachability (breachability = likelihood × reachability).** Reductions come only from facts, and each one shows its reason (hover the **Reach** chip on a finding). A finding's one reachability factor is the strongest that applies: CVSS physical access ×0.3, local access ×0.5, adjacent network ×0.8; otherwise found by a local check with no listening service tied to it ×0.75. Found on a listening port (Rapid7 records the port, for example `443/tcp`) is not discounted, and a NodeZero-confirmed exploitable finding never is. An EDR-contained or Not In Scope device counts nothing (reachability 0); its findings stay visible. The raw score is always kept alongside.

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
| Cyber Threat module | Aggregates alerts from all tools into one list, worst first: search, severity/status/source filters, short source codes (CS, R7, S1, MDE...), click through to the alert, its device, its MITRE ATT&CK technique and the alert in Falcon; AI analysis (async, cached) |
| Hunt module | Natural language AI queries across all telemetry sources |
| GRC / FairTPRM | Risk export and compliance evidence ingestion |
| CMDB | Every device, server-side paged with search, type filter and sorting; full ServiceNow import set JSON export |
| Full REST API | Interactive OpenAPI docs at `/api/docs` for signed-in admins and cyber analysts (hidden from everyone else) |
| Customizable branding | Logo, accent color, app title all configurable |

---

## Integrations

Every source is matched to the same device row by host name, however it spells it: `DESKTOP001` (CrowdStrike, AD), `desktop001.ad.acme.example` (Rapid7) and `desktop001$` all land on one device, so EDR, AD, vulnerability and last-user data show up together. A parent and child domain count as one (`ad.acme.example` ~ `acme.example`). A bare short name goes to the AD-joined record, or else the fleet's main domain. Two hosts with the same short name in unrelated domains stay separate. The inventory shows one uppercase short host name per device with a **Sources** column (CS, R7, AD, ...) and a type icon; the FQDN is on the device page and the CSV export has both Hostname and FQDN columns. Hosts that CrowdStrike has network-contained are flagged **Contained**: their findings show as info with a zero score until containment is lifted, with the original score shown beside the adjusted one. Admin and cyber can mark a device **Not in scope** from its page, with a justification and a last day up to a year ahead (`PUT /api/v1/devices/{id}/scope`, `DELETE` to undo). Until then its vulnerabilities don't count: risk 0, no open findings, and it's left out of vulnerability affected counts and the KEV, SLA and internet-facing GRC checks. Its findings stay visible, dimmed. The exclusion ends on its own after the last day, and every change is audited. Filter the inventory with Status: Not in scope. After upgrading, run `docker compose exec app python -m api.maintenance.backfill_sources` once to fill Sources for existing devices. Web apps and cloud resources are never matched to hosts by name. Upgrading from an earlier build that already made duplicates? Run `docker compose exec app python -m api.maintenance.merge_devices` to preview, then add `--apply` (back up the database first).

| Vendor | Type | Data pulled |
|---|---|---|
| LDAP / Active Directory | Identity | Users (name, title, E.164 phone numbers, last logon, password age/expiry, lockout, disabled), computers, groups, GPOs |
| Qualys | Vulnerability | Findings, CVSS, asset data |
| Rapid7 InsightVM | Vulnerability | Assets, per-asset findings and asset tags (custom, location, owner, criticality; cloud v4 API or on-prem console) |
| Rapid7 InsightAppSec | Vulnerability | Web app findings with triage status |
| Rapid7 InsightCloudSec | Cloud | Cloud posture findings |
| Horizon3 NodeZero | Pentest | Reachability validation |
| AWS | Cloud exposure | EC2 instances, public IPs, security groups and network ACLs (read-only) |
| Azure | Cloud exposure | VMs, public IPs, NIC and subnet NSGs (Reader app registration) |
| Oracle Cloud (OCI) | Cloud exposure | Instances, public IPs, security lists and NSGs (API signing key) |
| CrowdStrike Falcon | EDR + Threat | Devices, alerts with full detail |
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
| GitHub Code Review | SAST and DAST | Repositories as **Code** assets with code, dependency (CVE, KEV, EPSS, reachability), credential and misconfiguration findings; external sites as **Web application** assets with their latest DAST findings, telemetry and the repositories behind them. Application, owners and environment arrive as tags, a tag map adds your own, and code behind a live site counts as internet exposed. Each repository keeps GCR's own grade for a finding (reachability, validation and what it holds make it differ by repository) |
| AI (Anthropic, Amazon Bedrock, OpenAI, custom) | Analysis | Risk narratives, threat analysis, hunt, curated rule drafts |

**Which integrations are verified**: see [docs/integration-validation.md](docs/integration-validation.md). Integrations not checked off there haven't been tested against the vendor's real API yet.

**CrowdStrike Falcon scopes** (all Read; never Write, never Real Time Response): Hosts, Alerts, Firewall management, Device control policies, Prevention policies, Zero Trust Assessment; and when licensed, Vulnerabilities (Spotlight), Assets (Discover), Event streams, Falcon Data Replicator, Identity Protection and Intel. Each extra is optional: a refusal is a note on the integration card naming the scope, and the rest of the pull carries on. With the policies in, the asset page has Firewall (effective ruleset), USB (device control and authorized devices) and Posture (Zero Trust Assessment checks, disk encryption first) tabs for admins and cyber, and scores credit only the protections a host's policies actually enforce, with the reason on each finding.

**Splunk alert feed**: CTEM raises a small set of high-fidelity alerts (KEV on internet-facing assets, high/critical EDR alerts, unauthorized software, control checks that start failing, threat intel matches, remote response sessions), each once with a stable `key`, as `sourcetype=ctem:alert`. Deliver them directly to a reachable HEC (the Splunk integration's "HEC URL for CTEM alerts") or through the shipper's Splunk source (local HEC and/or a Universal Forwarder file), or both.

**Threat hunting telemetry**: with Falcon Data Replicator on the shipper's CrowdStrike source, Threat Hunt > Telemetry stacks every distinct process, DNS lookup, connection and logon per day by host count (rare first), matched against Falcon Intel indicators, alongside the real-time Falcon event stream. Raw data stays in your S3; CTEM keeps 30 days of stacks.

**Truncate** (admins, on each integration card) removes the data that integration's source reported, so the next sync starts clean: its findings, software installs, cached alerts, tag links and sync history, and the assets no other source reports (assets other sources also report are kept, minus this source's data). Software review decisions, tags and their access rules, and vulnerabilities with an exception are kept. Data is tagged by source, not by integration, so two integrations of the same vendor (say, InsightVM cloud and an InsightVM console) share it, and the warning names the other one. It runs in the background behind a warning that lists what goes, needs the integration's name typed to confirm, pauses that source's syncs and shipper uploads while it runs, rescores afterwards, and is audited. Cards also show the last sync's warnings, such as a shipper skipping software it can't read.

**Claude on Amazon Bedrock:** add a *Claude on Amazon Bedrock* integration, pick the AWS region and model (Bedrock IDs such as `anthropic.claude-sonnet-5-5`), and sign in with an IAM access key, a Bedrock API key, or the server's own AWS credentials (instance role). The endpoint is always `bedrock-mantle.<region>.api.aws`, so there is no URL to enter. Give the IAM principal only permission to invoke the chosen Claude models. **Test** sends a tiny real message. When more than one AI integration is enabled, the oldest one is used, so disable the Anthropic one to switch every AI feature (hunt, rule drafts, threat analysis) to Bedrock. Usage is metered like any other provider; enter your Bedrock prices under Admin > AI Usage, or CTEM estimates with Anthropic list prices.

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

Each source runs side by side in its own systemd instance (`open-ctem-collector-source@ldap`, `@rapid7_console`, `@crowdstrike`, `@splunk`), so a long console pass never delays the EDR. `sudo open-ctem-collector logs` and `status` cover them all.

When CTEM is hosted outside your network it can't reach your domain controllers, Rapid7 Security Console, or Splunk search head. A **shipper** is a small agent on one internal box that reads those sources locally and pushes the data to CTEM's REST API over outbound HTTPS. Nothing inside your network has to accept a connection from CTEM.

**Setting one up**

1. In CTEM go to **Settings > Integrations > Shippers > + New shipper**. Pick the sources (LDAP / AD, Rapid7 InsightVM console, CrowdStrike Falcon, Splunk), enter hosts, users, SPL, and the schedule. No passwords yet.
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

**Day two** (on the box): `open-ctem-collector approve | secrets [--all] | set-url URL | run-now | test | test-ctem | status | logs`. Every command and the installer print the agent version first (`open-ctem-collector --version` too). If CTEM's hostname changes, `open-ctem-collector set-url https://new-host` moves the shipper without re-enrolling: it only switches when the new address answers as open-ctem over verified HTTPS, accepts this shipper's token and returns its own profile, and keeps the box key, approvals and sealed passwords (`--ca-file` for a private CA). To pick up new shipper code, download a fresh installer and run it on the box: when a shipper is already installed it upgrades in place (`--upgrade` does the same explicitly), replacing the code only and keeping the box key, sealed passwords, approved destinations and every source setting, so nothing is re-entered. `--reinstall` forces a fresh enrollment. The shipper checks in every 5 minutes. Each source has its own **Run every** setting (5 minutes to a day; blank follows the shipper's default), so LDAP can run every 30 minutes, Rapid7 every 5 hours and Splunk every 5 minutes. Schedule changes apply at the next check-in and don't need approval on the box. `sudo bash open-ctem-shipper-NAME.sh --uninstall` removes it (revoke it in CTEM too).

**Troubleshooting:** `open-ctem-collector logs` showing `203/EXEC Permission denied` means the venv isn't readable by the service user (installs before this fix); re-run the installer. If LDAP syncs succeed with 0 records, run `open-ctem-collector test`, which now says when the bind works but no users are visible to that account. Shippers keep each request under 768 KB, so a load balancer with nginx's default 1 MB body limit is fine. A slow Rapid7 console gets smaller pages automatically (200 down to 25 rows) instead of a timed-out run.

**Notes:** Set `PUBLIC_URL=https://ctem.acme.example` so installers carry the right default address. A shipper-fed Splunk supplies notable events and the index catalog, but Hunt can't run live SPL through it (it's push-only). The CrowdStrike API client needs *Hosts: Read* and *Alerts: Read*; add *Firewall management: Read* and *Device control policies: Read* for the inventory's firewall and USB-blocking columns (they reflect the Falcon policies applied to each host). The shipper also pulls each host's login history (same *Hosts: Read* scope), so a kiosk or password-reset account signing in last (`SpecopsClient_…`, `kioskUser0`) no longer hides who uses the machine: CTEM picks the newest sign-in that matches a directory user, and the device page lists the recent sign-ins. If a column stays blank, the shipper's log on the box says which scope is missing. With shipper 1.0.6 or later (or CTEM's direct CrowdStrike connector, which now uses the Alerts API too), each alert in Cyber Threats carries its full detail, so you don't need the Falcon console: a plain-English summary of what happened, what Falcon did (killed, quarantined, blocked, contained), a timeline (process starts, files, network connections, DNS lookups, the detection, other alerts on the host, the last status change), the process tree with command lines, users and hashes, indicators, quarantined files, network and DNS activity, and CTEM's own view of the host (risk, open and KEV findings, assigned user). The detail is encrypted at rest, shown only to admin and cyber, and is not sent to the AI provider. Shipper 1.0.7 (and the direct connector) also pull hosts that are **hidden** in the Falcon console, which the normal host search leaves out, with the same *Hosts: Read* scope: a hidden host still shows as having CrowdStrike, keeps its containment state, and gets a *Hidden* chip and an inventory filter. A hidden copy left behind by a reimage doesn't overwrite the live host with the same name, and *EDR last seen* is now Falcon's own last contact time rather than the time of the pull.

---

## Dashboards you build

*Dashboards* lets anyone build dashboards from a catalog of ready-made widgets: single numbers, charts (line, area, bars, donut) and tables, drawn with ECharts on a drag-and-resize grid (GridStack.js). The catalog covers vulnerabilities (counts, trends, aging, mean time to remediate, top lists, by source or device type, with severity, KEV, source and device-type options), devices and EDR (counts by status such as contained or hidden in Falcon, EDR coverage, by type, grade and inventory status, riskiest devices), exceptions, GRC (control check results, compliance by framework from the latest FairTPRM assessment) and Cyber Threats (alerts over time, by severity, status, MITRE tactic and host). Directory widgets count stale AD computer and user objects at any age (for example 21, 30 and 90 days), list the stalest computers, and chart the trend from hourly snapshots; a stale-computer card opens the device list filtered to exactly those objects.

- **Each viewer sees their own numbers.** Widgets store a metric id and allow-listed options, never a query, and are computed for whoever is looking: an IT user sees only their devices, cyber the whole fleet. Threat widgets are for admin and cyber; GRC widgets for people with GRC access.
- **Sharing:** private, shared with chosen roles, or with everyone. Only the owner and admins change a dashboard; others can view, star or copy it. Admins have an *All dashboards* view.
- **Favorites:** star a dashboard to keep it in the menu's Favorites section and the Favorites tab.
- **Building:** in edit mode, drag stock widgets (about 50, grouped by topic) or any catalog metric from the library onto the grid, then move, resize and duplicate them. Switch a widget's chart type (number, gauge, line, area, bars, stacked bars, columns, donut, pie, table, scatter, bubble), color and transparency right on the widget.
- **Starter dashboards:** Risk overview, Remediation progress, Environment trends, Asset coverage, Asset inventory and Vulnerability trends.
- **Themes:** Default, Ocean glass, Sunset, Forest, Violet glass, Slate outline and Neon glass. They work in light and dark mode, and severity colors keep their meaning.
- **Filters:** any device-based widget can count only devices matching conditions on tags, tag-mapping roles (Executive owner, Application...), sources, device type, OS family, criticality or grade (all or any), or only the devices the viewer has access to. Every widget already shows each viewer only what they may see.
- **CSV export:** tables and charts download their data as formula-safe CSV.
- **AI follow-ups:** keep refining a dashboard in the "Ask the AI" box while editing; when a request is unclear, the AI asks a short question with suggested answers instead of guessing.
- **Draft and publish:** new dashboards are private drafts. Edits to a published dashboard stay a draft until you publish, so viewers never see half-finished changes.
- **Rename:** *Rename* changes a dashboard's name and description without touching its widgets or sharing.
- **Several sources at once:** vulnerability widgets take a list of sources (tick a few; none ticked means all).
- **Mean days to remediate as a number:** show it as a chart by month, or choose *Number* for the fixes in the last 30, 90, 180 or 365 days, with the change from the period before.
- **Style:** each widget can pick a color (blue, green, red, orange, yellow, purple, teal or gray) and a transparency; number cards can set amber and red thresholds.
- **AI help** (with an AI integration): describe a widget and it opens in the editor to check; describe a dashboard and it drafts one to edit, reusing a widget with different options where that fits; *Edit with AI* changes an existing dashboard on request ("make the trend blue", "add a 14-day card") and shows the result in edit mode, saved only when you click Save; *Explain* summarizes what a dashboard shows. The AI only picks from your own catalog, and Explain sends numbers only, never hostnames or people.
- Widget results are cached for 15 minutes per viewer scope; dashboards refresh every 5 minutes while open.

## Vulnerability dashboard

*Vuln Dashboard* (admin, cyber, read-only) shows the whole fleet: headline tiles (open, critical, high, KEV, exploit available, past SLA, devices affected, new and fixed in the last week, exceptions), open findings over time by severity with a KEV line (zoomable), new versus fixed per day, the age of open findings against the SLA, mean days to remediate by month, open findings by device type, and the most widespread vulnerabilities and riskiest devices. Filter by range, source and device type; tiles, slices and rows click through to the matching list. The **Code** tab adds a second row of filters, organization, application and code repository (an organization or application narrows the repository list), and labels everything in repositories; the main dashboard's Code tab has organization and repository filters too. Trends are rebuilt from each finding's first-detected and fixed dates, so there is history from day one; findings fixed before CTEM started tracking aren't in the data, so the chart marks where fix tracking began. The unfiltered view is rebuilt every 15 minutes in the background; filtered views are cached for 30 minutes.

Charts use [Apache ECharts](https://echarts.apache.org/) 6.1.0 (Apache-2.0) and the dashboard grid [GridStack.js](https://gridstackjs.com/) 14.1.1 (MIT), served from CTEM itself (`api/web/static/vendor/`, with licenses and checksums), never from a CDN. Read-only, IT and other scoped viewers see the Vuln Dashboard for their own devices only; the views of anyone who opened it in the last week are rebuilt in the background too, so their first click doesn't wait for a build. While a view loads, the page says so.

## Vulnerability exceptions and proof

**Proof:** on a vulnerability's affected devices, and on a device's findings, **Proof** shows what the scanner found and where (for example the path of a vulnerable PHP install), the port and the fix. It is fetched live from Rapid7 InsightVM for that one finding when you click, so nothing extra is stored; the scanner's HTML is turned into plain text first. Rapid7 findings only for now.

**Exceptions** (menu: *Exceptions*): admin and cyber create exceptions, which take effect at once; IT users request them for findings on their own devices, and admin or cyber approve (optionally changing the end date) or reject them with a note. An exception covers one finding, chosen devices, every device (including ones found later), or every device with a tag (including ones tagged later). Each needs a reason and an end date at most a year out; compensating controls are optional. While active, its findings are marked *Excepted* (risk accepted) and don't count toward risk, open counts, SLA, KEV or exposure; when it expires or is revoked they count again. Requesters see their own requests and how each was decided. Every step is in the audit log. For admin and cyber, a red count bubble on the menu, the *Waiting for approval* tab and the Vuln Dashboard's Exceptions tile shows requests waiting for approval. Approved exceptions on GitHub Code Review findings are mirrored to GCR in the background, so nobody waits on GCR's API.

## GRC with FairTPRM (both directions)

**FairTPRM updates CTEM.** The FairTPRM integration mirrors suppliers and the GRC module: frameworks and their compliance, internal controls, the risk register, evidence status and continuous monitors. The GRC page shows them next to CTEM's telemetry and flags **risk drift**: a risk recorded as mitigated whose controls are ineffective, whose CTEM checks are failing, that has no linked controls, or whose review date has passed.

**Shadow SaaS and Shadow AI.** The `ctem_shadow_saas` and `ctem_shadow_ai` checks accept Grip connected to CTEM, or FairTPRM's Shadow SaaS inventory (Grip, HERO or CSV fed) through `GET /api/v2/shadow-saas/apps`; an app reported by both counts once. FairTPRM only counts as a source after that data actually arrives, so an older FairTPRM or a token user who can't view Shadow SaaS shows as "no data", never as a pass. The FairTPRM token's user needs the administrator, cyber_tprm or auditor group.

**Internet-facing exposure from web apps.** `ctem_exposed_criticals` (v2) also counts Rapid7 AppSec web apps. An app is internet-facing when a scanned URL points at a public host: private, loopback and link-local IPs, single-label names, `.local`, `.internal`, `.lan`, `.corp`, `.home.arpa` and any domains listed in the integration's **Internal domains** setting are treated as internal (decided from the URL, no DNS lookups).

**Assessment results and audits.** CTEM also pulls FairTPRM's maturity assessments: overall FairScore (1 to 4) and compliance, answer progress, per-domain scores against FairTPRM's maturity targets, per-framework compliance, and the gaps (non-conforming and partial questions), plus audits with their findings. The GRC page shows the latest completed assessment up top, every assessment and audit below, and each assessment opens to its gap list. Gaps and findings are encrypted at rest; assessor notes, remediation text and report PDFs never leave FairTPRM. This needs FairTPRM with `GET /api/v2/grc/assessments`; an older FairTPRM keeps syncing everything else and the panel says it needs the update.

**Editing risks from CTEM.** Admins and the `grc` role can edit a risk's status, review date and treatment plan on the GRC page (**(edit)** on each row). The change goes straight to FairTPRM through `PUT /api/v2/grc/risks/{id}/review`, which records who made it in CTEM plus the before and after values in FairTPRM's audit log; CTEM audits it too. Likelihood, impact, treatment, category, owner and controls stay editable only in FairTPRM. This needs a FairTPRM token with **read_write** scope and FairTPRM with the review endpoint; if either is missing the page says so and nothing changes.

**CTEM updates FairTPRM.** CTEM answers 16 control checks that FairTPRM continuous monitors call on their schedule; each run becomes FairTPRM evidence and updates control effectiveness in every framework the control maps to.

| Check | Measures |
|---|---|
| `ctem_edr_coverage` | Active devices with a healthy EDR agent |
| `ctem_host_hardening` | Host firewall on, USB mass storage blocked |
| `ctem_asset_inventory` | Active devices with an owner and criticality; single-source assets |
| `ctem_stale_ad_computers` | AD computers with no logon in 90 days |
| `ctem_kev_remediation` | Open CISA KEV findings past their deadline |
| `ctem_vuln_sla` | Critical/high findings past SLA (optionally reachable only) |
| `ctem_vuln_age` | Open findings older than allowed for Infrastructure, Code and Web apps: each severity's SLA from Change SLAs (or one ceiling), with the age profile |
| `ctem_admin_local_logons` | Workstations and servers where an admin or service account (`adm*`, `svc_*`, `sulocal_*` by default) signed in interactively, from the EDR's sign-in history; rules can change the patterns and leave out jump servers |
| `ctem_deprovisioning` | Leaver access left behind, from AD/LDAP: disabled accounts still in groups, enabled accounts in a Disabled/Terminated OU, and long-idle enabled accounts (suits controls like "Automated deprovision of account triggers") |
| `ctem_unauthorized_software` | Assets running software marked Unauthorized in the software inventory (an error, never a pass, until some source reports software) |
| `ctem_exposed_criticals` | Internet-facing devices with critical or KEV findings |
| `ctem_attack_paths` | Open validated attack paths |
| `ctem_risk_exceptions` | Expired or permanent risk exceptions |
| `ctem_dormant_accounts` | Enabled people accounts idle 90+ days |
| `ctem_password_policy` | People accounts whose passwords never expire |
| `ctem_privileged_accounts` | AD admin group members: count, idle, disabled leftovers |
| `ctem_itdr_alerts` | Open critical/high ITDR alerts and their age |
| `ctem_shadow_ai` / `ctem_shadow_saas` | Unsanctioned AI / SaaS apps in use |
| `ctem_monitoring_health` | Every telemetry source syncing, every shipper checking in |

- `GET /api/v1/grc/checks` lists them with default thresholds and suggested control mappings; `GET /api/v1/grc/checks/{type}` runs one (thresholds can be overridden within their bounds).
- A check whose source data is missing or older than its window returns `error`, never `pass`.
- Results sent to FairTPRM carry counts only. The detail behind a check (hosts, CVEs, accounts) comes from `/checks/{type}/report`, signed with Ed25519 (`X-CTEM-Evidence-Signature` over the exact body; public key at `/api/v1/grc/evidence-key`), formula-safe as CSV, and every download is audited.
- In CTEM, click a check on the GRC page to see that detail as a remediation list (`/grc/checks/{type}`, API `/api/v1/grc/checks/{type}/items`): searchable, sortable, paged, with each device linked to its page.
- `/checks/{type}/history?from=&to=` rolls up daily results (up to 400 days) for audit-period evidence; every check runs daily so there are no gaps.
- **Connecting FairTPRM:** GRC page > **FairTPRM access** (admin) creates a read-only, IP-bound token for the `svc-fairtprm-grc` service account. Enter that token and the CTEM URL in FairTPRM's open-ctem integration.

---

## Curated rules

**Admin > Curated Rules** lets an admin change what a control check counts without code. A rule is a JSON document in the `open-ctem/curated-rule@1` standard (schema at `/api/v1/rules/schema`):

```json
{"schema": "open-ctem/curated-rule@1", "name": "EDR coverage: workstations and servers only",
 "check": "ctem_edr_coverage", "scope": {"include": {"device_types": ["workstation", "server"]}}}
```

- **Scope** (device-based checks: EDR coverage, host hardening, asset inventory, stale AD computers, KEV, SLA, internet-facing exposure): `include` and `exclude` take `device_types`, `os_contains`, `os_starts_with`, `hostname_patterns` (`*` and `?`), `tags`, `sources`, `criticality`, `internet_facing` and `edr_contained` (true when the EDR has network-isolated the device). Source names take any case and common names (`CrowdStrike`, `InsightVM`, `Defender`). A device must meet every `include` condition, and is left out if it meets any one `exclude` condition; values in one list are alternatives. To leave out only a combination, make `exclude` a list of blocks: a device is left out when it meets every condition of any one block, for example `"exclude": [{"sources_only": ["rapid7_insightvm"], "not_seen_days": 5}]` drops old scan records only the scanner still holds. `sources_only` means reported by those sources and no other; `not_seen_days` means no source has seen the device for that many days. Printers and firewalls are often typed `unknown` by scanners, so exclude them by `os_contains` too (for example `printer`, `ricoh`, `fortigate`).
- **Thresholds**: a rule can move a check's thresholds, only inside the bounds the check already allows. They become the org's defaults; a FairTPRM monitor's explicit parameter still wins. Two enabled rules can't set the same threshold differently.
- **Plain English**: with an AI integration enabled, type the rule ("for EDR coverage only count workstations and servers") and AI drafts the JSON. The draft is validated like anything typed and is never saved until you save it.
- **Preview** shows the check's result now and with the rule, how many devices stay in scope, and examples of what it leaves out.
- **New checks** (`open-ctem/custom-check@1`, "+ New check"): a rule can also create a control check, named `ctem_custom_<id>`, that the GRC page, its remediation list and FairTPRM monitors use like a built-in one. `population` is the devices it looks at and `match` the condition, using the same filters plus `ad_joined`, `ad_stale_days` (no AD logon for N days, or never), `sources_only` (reported by those sources and no other), `seen_within_days` / `not_seen_days` (a scan, EDR heartbeat or AD logon within, or not within, N days) and `inventory_status` (`in_use`, `shipped`, `lost`, `stolen`, `returned`). `measure: "count"` counts matching devices (fewer is better, `pass_max` / `warn_max`) and lists them; `measure: "percent"` is the share that match (more is better, `pass_at` / `warn_at`) and lists the rest. Optional `controls` become its suggested mappings. Disabling or deleting it removes the check; its history stays.

```json
{"schema": "open-ctem/custom-check@1", "name": "Servers with a vulnerability scan", "id": "scanned_servers",
 "measure": "percent", "population": {"device_types": ["server"]},
 "match": {"sources": ["rapid7_insightvm", "qualys"]}, "thresholds": {"pass_at": 95, "warn_at": 85}}
```

- Rules are filters on an allow-list of fields; nothing in a rule runs as code or SQL, and rules never change stored data. Every result records the rules (name and version) that shaped it, in CTEM and in the evidence FairTPRM keeps. A rule that stops validating (say a check changed) makes its check report an error instead of silently measuring something else. Every change is audited.

## Authentication modes

| Mode | Behavior |
|---|---|
| `oidc_only` | Immediately redirects to the IdP; no local sign-in form |
| `local_only` | Username + password + TOTP only |
| `both` | Login page shows the local form and the SSO button |

### Single sign-on (OIDC)

**Admin > Single sign-on** (admin) walks through it:

1. Pick **Okta**, **Auth0**, **Ping Identity (PingOne)** or **Microsoft 365 (Entra ID)**. CTEM shows that provider's current setup steps with its own redirect URI (`https://<PUBLIC_URL>/auth/callback`) and sign-out URL filled in.
2. Enter what the provider needs (Okta domain and authorization server, Auth0 domain, PingOne region and environment ID, or Entra tenant ID); CTEM builds the issuer.
3. Paste the client ID and secret. The secret is encrypted at rest and never shown again.
4. Choose the **default role** for new people (No Access unless you change it; never admin), the **message** people with No Access see, and SSO-and-local or SSO-only.
5. **Test** checks the provider's live discovery document, issuer, signing keys, PKCE and client-secret support. Save, then sign in from a private window.

Roles are pinned to people in **Admin > Users**; signing in never changes them. Anyone whose only role is **No Access** sees the configured message and gets no session. ID tokens are verified against the provider's signing keys (asymmetric algorithms only) with issuer, audience, expiry and nonce checks, and an SSO sign-in never attaches to an existing local or directory account.

**Break-glass:** environment variables win over the wizard. `AUTH_MODE=local_only` in `.env` brings the local sign-in back if the IdP or the settings break; `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and `OIDC_REDIRECT_URI` configure SSO without the database. Remove `AUTH_MODE` from `.env` to let the wizard choose the sign-in mode. `PUBLIC_URL` must be set for SSO.

Signed-out visits to a CTEM page (for example a link in an email) return to that page after password, MFA or SSO sign-in; only same-site paths are honored.

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
# Docs:  https://localhost/api/docs  (signed-in admin or cyber analyst)
```

Requirements: Docker 24+, Docker Compose v2.

### Upgrading a server

```bash
sudo bash /data/docker/ctem/install.sh --upgrade
```

It refuses to run over uncommitted local changes, backs up the database to `.backups/`, fast-forwards the checkout from `origin`, pulls the base images, rebuilds the app, worker and beat images, restarts the stack and waits for `/health`. If the app doesn't come up healthy it rolls the code back and rebuilds the previous version. A local `docker/docker-compose.override.yml` is honored. Schema changes apply on startup, so there's no separate migration step. Shippers on other boxes are upgraded separately (see On-prem shippers).

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
| `inventory` | Every device (no findings); sets who a device is assigned to and whether it's shipped, lost, stolen or returned |

Roles are fully customizable -- create new ones, duplicate existing ones, assign granular permissions.

**Device assignment and status.** CTEM links each device to the directory user CrowdStrike last saw signing in (`ACME\jdoe`, `jdoe@acme.example`, and admin-style accounts listed in `ACCOUNT_ALIAS_PATTERNS`... see `ACCOUNT_ALIAS_PREFIXES`, default `sulocal_`). That detected user is only a hint and never grants access. Who a device is *supposed* to belong to is set by a person with the `admin` or `inventory` role and kept in its own table that syncs never touch: **Assign** (or confirm the detected user with one click), plus a status of **Shipped** (UPS, FedEx, USPS or DHL with a tracking number), **Lost**, **Stolen** or **Returned**. The inventory shows the assigned user with a check mark and filters by status; assigning and the sign-in details are on the device page. Alias sign-ins that use a first name (`sulocal_akash`) link only when exactly one active person has that first name. Inventory search finds devices by partial username of the assigned or detected user or by their full UPN (`jdoe@ad.acme.example`), and `jdoe` also finds `sulocal_jdoe` sign-ins. Sign-ins in UPN form link to the matching person, and the device page shows each person's UPN and title (from the AD shipper 1.0.3 or later). Every change is audited.

| REST endpoint | What it does |
|---|---|
| `GET /api/v1/devices?status=assigned\|shipped\|lost\|stolen\|returned` | List devices (each has `assigned_user`, `detected_user`, `last_login_user`, `inventory_status`) |
| `PUT /api/v1/devices/{id}/assignment` `{"user_id", "note"}` | Assign (admin / inventory) |
| `DELETE /api/v1/devices/{id}/assignment` | Unassign; any status stays |
| `PUT /api/v1/devices/{id}/status` `{"status", "carrier", "tracking_number", "note"}` | Set status; `shipped` needs a carrier and tracking number, `null` puts it back in use |
| `GET /api/v1/devices/assignable-users?q=` | Directory users for a picker |

Use an API token (`Authorization: Bearer ...`) owned by an admin or inventory user. Interactive docs for every endpoint are at `/api/docs` for signed-in admins and cyber analysts.

---

## Dashboards

The executive dashboard filters by tag category: **Executive Owner**, **Technical Owner**, **Application**, **Environment**, **Severity** -- all driven by the tag system. Each filter narrows the entire view to assets matching that tag combination.

**AI usage** (Admin > AI Usage): month-to-date AI cost and tokens against optional monthly limits (dollars and/or tokens), with a forecast and per-model / per-feature breakdowns. Claude models are priced from Anthropic list prices; custom, OpenAI-compatible and Amazon Bedrock providers use the input/output/cache prices you enter there (Bedrock falls back to Anthropic list prices as an estimate).

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
