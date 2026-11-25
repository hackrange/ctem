# Integration validation

open-ctem is public, so every integration has to work against the vendor's real API, not a guess of it. This is
the checklist: what's verified, and what still needs in-depth research and a fix before it's offered as working.

**Verified** means checked against the vendor's own API reference or official SDK, run against a real tenant, and
covered by tests. **Unverified** means written but not yet checked that way: its endpoints, auth and response
fields may not match the real API (the Horizon3 connector, for one, called endpoints the API doesn't have).

## Verified

| Integration | How it was verified |
|---|---|
| Rapid7 InsightVM (cloud and console), AppSec | Real tenant |
| CrowdStrike Falcon (shipper) | Real tenant; formats checked against CrowdStrike's gofalcon SDK |
| LDAP / Active Directory (shipper) | Real directory |
| Splunk (shipper search) | Real search head |
| FairTPRM | Real instance, both directions |
| GitHub Code Review | Real instance |
| AWS, Oracle OCI | Real accounts |
| Anthropic | Real API |
| Zscaler (OneAPI) | Real tenant, 2026-11-24: token POST plus GETs on an allow-list; Client Connector (15,244 devices), ZDX devices, ZIA URL, SSL, firewall and DLP rules and admins |
| Okta | Real tenant, 2026-11-25: GET only on the allow-list; users, devices (11,729 active Windows and macOS computers; Okta pages devices with users 20 at a time), MFA factors, System Log security events; rate-limit headers honored with half of each bucket left for the org |
| Grip Security | Real tenant, 2026-11-24: every read endpoint, a full sync (227 ITDR threats, 606 posture findings, 3,266 SaaS apps, 68 AI agents, 14,665 identities) with GET only; paths match open-fairtprm's working client |

## In progress

- [ ] **Rapid7 InsightCloudSec**: the old connector searched each Insight with `POST /v2/public/resource/query`, which
  answered 500 to every call on a real tenant (it was listed as verified before any key worked). Rebuilt, GET only, on
  `GET /v4/insights/findings-per-cloud/{id}/` per cloud account from `GET /v2/public/clouds/list`, joined to
  `GET /v2/public/insights/list`; all three confirmed against a live tenant. To check off after its first full sync.
- [ ] **Horizon3.ai NodeZero**: rebuilt on the GraphQL API; auth, pentests, weaknesses, services, hosts, attack
  paths, credentials and data stores confirmed field by field against a live tenant (introspection is disabled). To
  check off after its first full sync.
- [ ] **Email (SMTP, Microsoft 365)**: rebuilt as an integration; to check off after a test send on each.

## To research and fix

For each: read the vendor's API reference and official SDK or CLI, confirm auth, endpoints, pagination, rate
limits and response fields, fix the connector, register it (`api/integrations/__init__.py`), add tests built
from documented responses, and test against a real tenant where one is available.

| Integration | Registered | Tests | Notes |
|---|---|---|---|
| [ ] Palo Alto Cortex XDR | yes | none | API key + key id, advanced key hashing (nonce, timestamp) |
| [ ] Fortinet (FortiGate / FortiAnalyzer) | yes | none | which product's API, REST token |
| [ ] Snyk | yes | some | REST vs v1 API, org and project paging |
| [ ] Microsoft Defender for Endpoint | yes | some | Entra app, machine and vulnerability APIs |
| [ ] SentinelOne | yes | some | API token, sites, agents, threats |
| [ ] Tanium | yes | none | Gateway GraphQL vs REST |
| [ ] Palo Alto NGFW | yes | none | XML/REST API, keygen |
| [ ] GitHub Advanced Security | yes | none | code scanning, Dependabot, secret scanning alerts |
| [ ] ForgeRepo | yes | none | |
| [ ] Qualys VMDR | yes | some | XML API v2, platform URL per subscription |
| [ ] Akamai Guardicore | yes | some | |
| [ ] ServiceNow | yes | some | ticket write-back |
| [ ] Microsoft Azure | n/a (cloud) | some | Resource Graph, NSGs |
| [ ] OpenAI, custom AI endpoint, Claude on Amazon Bedrock | via the AI connector | some | |

Until an integration is checked off here, treat it as untested.
