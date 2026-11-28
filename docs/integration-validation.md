# Integration status

Every integration should work against the vendor's real API, not a guess of it. This page says which ones are
verified and which aren't yet.

- **Verified:** checked against the vendor's API reference or official SDK, run against a real tenant, and covered
  by tests.
- **In progress:** rebuilt and confirmed against a live tenant, waiting on a first full run before it's checked off.
- **Coming soon:** written, but not yet checked that way. Its endpoints, authentication or response fields may
  not match the real API, so treat it as untested until it moves up this page.

Vendor APIs are read only, except where a feature needs to write and says so (see the README's Integrations section).

## Verified

| Integration | Notes |
|---|---|
| Rapid7 InsightVM (cloud and console), AppSec | |
| CrowdStrike Falcon (shipper) | Formats checked against CrowdStrike's gofalcon SDK |
| LDAP / Active Directory (shipper) | Pages the whole directory |
| Splunk (shipper search) | |
| FairTPRM | Both directions |
| GitHub Code Review | |
| AWS, Oracle OCI | |
| Anthropic | |
| Zscaler (OneAPI) | One token request, then GETs on an allow-list of paths |
| Okta | GETs on an allow-list of paths; rate-limit headers honored, with half of each bucket left for the org |
| Tanium (Cloud API Gateway) | GraphQL over GET, read queries only, an allow-list of sensors (never BitLocker Key) |
| Grip Security | GET only |
| Rapid7 InsightCloudSec | GET only; confirmed against a live tenant and in production use |
| Persona | Identity verification: creates, approves and declines inquiries |

## In progress

| Integration | Status |
|---|---|
| Horizon3.ai NodeZero | Rebuilt on the GraphQL API, confirmed field by field against a live tenant; checked off after its first full sync |
| Email (SMTP, Microsoft 365) | Checked off after a test send on each |
| Twilio | SMS for identity verification; checked off after a test send |

## Coming soon

Palo Alto Cortex XDR, Fortinet (FortiGate / FortiAnalyzer), Snyk, Microsoft Defender for Endpoint, SentinelOne,
Palo Alto NGFW, GitHub Advanced Security, ForgeRepo, Qualys VMDR, Akamai Guardicore, ServiceNow (ticket write-back),
Microsoft Azure, and the OpenAI, custom and Amazon Bedrock AI endpoints.

To verify one: read the vendor's API reference and official SDK, confirm authentication, endpoints, pagination, rate
limits and response fields, fix the connector, add tests built from documented responses, and run it against a real
tenant.
