# Caller verification in ServiceNow

Service desk analysts verify a caller before helping them: from the ticket, they send a Persona identity check to
the caller's **verified MFA phone or email** and watch the result arrive in the ticket.

## Set up (CTEM admin)

IDV page > **Iframe Code** > New embed:

| Field | What to put |
| --- | --- |
| Name | e.g. ServiceNow production |
| Service desk site | The instance's exact address, e.g. `https://acme.service-now.com` (no path, no wildcard) |
| Service desk server addresses | The instance's outbound IP ranges (ServiceNow support lists them for your instance) |
| Analysts' network ranges | The office and VPN egress ranges analysts browse from |

CTEM shows the token **once**, the steps for the ServiceNow admin, and the UI Macro code to paste. Revoke an embed
there and its token and every open panel stop at once.

## Set up (ServiceNow admin, about 10 minutes)

1. System Properties > New: `x_ctem.idv_desk_token`, type `password2`, value = the token, read and write roles `admin`.
2. System UI > UI Macros > New: name `ctem_caller_verification`, paste the code as it is.
3. System UI > Formatters > New: name "Caller verification", formatter `ctem_caller_verification.xml`, table Incident.
4. Incident form > Configure > Form Layout: add "Caller verification". Save.

If the panel says "unavailable", look in System Logs > Warnings for "CTEM caller verification". If the panel is
blank, the instance's own policy may block frames from other sites: allow the CTEM address there.

## How it is kept to ServiceNow

- **Only ServiceNow's servers start a panel.** The macro's server part calls CTEM with the embed's API token, which
  works only from the server ranges set on the embed. A browser session can't start one.
- **Only the embed's site can frame it.** The panel page sends `Content-Security-Policy: frame-ancestors <site>`;
  every other CTEM page stays unframeable. The page itself holds no data.
- **A one-time launch token in the URL fragment** (never sent to a server, so never in a log), valid 2 minutes, used
  once, traded for a session key that lives only in the panel's memory for 30 minutes and works only from the
  analyst's address, which must be in the analysts' ranges. No cookies, so nothing rides on a sign-in.
- **CORS stays closed.** CTEM sends no `Access-Control-Allow-Origin`; no other site's script reads any of it.
- **Same rules as the rest of CTEM.** The link goes only to a contact the identity provider verified; a contact
  changed in the last 7 days needs the analyst to confirm it; limits per caller and per hour; everything audited with
  the ticket and analyst.
- **The result** is posted to the ticket's page only at the embed's exact site, and ServiceNow's server can read it
  with its token: `GET /api/v1/idv/desk/sessions/{session}` (`verified: true/false`).
