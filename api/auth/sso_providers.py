"""OIDC providers CTEM knows how to set up: the fields an admin fills in, the issuer they make, and setup steps.

Setup steps follow each vendor's documentation as of November 2026 (Okta Classic + Identity Engine admin
console, Auth0 Dashboard, PingOne, Microsoft Entra admin center). Roles are assigned in CTEM, not from IdP groups. Placeholders in steps:
{redirect_uri}, {signout_uri}, {app_name}.
"""
from __future__ import annotations

import re

HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
OKTA_SERVER_RE = re.compile(r"^(org|default|[A-Za-z0-9]{1,32})$")
PING_REGIONS = {"com": "North America", "eu": "Europe", "ca": "Canada", "asia": "Asia-Pacific", "com.au": "Australia"}


def _host(v: str) -> str:
    v = (v or "").strip().lower().removeprefix("https://").rstrip("/")
    if not HOST_RE.match(v):
        raise ValueError("enter just the host name, like acme.okta.com")
    return v


def okta_issuer(f: dict) -> str:
    host = _host(f.get("domain", ""))
    server = (f.get("auth_server") or "org").strip()
    if not OKTA_SERVER_RE.match(server):
        raise ValueError("authorization server must be org, default, or a server ID")
    return f"https://{host}" if server == "org" else f"https://{host}/oauth2/{server}"


def auth0_issuer(f: dict) -> str:
    return f"https://{_host(f.get('domain', ''))}/"  # Auth0 issuers end with a slash


def ping_issuer(f: dict) -> str:
    region = (f.get("region") or "com").strip()
    env = (f.get("environment_id") or "").strip().lower()
    if region not in PING_REGIONS:
        raise ValueError("pick a PingOne region")
    if not UUID_RE.match(env):
        raise ValueError("environment ID is a UUID (Settings > Environment Properties in PingOne)")
    return f"https://auth.pingone.{region}/{env}/as"


def entra_issuer(f: dict) -> str:
    tenant = (f.get("tenant_id") or "").strip().lower()
    if not UUID_RE.match(tenant):
        raise ValueError("Directory (tenant) ID is a GUID from the app's Overview page")
    return f"https://login.microsoftonline.com/{tenant}/v2.0"


PROVIDERS: dict[str, dict] = {
    "okta": {
        "label": "Okta",
        "issuer": okta_issuer,
        "scopes": "openid profile email",
        "fields": [
            {"key": "domain", "label": "Okta domain", "placeholder": "acme.okta.com",
             "help": "Your Okta org URL without https://, or your custom URL domain."},
            {"key": "auth_server", "label": "Authorization server", "placeholder": "org",
             "help": "org (default, issuer is your Okta domain), default, or a custom authorization server ID."},
        ],
        "steps": [
            "In the Okta Admin Console go to Applications > Applications and click Create App Integration.",
            "Sign-in method: OIDC - OpenID Connect. Application type: Web Application. Click Next.",
            "App integration name: {app_name}. Grant type: keep Authorization Code checked (Refresh Token isn't needed).",
            "Sign-in redirect URIs: {redirect_uri}",
            "Sign-out redirect URIs: {signout_uri}",
            "Assignments: choose Limit access to selected groups and pick the groups that should use CTEM. Save. "
            "Only assigned people can sign in.",
            "On the General tab, under Client Credentials, copy the Client ID and Client secret into this page. "
            "Client authentication should be Client secret; PKCE can stay on (CTEM always sends it).",
            "Using a custom authorization server (API Access Management)? Set Authorization server above to its ID "
            "(for example default); otherwise leave it as org.",
            "Click Test, then try signing in from a private window. New people land on the default role (No Access "
            "unless you change it) until you give them a role in Admin > Users.",
        ],
    },
    "auth0": {
        "label": "Auth0",
        "issuer": auth0_issuer,
        "scopes": "openid profile email",
        "fields": [
            {"key": "domain", "label": "Auth0 domain", "placeholder": "acme.us.auth0.com",
             "help": "Settings > Basic Information > Domain (or your custom domain)."},
        ],
        "steps": [
            "In the Auth0 Dashboard go to Applications > Applications and click Create Application.",
            "Name it {app_name}, choose Regular Web Applications, and click Create.",
            "On the Settings tab copy Domain, Client ID and Client Secret (Reveal Client Secret) into this page.",
            "Allowed Callback URLs: {redirect_uri}",
            "Allowed Logout URLs: {signout_uri}",
            "Under Advanced Settings > OAuth keep JSON Web Token Signature Algorithm at RS256 and OIDC Conformant on. Save Changes.",
            "Auth0 has no per-application assignment: to limit who can sign in, add a Login / Post Login Action "
            "that calls api.access.deny() for users who shouldn't use CTEM, or restrict the connection.",
            "Click Test, then try signing in from a private window.",
        ],
    },
    "ping": {
        "label": "Ping Identity (PingOne)",
        "issuer": ping_issuer,
        "scopes": "openid profile email",
        "fields": [
            {"key": "region", "label": "PingOne region", "options": PING_REGIONS,
             "help": "The domain your PingOne console uses: auth.pingone.com, .eu, .ca, .asia or .com.au."},
            {"key": "environment_id", "label": "Environment ID", "placeholder": "00000000-0000-0000-0000-000000000000",
             "help": "Settings > Environment > Properties, or the Overview of the application."},
        ],
        "steps": [
            "In the PingOne admin console open the environment, go to Applications > Applications and click +.",
            "Name it {app_name}, choose OIDC Web App, and click Save.",
            "On the Configuration tab click the pencil: Response Type Code, Grant Type Authorization Code, "
            "Token Endpoint Authentication Method Client Secret Post. For PKCE Enforcement pick the strictest "
            "S256 option offered (CTEM always sends an S256 challenge).",
            "Redirect URIs: {redirect_uri}",
            "Signoff URLs: {signout_uri}",
            "Resources tab: make sure openid, profile and email are in Allowed Scopes.",
            "Access tab: add the groups allowed to sign in to CTEM (Group Membership Policy).",
            "Copy Client ID, Client Secret and the Environment ID from the Configuration / Overview tabs into this page.",
            "Turn the application on with the toggle at the top right of its page.",
            "Click Test here (it checks the regional issuer), then try signing in from a private window.",
        ],
    },
    "entra": {
        "label": "Microsoft 365 (Entra ID)",
        "issuer": entra_issuer,
        "scopes": "openid profile email",
        "fields": [
            {"key": "tenant_id", "label": "Directory (tenant) ID", "placeholder": "00000000-0000-0000-0000-000000000000",
             "help": "App registration Overview > Directory (tenant) ID. A GUID, not a domain name."},
        ],
        "steps": [
            "In the Microsoft Entra admin center (entra.microsoft.com) go to Entra ID > App registrations > New registration.",
            "Name {app_name}; Supported account types: Single tenant only; Redirect URI platform Web with {redirect_uri}. Register.",
            "From Overview copy Application (client) ID and Directory (tenant) ID into this page.",
            "Certificates & secrets > Client secrets > New client secret. Pick an expiry (Microsoft recommends 180 days; "
            "max 24 months), copy the secret Value (not the Secret ID) into this page, and diary the renewal.",
            "Authentication: under Front-channel logout URL enter {signout_uri}. Leave the implicit grant boxes unchecked.",
            "Enterprise applications > {app_name} > Properties: set Assignment required? to Yes, then add the allowed "
            "users or groups under Users and groups.",
            "Click Test, then try signing in from a private window.",
        ],
    },
}


def issuer_for(provider: str, fields: dict) -> str:
    if provider not in PROVIDERS:
        raise ValueError("unknown provider")
    return PROVIDERS[provider]["issuer"](fields)


def catalog(redirect_uri: str, signout_uri: str, app_name: str) -> list[dict]:
    out = []
    for key, p in PROVIDERS.items():
        steps = [s.replace("{redirect_uri}", redirect_uri).replace("{signout_uri}", signout_uri)
                 .replace("{app_name}", app_name) for s in p["steps"]]
        out.append({"key": key, "label": p["label"], "fields": p["fields"], "steps": steps,
                    "default_scopes": p["scopes"]})
    return out
