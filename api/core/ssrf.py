"""SSRF-safe outbound HTTP client. DNS-pinned, blocks private/metadata IPs."""
from __future__ import annotations

import ipaddress
import os
import socket
from typing import Any

import httpx

# Admin-controlled allowlist: comma-separated hostnames that bypass the SSRF check.
# Use ONLY for local test containers (e.g. SSRF_BYPASS_HOSTS=test-splunk,test-ldap).
_BYPASS_HOSTS = {h.strip() for h in os.getenv("SSRF_BYPASS_HOSTS", "").split(",") if h.strip()}

# Blocks loopback, private, link-local, and AWS/GCP metadata ranges
_BLOCKED_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + AWS metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_MAX_REDIRECTS = 5
_DEFAULT_TIMEOUT = 30.0


class SSRFBlocked(ValueError):
    """Destination resolves somewhere we refuse to go."""


class SSRFUnresolvable(ValueError):
    """Destination doesn't resolve (yet)."""


def _is_blocked(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in net for net in _BLOCKED_NETS)
    except ValueError:
        return True


def _resolve_and_validate(host: str) -> str | None:
    """Return the IP to connect to, or None for an allowlisted test host."""
    if host in _BYPASS_HOSTS:
        return None
    try:
        info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFUnresolvable(f"DNS resolution failed for {host!r}") from e
    addrs = [sockaddr[0] for *_, sockaddr in info]
    # Every answer must be clean, or a mixed record set could sneak one through
    if not addrs or any(_is_blocked(a) for a in addrs):
        raise SSRFBlocked(f"{host!r} resolves to a blocked address")
    return addrs[0]


class _SSRFTransport(httpx.AsyncHTTPTransport):
    """Validates every hop and connects to the exact IP that passed validation."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.scheme not in ("http", "https"):
            raise SSRFBlocked(f"Only http/https allowed, got {request.url.scheme!r}")
        host = request.url.host
        ip = _resolve_and_validate(host)
        if ip is not None:
            # Pin: connect to the vetted IP, keep Host and TLS SNI on the name
            request.headers["Host"] = request.url.netloc.decode("ascii")
            request.extensions = {**request.extensions, "sni_hostname": host}
            request.url = request.url.copy_with(host=ip)
        return await super().handle_async_request(request)


def safe_client(**kwargs: Any) -> httpx.AsyncClient:
    """Return an httpx client that refuses SSRF targets."""
    verify = kwargs.pop("verify", True)
    return httpx.AsyncClient(
        transport=_SSRFTransport(verify=verify),
        follow_redirects=True,
        max_redirects=_MAX_REDIRECTS,
        timeout=kwargs.pop("timeout", _DEFAULT_TIMEOUT),
        verify=verify,
        **kwargs,
    )
