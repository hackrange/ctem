"""SSRF-safe outbound HTTP client. DNS-pinned, blocks private/metadata IPs."""
from __future__ import annotations

import ipaddress
import socket
from typing import Any

import httpx

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


def _is_blocked(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _BLOCKED_NETS)
    except ValueError:
        return True


def _resolve_and_validate(host: str) -> str:
    """Resolve host to IP and block private/metadata ranges."""
    try:
        info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for {host!r}: {e}") from e

    for family, _, _, _, sockaddr in info:
        addr = sockaddr[0]
        if _is_blocked(addr):
            raise ValueError(f"Blocked IP {addr} resolved from {host!r}")
        return addr  # first non-blocked address wins

    raise ValueError(f"No usable address resolved for {host!r}")


class _SSRFTransport(httpx.AsyncHTTPTransport):
    """Wraps the default transport with DNS pinning per request."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if request.url.scheme not in ("http", "https"):
            raise ValueError(f"Only http/https allowed, got {request.url.scheme!r}")
        _resolve_and_validate(host)
        return await super().handle_async_request(request)


def safe_client(**kwargs: Any) -> httpx.AsyncClient:
    """Return an httpx client that refuses SSRF targets."""
    return httpx.AsyncClient(
        transport=_SSRFTransport(),
        follow_redirects=True,
        max_redirects=_MAX_REDIRECTS,
        timeout=kwargs.pop("timeout", _DEFAULT_TIMEOUT),
        **kwargs,
    )
