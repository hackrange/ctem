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
# Internal address space (RFC 1918, IPv6 unique local): where a site's own hosts live (api/core/location.py)
INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))

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


_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _tunneled_v4(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """The IPv4 address a translation or tunnel address really reaches (NAT64, 6to4, Teredo)."""
    if ip in _NAT64:
        return [ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)]
    if ip.sixtofour is not None:
        return [ip.sixtofour]
    return list(ip.teredo or ())


def _bad(ip) -> bool:
    return (ip.is_unspecified or ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or any(ip in net for net in _BLOCKED_NETS if net.version == ip.version))


def _is_blocked(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])   # drop an IPv6 zone id before parsing
    except ValueError:
        return True
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.version == 6:
        # Judge a NAT64/6to4/Teredo address by the IPv4 host behind it, so IPv6-only sites still reach public APIs
        inner = _tunneled_v4(ip)
        if inner:
            return any(_bad(v) for v in inner)
    return _bad(ip)


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
