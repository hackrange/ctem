"""The client address and scheme come from X-Forwarded-For / X-Forwarded-Proto only when the request came from the
reverse proxy (nginx). Anything else on the Docker network (another container joined to it) that reaches the app
directly is seen as itself, so it can't pick the address API token allow-lists, shipper pins and sign-in throttling
look at.

The proxy is named, not numbered (TRUSTED_PROXY_HOST, "nginx" in the image), and resolved again when a request comes
from an address it doesn't know, so a recreated nginx container is followed. If the name can't be resolved at all
the headers are trusted as before (logged), so a deployment that names its proxy differently never sees every person
arrive from one address and get throttled together. Unset, no forwarded header is read (tests, a bare app)."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time

log = logging.getLogger("open-ctem.proxy")
REFRESH = 30.0     # seconds a resolved address set is reused
RETRY = 5.0        # an unknown peer triggers a fresh lookup at most this often


def _header(scope, name: bytes) -> str | None:
    for k, v in scope.get("headers") or []:
        if k == name:
            return v.decode("latin-1")
    return None


class TrustedProxyMiddleware:
    def __init__(self, app, host: str = "") -> None:
        self.app, self.host = app, (host or "").strip()
        self._ips: set[str] = set()
        self._at = 0.0
        self._warned = 0.0

    async def _resolve(self) -> set[str] | None:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(self.host, None, type=socket.SOCK_STREAM)
            return {i[4][0] for i in infos}
        except OSError:
            return None

    async def _trusted(self, peer: str) -> bool:
        now = time.monotonic()
        stale = now - self._at > REFRESH or (peer not in self._ips and now - self._at > RETRY)
        if stale:
            got = await self._resolve()
            self._at = now
            if got is None:
                if now - self._warned > 300:
                    self._warned = now
                    log.warning("reverse proxy %r not resolvable; trusting forwarded headers from any peer", self.host)
                self._ips = set()
                return True
            self._ips = got
        return peer in self._ips if self._ips else True

    async def __call__(self, scope, receive, send):
        if self.host and scope["type"] in ("http", "websocket"):
            peer = (scope.get("client") or (None, None))[0]
            if peer and await self._trusted(peer):
                xff = _header(scope, b"x-forwarded-for")
                if xff:
                    ip = xff.split(",")[-1].strip()   # the entry the proxy itself wrote
                    try:
                        ipaddress.ip_address(ip)
                        scope = {**scope, "client": (ip, 0)}
                    except ValueError:
                        pass
                proto = (_header(scope, b"x-forwarded-proto") or "").strip().lower()
                if proto in ("http", "https"):
                    scheme = ("wss" if proto == "https" else "ws") if scope["type"] == "websocket" else proto
                    scope = {**scope, "scheme": scheme}
        await self.app(scope, receive, send)
