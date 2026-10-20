"""Guards for outbound requests to user-supplied hosts."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(:\d{1,5})?$")


class UnsafeHostError(ValueError):
    pass


def normalize_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if not _HOST_RE.match(host):
        raise UnsafeHostError(f"not a valid host name: {host!r}")
    return host


async def ensure_public_host(host: str, allow_private: bool) -> None:
    """Refuse hosts that resolve to loopback/private/link-local addresses (SSRF guard).

    Note: this checks at lookup time only; a hostile DNS server could rebind between
    check and request. Good enough for a prototype; pin resolved IPs before production.
    """
    if allow_private:
        return
    name, _, port = host.partition(":")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(name, int(port or 443), type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UnsafeHostError(f"cannot resolve {name}") from e
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if not addr.is_global:
            raise UnsafeHostError(f"{name} resolves to a non-public address")
