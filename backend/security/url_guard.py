"""SSRF guard for user-supplied outbound URLs (Web Push endpoints).

KRY-002: `PushSubscription.endpoint` is attacker-controlled and was handed
straight to pywebpush, which posts to it with `requests` — and `requests`
follows redirects by default. That made the server an HTTP client pointed
wherever the attacker liked, including cloud metadata services and anything
reachable on the internal network.

Defence, in layers:

1. Parse and require HTTPS with a plain hostname (no userinfo, no odd port).
2. Resolve the hostname and reject every address that is not global unicast —
   loopback, private, link-local (169.254.169.254 lives here), multicast,
   reserved.
3. Pin the connection to the addresses validated in step 2, so a name that
   resolves benignly during validation cannot resolve to an internal address
   moments later when the request actually goes out (DNS rebinding).
4. Refuse redirects, so a permitted host cannot bounce us to a forbidden one.

Steps 1-2 alone are a TOCTOU race; 3 is what actually closes it.
"""
import ipaddress
import logging
import socket
from typing import List, Sequence
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = ("https",)

# Belt and braces around `is_global`: these ranges must never be reachable.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("10.0.0.0/8"),       # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC1918
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]

MAX_ENDPOINT_LENGTH = 2000


class UnsafeUrlError(ValueError):
    """Raised when a URL is not a safe outbound destination."""


def _address_is_safe(ip: ipaddress._BaseAddress) -> bool:
    """True only for globally-routable unicast addresses."""
    if ip.is_loopback or ip.is_private or ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    # IPv4-mapped/compatible IPv6 (::ffff:127.0.0.1) smuggles v4 past v6 checks.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None and not _address_is_safe(mapped):
        return False
    if any(ip in net for net in _BLOCKED_NETWORKS if net.version == ip.version):
        return False
    return bool(getattr(ip, "is_global", True))


def resolve_safe_addresses(hostname: str, port: int) -> List[str]:
    """Resolve `hostname`, requiring every returned address to be safe.

    Every address must pass: a name resolving to both a public and an internal
    address must not be usable, since we cannot control which one is dialled.
    """
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"Cannot resolve host: {hostname}") from exc

    if not infos:
        raise UnsafeUrlError(f"Cannot resolve host: {hostname}")

    addresses = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise UnsafeUrlError(f"Unparseable address for host: {hostname}")
        if not _address_is_safe(ip):
            raise UnsafeUrlError(
                f"Host {hostname} resolves to a non-public address ({addr})"
            )
        addresses.append(addr)

    return addresses


def validate_push_endpoint(endpoint: str) -> List[str]:
    """Validate a Web Push endpoint URL. Returns the resolved safe addresses.

    Raises UnsafeUrlError with a caller-safe message on any violation.
    """
    if not endpoint or not isinstance(endpoint, str):
        raise UnsafeUrlError("Endpoint must be a non-empty string")
    if len(endpoint) > MAX_ENDPOINT_LENGTH:
        raise UnsafeUrlError("Endpoint is too long")

    # Control characters enable request/header smuggling.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in endpoint):
        raise UnsafeUrlError("Endpoint contains control characters")

    try:
        parsed = urlparse(endpoint)
    except ValueError as exc:
        raise UnsafeUrlError("Endpoint is not a valid URL") from exc

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeUrlError("Endpoint must use https")

    # Credentials in the URL are never legitimate for a push endpoint and can
    # confuse downstream parsers about which host is really being addressed.
    if parsed.username or parsed.password:
        raise UnsafeUrlError("Endpoint must not contain credentials")

    hostname = parsed.hostname
    if not hostname:
        raise UnsafeUrlError("Endpoint must contain a hostname")

    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise UnsafeUrlError("Endpoint has an invalid port") from exc
    if port != 443:
        raise UnsafeUrlError("Endpoint must use port 443")

    # A literal IP bypasses nothing (we validate it the same way), but reject
    # early so the error is clearer.
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None and not _address_is_safe(literal):
        raise UnsafeUrlError("Endpoint points at a non-public address")

    return resolve_safe_addresses(hostname, port)


class _PinnedHostAdapter(HTTPAdapter):
    """Adapter that re-validates DNS at connect time (anti-rebinding).

    Validation and the request are separate moments; between them the name can
    be re-pointed at an internal address. Re-resolving here and requiring the
    result to still be safe (and to intersect what we validated) removes that
    window.
    """

    def __init__(self, hostname: str, allowed_addresses: Sequence[str], *args, **kwargs):
        self._hostname = hostname
        self._allowed = set(allowed_addresses)
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        parsed = urlparse(request.url)
        if parsed.scheme.lower() not in ALLOWED_SCHEMES:
            raise UnsafeUrlError("Refusing non-https request")
        if parsed.hostname != self._hostname:
            raise UnsafeUrlError("Refusing request to an unexpected host")

        current = set(resolve_safe_addresses(parsed.hostname, parsed.port or 443))
        if not current & self._allowed:
            raise UnsafeUrlError(
                "Host now resolves to different addresses; refusing (possible rebinding)"
            )
        return super().send(request, **kwargs)


def build_guarded_session(endpoint: str) -> requests.Session:
    """A requests Session locked to `endpoint`: no redirects, pinned host.

    Validates the endpoint as a side effect; raises UnsafeUrlError if unsafe.
    """
    addresses = validate_push_endpoint(endpoint)
    hostname = urlparse(endpoint).hostname

    session = requests.Session()
    # A permitted host must not be able to bounce us somewhere forbidden.
    session.max_redirects = 0
    adapter = _PinnedHostAdapter(hostname, addresses)
    session.mount("https://", adapter)

    original_request = session.request

    def _no_redirect_request(method, url, **kwargs):
        kwargs["allow_redirects"] = False
        return original_request(method, url, **kwargs)

    session.request = _no_redirect_request
    return session


def is_safe_push_endpoint(endpoint: str) -> bool:
    """Non-raising variant for filtering stored rows."""
    try:
        validate_push_endpoint(endpoint)
        return True
    except UnsafeUrlError:
        return False
    except Exception:
        logger.exception("Unexpected error validating push endpoint")
        return False
