"""SSRF guard tests (KRY-002).

Covers the address matrix from the audit plus the redirect / DNS-rebinding
variants that made the finding exploitable in the first place.
"""
import pytest
from unittest.mock import patch

from security.url_guard import (
    UnsafeUrlError,
    build_guarded_session,
    is_safe_push_endpoint,
    validate_push_endpoint,
)

PUBLIC_IP = "93.184.216.34"


def _resolves_to(*addresses):
    """Patch DNS resolution to return exactly these addresses."""
    return patch(
        "security.url_guard.socket.getaddrinfo",
        return_value=[(2, 1, 6, "", (addr, 443)) for addr in addresses],
    )


class TestBlockedAddresses:
    # The audit's explicit list, plus IPv6 and CGNAT.
    @pytest.mark.parametrize("addr", [
        "127.0.0.1",        # loopback
        "127.1.2.3",        # loopback, non-canonical
        "10.0.0.1",         # RFC1918
        "10.255.255.254",
        "172.16.0.1",       # RFC1918
        "172.31.255.254",
        "192.168.0.1",      # RFC1918
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "169.254.1.1",      # link-local
        "0.0.0.0",          # unspecified
        "100.64.0.1",       # CGNAT
        "224.0.0.1",        # multicast
        "::1",              # IPv6 loopback
        "fc00::1",          # IPv6 unique-local
        "fe80::1",          # IPv6 link-local
    ])
    def test_literal_ip_endpoint_is_rejected(self, addr):
        host = f"[{addr}]" if ":" in addr else addr
        with pytest.raises(UnsafeUrlError):
            validate_push_endpoint(f"https://{host}/push/abc")

    @pytest.mark.parametrize("addr", [
        "127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1",
    ])
    def test_hostname_resolving_to_internal_is_rejected(self, addr):
        """A public-looking name that resolves inward must still be refused."""
        with _resolves_to(addr):
            with pytest.raises(UnsafeUrlError):
                validate_push_endpoint("https://evil.example.com/push/abc")

    def test_ipv4_mapped_ipv6_is_rejected(self):
        """::ffff:127.0.0.1 must not smuggle a v4 loopback past v6 checks."""
        with pytest.raises(UnsafeUrlError):
            validate_push_endpoint("https://[::ffff:127.0.0.1]/push")

    def test_mixed_resolution_is_rejected(self):
        """Public + internal in one answer: we can't control which gets dialled."""
        with _resolves_to(PUBLIC_IP, "127.0.0.1"):
            with pytest.raises(UnsafeUrlError):
                validate_push_endpoint("https://mixed.example.com/push")

    def test_unresolvable_host_is_rejected(self):
        with pytest.raises(UnsafeUrlError):
            validate_push_endpoint("https://nx.invalid./push")


class TestSchemeAndShape:
    @pytest.mark.parametrize("url", [
        "http://push.example.com/abc",       # plaintext
        "file:///etc/passwd",
        "gopher://push.example.com/",
        "ftp://push.example.com/",
        "//push.example.com/abc",            # scheme-relative
        "https://user:pass@push.example.com/",  # credentials
        "https://push.example.com:8080/abc",    # non-443 port
        "",
    ])
    def test_bad_shape_is_rejected(self, url):
        with _resolves_to(PUBLIC_IP):
            with pytest.raises(UnsafeUrlError):
                validate_push_endpoint(url)

    def test_control_characters_are_rejected(self):
        with pytest.raises(UnsafeUrlError):
            validate_push_endpoint("https://push.example.com/a\r\nHost: evil")

    def test_overlong_endpoint_is_rejected(self):
        with pytest.raises(UnsafeUrlError):
            validate_push_endpoint("https://push.example.com/" + "a" * 5000)

    def test_public_https_endpoint_is_accepted(self):
        with _resolves_to(PUBLIC_IP):
            assert validate_push_endpoint(
                "https://fcm.googleapis.com/fcm/send/abc"
            ) == [PUBLIC_IP]


class TestRedirectAndRebinding:
    def test_session_refuses_redirects(self):
        """A permitted host must not be able to bounce us somewhere forbidden."""
        with _resolves_to(PUBLIC_IP):
            session = build_guarded_session("https://push.example.com/abc")
        assert session.max_redirects == 0

    def test_rebinding_between_validation_and_send_is_refused(self):
        """Validate against a public IP, then re-point the name internally."""
        with _resolves_to(PUBLIC_IP):
            session = build_guarded_session("https://push.example.com/abc")

        # DNS now answers with a loopback address — the pinned adapter must
        # re-resolve at send time and refuse.
        with _resolves_to("127.0.0.1"):
            with pytest.raises(UnsafeUrlError):
                session.get("https://push.example.com/abc")

    def test_send_to_unexpected_host_is_refused(self):
        with _resolves_to(PUBLIC_IP):
            session = build_guarded_session("https://push.example.com/abc")
        with _resolves_to(PUBLIC_IP):
            with pytest.raises(UnsafeUrlError):
                session.get("https://other.example.com/abc")


class TestIsSafeHelper:
    def test_non_raising_helper(self):
        with _resolves_to("127.0.0.1"):
            assert is_safe_push_endpoint("https://evil.example.com/p") is False
        with _resolves_to(PUBLIC_IP):
            assert is_safe_push_endpoint("https://push.example.com/p") is True
