"""HTTP security headers on API responses (audit KRY-009).

The SPA's own headers (full CSP, HSTS, Permissions-Policy) are set by nginx —
see nginx.conf.example. These assert what FastAPI itself emits, which is what
a deployment reaching the API directly would get.
"""


class TestSecurityHeaders:
    def test_baseline_headers_present(self, client):
        r = client.get("/")
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert r.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    def test_obsolete_xss_header_is_not_sent(self):
        """X-XSS-Protection is obsolete and its legacy auditor had bypasses;
        emitting it is noise at best."""
        from fastapi.testclient import TestClient
        from main import app
        r = TestClient(app).get("/")
        assert "X-XSS-Protection" not in r.headers

    def test_api_csp_denies_everything(self, client):
        """The API serves JSON, never markup — so it can afford default-src 'none'."""
        csp = client.get("/").headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "base-uri 'none'" in csp

    def test_cross_origin_isolation_headers(self, client):
        r = client.get("/")
        assert r.headers["Cross-Origin-Resource-Policy"] == "same-origin"
        assert r.headers["Cross-Origin-Opener-Policy"] == "same-origin"

    def test_permissions_policy_disables_sensitive_features(self, client):
        pp = client.get("/").headers["Permissions-Policy"]
        for feature in ("camera=()", "microphone=()", "geolocation=()"):
            assert feature in pp

    def test_hsts_not_sent_over_plaintext(self, client):
        """Sending HSTS on a plaintext dev request is meaningless and would
        pin localhost to https."""
        assert "Strict-Transport-Security" not in client.get("/").headers

    def test_hsts_sent_when_proxy_reports_tls(self, client):
        r = client.get("/", headers={"x-forwarded-proto": "https"})
        assert "max-age=" in r.headers["Strict-Transport-Security"]

    def test_headers_present_on_error_responses(self, client):
        """A 404 is still a response an attacker can reach."""
        r = client.get("/definitely-not-a-route")
        assert r.status_code == 404
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert "Content-Security-Policy" in r.headers
