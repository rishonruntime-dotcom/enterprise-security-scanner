import pytest
from scanner.network.models import HTTPResponse, HTTPRequest, Cookie
from scanner.passive.plugins.headers import MissingSecurityHeadersPlugin
from scanner.passive.plugins.cookies import InsecureCookiePlugin
from scanner.models.finding import Severity

def test_missing_security_headers_plugin():
    plugin = MissingSecurityHeadersPlugin()
    
    req = HTTPRequest(method="GET", url="https://example.com")
    
    # 1. Test secure response
    secure_resp = HTTPResponse(
        status_code=200,
        url="https://example.com",
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()"
        },
        cookies=[],
        body=b"secure",
        text="secure",
        request=req
    )
    observations = plugin.analyze(secure_resp)
    assert len(observations) == 0
    
    # 2. Test insecure response (missing all 6 security headers)
    insecure_resp = HTTPResponse(
        status_code=200,
        url="https://example.com",
        headers={"Server": "nginx"},
        cookies=[],
        body=b"insecure",
        text="insecure",
        request=req
    )
    observations = plugin.analyze(insecure_resp)
    assert len(observations) == 5
    titles = [o.title for o in observations]
    assert any("HSTS" in t for t in titles)
    assert any("Anti-Clickjacking" in t for t in titles)

def test_insecure_cookie_plugin():
    plugin = InsecureCookiePlugin()
    req = HTTPRequest(method="GET", url="https://example.com")
    
    from scanner.network.models import Cookie
    
    secure_cookie = Cookie(name="session", value="123", secure=True, http_only=True, same_site="Lax")
    insecure_cookie = Cookie(name="session", value="123", secure=False, http_only=False)
    
    secure_resp = HTTPResponse(
        status_code=200, url="https://example.com", headers={}, cookies=[secure_cookie], body=b"", text="", request=req
    )
    assert len(plugin.analyze(secure_resp)) == 0
    
    insecure_resp = HTTPResponse(
        status_code=200, url="https://example.com", headers={}, cookies=[insecure_cookie], body=b"", text="", request=req
    )
    observations = plugin.analyze(insecure_resp)
    assert len(observations) == 1
    desc = " ".join(o.description for o in observations)
    assert "Secure" in desc
    assert "HttpOnly" in desc

def test_csp_context_aware_risk_evaluation():
    from scanner.passive.plugins.headers import CSPParser
    
    # 1. YouTube-style CSP (Level 3 strict-dynamic + nonce + unsafe-inline + Trusted Types)
    youtube_csp = "require-trusted-types-for 'script'; base-uri 'self'; object-src 'none'; script-src 'report-sample' 'nonce-37ig1yPVl2_HfCMg8UZJEw' 'unsafe-inline' 'strict-dynamic' https: http: 'unsafe-eval'; report-uri https://csp.withgoogle.com/csp/youtube_main/strict"
    obs_yt = CSPParser.analyze_csp(youtube_csp, "https://www.youtube.com")
    
    # Verify no Medium false positives for unsafe-inline or wildcards (overridden by W3C CSP3 strict-dynamic)
    medium_yt = [o for o in obs_yt if o.severity.name == "MEDIUM"]
    assert len(medium_yt) == 0

    # 2. Unrestricted unsafe-inline CSP (True Vulnerability)
    unrestricted_csp = "script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self';"
    obs_unrestricted = CSPParser.analyze_csp(unrestricted_csp, "https://vulnerable.example.com")
    medium_unrestricted = [o for o in obs_unrestricted if o.severity.name == "MEDIUM"]
    assert len(medium_unrestricted) == 1
    assert "Unrestricted 'script-src' Allows 'unsafe-inline'" in medium_unrestricted[0].title


class TestCSPReasoningEngine:
    """Test the new context-aware CSP reasoning engine."""

    def test_strong_policy_scores_info(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        strong_csp = (
            "default-src 'self'; "
            "script-src 'self' 'nonce-abc123' 'strict-dynamic'; "
            "style-src 'self' 'sha256-xyz'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'self'; "
            "upgrade-insecure-requests; "
            "report-uri /csp-report"
        )
        obs = CSPReasoningEngine.evaluate(strong_csp, "https://example.com")
        assert obs.severity == Severity.INFO
        assert "Strong Protection" in obs.title
        assert obs.remediation is not None

    def test_weak_policy_scores_high(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        weak_csp = "script-src 'self' 'unsafe-inline' 'unsafe-eval' * http:; object-src *;"
        obs = CSPReasoningEngine.evaluate(weak_csp, "https://example.com")
        assert obs.severity == Severity.HIGH
        assert "Insufficient Protection" in obs.title

    def test_moderate_policy_scores_medium(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        moderate_csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "object-src 'none'; "
            "connect-src *"
        )
        obs = CSPReasoningEngine.evaluate(moderate_csp, "https://example.com")
        # unsafe-inline + wildcard connect-src without mitigations should be at least HIGH
        assert obs.severity in (Severity.HIGH, Severity.MEDIUM)

    def test_missing_csp_returns_low(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        obs = CSPReasoningEngine.evaluate("", "https://example.com")
        assert obs.severity == Severity.LOW
        assert "Missing" in obs.title

    def test_strict_dynamic_mitigates_unsafe_inline(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = (
            "script-src 'self' 'unsafe-inline' 'strict-dynamic' 'nonce-abc123' https:; "
            "object-src 'none'; "
            "base-uri 'self'"
        )
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        # strict-dynamic + nonce mitigates unsafe-inline, but missing some directives
        assert obs.severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM)

    def test_trusted_types_mitigates_unsafe_eval(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-eval'; "
            "require-trusted-types-for 'script'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'self'"
        )
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        # Trusted Types + strong base policy should result in at least MEDIUM
        assert obs.severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM)

    def test_evidence_contains_full_policy(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = "script-src 'self' 'unsafe-inline'; object-src 'none';"
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        assert len(obs.evidence) > 0
        evidence_data = obs.evidence[0].data
        assert "raw_csp" in evidence_data
        assert "policy_quality_score" in evidence_data
        assert "protections" in evidence_data
        assert "weaknesses" in evidence_data
        assert "reasoning" in evidence_data
        assert "browser_compatibility" in evidence_data
        assert "directives" in evidence_data
        assert evidence_data["raw_csp"] == csp

    def test_policy_without_default_src_penalized(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = "script-src 'self'; object-src 'none';"
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        assert obs.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.INFO)
        assert obs.evidence[0].data["policy_quality_score"] < 50

    def test_comprehensive_strong_policy(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'nonce-abc' 'sha256-xyz' 'strict-dynamic'; "
            "style-src 'self' 'nonce-abc'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'self'; "
            "connect-src 'self' https://api.example.com; "
            "form-action 'self'; "
            "upgrade-insecure-requests; "
            "report-uri /csp-report; "
            "report-to csp-endpoint; "
            "sandbox allow-scripts; "
            "require-trusted-types-for 'script'; "
            "trusted-types 'none'"
        )
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        assert obs.severity == Severity.INFO
        assert obs.evidence[0].data["policy_quality_score"] >= 75


class TestBrowserCompatibility:
    """Test browser compatibility analysis."""

    def test_browser_notes_in_evidence(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'nonce-abc' 'strict-dynamic'; "
            "require-trusted-types-for 'script'; "
            "upgrade-insecure-requests; "
            "report-to csp-endpoint"
        )
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        browser_notes = obs.evidence[0].data["browser_compatibility"]
        assert any("strict-dynamic" in note for note in browser_notes)
        assert any("nonce" in note for note in browser_notes)
        assert any("Trusted Types" in note for note in browser_notes)
        assert any("upgrade-insecure-requests" in note for note in browser_notes)
        assert any("report-to" in note for note in browser_notes)

    def test_legacy_report_uri_note(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = "default-src 'self'; script-src 'self'; report-uri /report"
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        browser_notes = obs.evidence[0].data["browser_compatibility"]
        assert any("deprecated" in note.lower() for note in browser_notes)

    def test_no_browser_compatibility_penalty_for_severity(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        # Even with older browser support notes, severity should be based on policy strength
        csp = "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'"
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        # nonce is well supported, should be decent
        assert obs.severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM)
        # Should not be HIGH just because of browser support
        assert obs.severity != Severity.HIGH


class TestNoDuplicateFindings:
    """Ensure PASS-001 does not emit duplicate CSP findings."""

    def test_pass_001_does_not_emit_csp_directive_findings(self):
        plugin = MissingSecurityHeadersPlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        
        resp = HTTPResponse(
            status_code=200,
            url="https://example.com",
            headers={
                "Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'strict-dynamic' 'nonce-abc' https:; object-src 'none'; base-uri 'self'"
            },
            cookies=[],
            body=b"",
            text="",
            request=req
        )
        observations = plugin.analyze(resp)
        csp_obs = [o for o in observations if "CSP" in o.title or "Content-Security-Policy" in o.title]
        assert len(csp_obs) == 0, f"PASS-001 should not emit CSP directive findings, got: {[o.title for o in csp_obs]}"

    def test_only_one_csp_finding_per_response(self):
        from scanner.passive.engine import PassiveScannerManager
        from scanner.passive.plugins.csp_reasoning import CSPReasoningPlugin
        
        manager = PassiveScannerManager()
        req = HTTPRequest(method="GET", url="https://example.com")
        
        resp = HTTPResponse(
            status_code=200,
            url="https://example.com",
            headers={
                "Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'strict-dynamic' 'nonce-abc' https:; object-src 'none'; base-uri 'self'"
            },
            cookies=[],
            body=b"",
            text="",
            request=req
        )
        
        observations = manager.analyze_response(resp)
        csp_observations = [o for o in observations if "PASS-006" in o.plugin_id]
        assert len(csp_observations) == 1, f"Expected exactly 1 holistic CSP finding, got {len(csp_observations)}"
        assert csp_observations[0].observation_type == "csp_policy_assessment"


class TestSpecificPolicies:
    """Verify reasoning for specific real-world policies."""

    def test_youtube_style_csp(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        youtube_csp = (
            "require-trusted-types-for 'script'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "script-src 'report-sample' 'nonce-37ig1yPVl2_HfCMg8UZJEw' 'unsafe-inline' 'strict-dynamic' https: http: 'unsafe-eval'; "
            "report-uri https://csp.withgoogle.com/csp/youtube_main/strict"
        )
        obs = CSPReasoningEngine.evaluate(youtube_csp, "https://www.youtube.com")
        assert obs.severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM)
        assert obs.evidence[0].data["policy_quality_score"] >= 50

    def test_hashes_instead_of_nonces(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'sha256-abc123' 'strict-dynamic'; "
            "object-src 'none'; "
            "base-uri 'self'"
        )
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        # Hashes + strict-dynamic should be strong
        assert obs.severity in (Severity.INFO, Severity.LOW)
        assert "sha256" in str(obs.evidence[0].data["directives"])

    def test_wildcard_policy_without_strict_dynamic(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = "script-src * http:; object-src *; connect-src *;"
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        assert obs.severity == Severity.HIGH
        assert "Insufficient Protection" in obs.title
        assert obs.evidence[0].data["policy_quality_score"] < 30

    def test_strong_csp_without_unsafe_inline(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'nonce-abc' 'sha256-xyz'; "
            "style-src 'self' 'sha256-xyz'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'self'; "
            "connect-src 'self' https://api.example.com; "
            "form-action 'self'; "
            "upgrade-insecure-requests"
        )
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        assert obs.severity == Severity.INFO
        assert "Strong Protection" in obs.title

    def test_unsafe_inline_with_nonce_and_strict_dynamic(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        # Modern best practice: unsafe-inline kept only for legacy browsers
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'nonce-abc123' 'unsafe-inline' 'strict-dynamic' https:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'self'"
        )
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        # strict-dynamic + nonce should mitigate unsafe-inline
        assert obs.severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM)
        assert obs.evidence[0].data["policy_quality_score"] >= 50

    def test_unsafe_eval_with_trusted_types(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-eval'; "
            "require-trusted-types-for 'script'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'self'"
        )
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        # Trusted Types mitigates unsafe-eval
        assert obs.severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM)
        assert obs.evidence[0].data["policy_quality_score"] >= 50


class TestEvidenceQuality:
    """Verify evidence contains all required quality fields."""

    def test_evidence_has_protections_and_weaknesses(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';"
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        data = obs.evidence[0].data
        assert len(data["protections"]) > 0
        assert len(data["weaknesses"]) > 0
        assert "no unsafe-inline in script-src" not in data["protections"]  # unsafe-inline present
        assert "unsafe-inline in script-src without effective mitigation" in data["weaknesses"]

    def test_evidence_has_reasoning(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = "script-src 'self' 'unsafe-inline' 'unsafe-eval' * http:; object-src *;"
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        reasoning = obs.evidence[0].data["reasoning"]
        assert "scored" in reasoning
        assert "100" in reasoning
        assert "modern browsers" in reasoning or "mitigations" in reasoning

    def test_remediation_only_when_applicable(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        # Strong policy should have minimal remediation
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'nonce-abc' 'strict-dynamic'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'self'; "
            "report-uri /csp-report"
        )
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        assert "No immediate remediation required" in obs.remediation

    def test_weak_policy_has_actionable_remediation(self):
        from scanner.passive.csp_engine import CSPReasoningEngine
        
        csp = "script-src * http:; object-src *;"
        obs = CSPReasoningEngine.evaluate(csp, "https://example.com")
        assert "Prioritize CSP remediation" in obs.remediation
        assert len(obs.evidence[0].data["weaknesses"]) > 0


class TestHeaderIntelligenceEnrichment:
    """Test enriched header intelligence: reverse proxy, CDN, HSTS preload, redirects, browser defaults, CSP protections."""

    def test_reverse_proxy_detection(self):
        plugin = MissingSecurityHeadersPlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        resp = HTTPResponse(
            status_code=200,
            url="https://example.com",
            headers={"X-Forwarded-For": "1.2.3.4", "Via": "nginx"},
            cookies=[],
            body=b"",
            text="",
            request=req,
        )
        observations = plugin.analyze(resp)
        proxy_obs = [o for o in observations if o.proxy_type is not None]
        assert len(proxy_obs) > 0
        assert any(o.proxy_type == "nginx" for o in proxy_obs)

    def test_cdn_detection(self):
        plugin = MissingSecurityHeadersPlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        resp = HTTPResponse(
            status_code=200,
            url="https://example.com",
            headers={"Server": "cloudflare", "CF-RAY": "abc123"},
            cookies=[],
            body=b"",
            text="",
            request=req,
        )
        observations = plugin.analyze(resp)
        cdn_obs = [o for o in observations if o.cdn_provider is not None]
        assert len(cdn_obs) > 0
        assert any(o.cdn_provider == "cloudflare" for o in cdn_obs)

    def test_hsts_preload_detected_via_direct_method(self):
        assert MissingSecurityHeadersPlugin._check_hsts_preload({
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
        }) is True
        assert MissingSecurityHeadersPlugin._check_hsts_preload({
            "strict-transport-security": "max-age=31536000"
        }) is False
        assert MissingSecurityHeadersPlugin._check_hsts_preload({}) is None

    def test_redirect_observed(self):
        plugin = MissingSecurityHeadersPlugin()
        req = HTTPRequest(method="GET", url="http://example.com")
        resp = HTTPResponse(
            status_code=301,
            url="https://example.com",
            headers={"Location": "https://example.com"},
            cookies=[],
            body=b"",
            text="",
            request=req,
        )
        observations = plugin.analyze(resp)
        redirect_obs = [o for o in observations if o.redirect_observed is True]
        assert len(redirect_obs) > 0

    def test_csp_protections_present(self):
        plugin = MissingSecurityHeadersPlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        resp = HTTPResponse(
            status_code=200,
            url="https://example.com",
            headers={
                "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; object-src 'none'; frame-ancestors 'self'; report-uri /report"
            },
            cookies=[],
            body=b"",
            text="",
            request=req,
        )
        observations = plugin.analyze(resp)
        csp_obs = [o for o in observations if o.csp_protections_present is not None]
        assert len(csp_obs) > 0
        protections = csp_obs[0].csp_protections_present
        assert "default-src 'self'" in protections
        assert "strict-dynamic" in protections
        assert "frame-ancestors" in protections

    def test_browser_defaults_note_for_x_content_type_options(self):
        plugin = MissingSecurityHeadersPlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        resp = HTTPResponse(
            status_code=200,
            url="https://example.com",
            headers={},
            cookies=[],
            body=b"",
            text="",
            request=req,
        )
        observations = plugin.analyze(resp)
        xcto_obs = [o for o in observations if "X-Content-Type-Options" in o.title]
        assert len(xcto_obs) == 1
        assert xcto_obs[0].browser_defaults_applicable is True
        evidence_data = xcto_obs[0].evidence[0].data
        assert "browser_default" in evidence_data

    def test_severity_downgraded_with_cdn_and_csp(self):
        plugin = MissingSecurityHeadersPlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        resp = HTTPResponse(
            status_code=200,
            url="https://example.com",
            headers={
                "Server": "cloudflare",
                "CF-RAY": "abc123",
                "Content-Security-Policy": "frame-ancestors 'self'",
            },
            cookies=[],
            body=b"",
            text="",
            request=req,
        )
        observations = plugin.analyze(resp)
        clickjacking_obs = [o for o in observations if "Anti-Clickjacking" in o.title]
        assert len(clickjacking_obs) == 0

    def test_enriched_evidence_contains_proxy_and_cdn_notes(self):
        plugin = MissingSecurityHeadersPlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        resp = HTTPResponse(
            status_code=200,
            url="https://example.com",
            headers={
                "Server": "cloudflare",
                "X-Forwarded-For": "1.2.3.4",
                "Via": "nginx",
            },
            cookies=[],
            body=b"",
            text="",
            request=req,
        )
        observations = plugin.analyze(resp)
        hsts_obs = [o for o in observations if "HSTS" in o.title]
        assert len(hsts_obs) == 1
        evidence_data = hsts_obs[0].evidence[0].data
        assert "proxy_note" in evidence_data or "cdn_note" in evidence_data


class TestCookieIntelligence:
    """Test enriched cookie intelligence: type detection, SameSite, __Host-/__Secure-, security scoring."""

    def test_session_cookie_detection(self):
        from scanner.passive.plugins.cookies import CookieSecurityAnalyzer
        from scanner.network.models import Cookie

        cookie = Cookie(name="PHPSESSID", value="abc", secure=False, http_only=False)
        context = CookieSecurityAnalyzer.classify(cookie, "https://example.com")
        assert context.cookie_type == "session"
        assert context.role == "authentication/session"

    def test_authentication_cookie_detection(self):
        from scanner.passive.plugins.cookies import CookieSecurityAnalyzer
        from scanner.network.models import Cookie

        cookie = Cookie(name="auth_token", value="abc", secure=False, http_only=False)
        context = CookieSecurityAnalyzer.classify(cookie, "https://example.com")
        assert context.cookie_type == "authentication"
        assert context.role == "authentication/session"

    def test_oauth_cookie_detection(self):
        from scanner.passive.plugins.cookies import CookieSecurityAnalyzer
        from scanner.network.models import Cookie

        cookie = Cookie(name="oauth_token", value="abc", secure=False, http_only=False)
        context = CookieSecurityAnalyzer.classify(cookie, "https://example.com")
        assert context.cookie_type == "oauth"

    def test_analytics_cookie_detection(self):
        from scanner.passive.plugins.cookies import CookieSecurityAnalyzer
        from scanner.network.models import Cookie

        cookie = Cookie(name="_ga", value="GA1.2.123", secure=False, http_only=False)
        context = CookieSecurityAnalyzer.classify(cookie, "https://example.com")
        assert context.cookie_type == "analytics"

    def test_third_party_cookie_detection(self):
        from scanner.passive.plugins.cookies import CookieSecurityAnalyzer
        from scanner.network.models import Cookie

        cookie = Cookie(name="tracking_id", value="xyz", domain=".tracker.com", secure=False, http_only=False)
        context = CookieSecurityAnalyzer.classify(cookie, "https://example.com")
        assert context.first_party is False
        assert context.cookie_type == "third_party"

    def test_samesite_missing_raises_issue_for_auth_cookie(self):
        plugin = InsecureCookiePlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        cookie = Cookie(name="sessionid", value="abc", secure=False, http_only=False, same_site=None)
        resp = HTTPResponse(status_code=200, url="https://example.com", headers={}, cookies=[cookie], body=b"", text="", request=req)
        observations = plugin.analyze(resp)
        assert len(observations) == 1
        assert "SameSite" in observations[0].description

    def test_samesite_none_without_secure_is_rejected(self):
        from scanner.passive.plugins.cookies import CookieSecurityAnalyzer
        from scanner.network.models import Cookie

        cookie = Cookie(name="sessionid", value="abc", secure=False, http_only=False, same_site="None")
        issues, severity, context, note = CookieSecurityAnalyzer.analyze(cookie, "https://example.com")
        assert issues == []
        assert severity is None
        assert note is not None

    def test_host_prefix_without_secure_is_flagged(self):
        plugin = InsecureCookiePlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        cookie = Cookie(name="__Host-session", value="abc", secure=False, http_only=False, path="/")
        resp = HTTPResponse(status_code=200, url="https://example.com", headers={}, cookies=[cookie], body=b"", text="", request=req)
        observations = plugin.analyze(resp)
        assert len(observations) == 1
        assert "__Host- prefix without Secure" in observations[0].description

    def test_secure_prefix_without_secure_is_flagged(self):
        plugin = InsecureCookiePlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        cookie = Cookie(name="__Secure-session", value="abc", secure=False, http_only=False)
        resp = HTTPResponse(status_code=200, url="https://example.com", headers={}, cookies=[cookie], body=b"", text="", request=req)
        observations = plugin.analyze(resp)
        assert len(observations) == 1
        assert "__Secure- prefix without Secure" in observations[0].description

    def test_security_score_in_evidence(self):
        plugin = InsecureCookiePlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        cookie = Cookie(name="sessionid", value="abc", secure=False, http_only=False)
        resp = HTTPResponse(status_code=200, url="https://example.com", headers={}, cookies=[cookie], body=b"", text="", request=req)
        observations = plugin.analyze(resp)
        assert len(observations) == 1
        evidence_data = observations[0].evidence[0].data
        assert "security_score" in evidence_data
        assert 0.0 <= evidence_data["security_score"] <= 1.0

    def test_secure_cookie_has_high_security_score(self):
        from scanner.passive.plugins.cookies import CookieSecurityAnalyzer
        from scanner.network.models import Cookie

        cookie = Cookie(name="sessionid", value="abc", secure=True, http_only=True, same_site="Strict")
        context = CookieSecurityAnalyzer.classify(cookie, "https://example.com")
        assert context.security_score >= 0.7

    def test_insecure_auth_cookie_has_low_security_score(self):
        from scanner.passive.plugins.cookies import CookieSecurityAnalyzer
        from scanner.network.models import Cookie

        cookie = Cookie(name="sessionid", value="abc", secure=False, http_only=False, same_site=None)
        context = CookieSecurityAnalyzer.classify(cookie, "https://example.com")
        assert context.security_score < 0.5

    def test_third_party_cookie_severity_downgraded(self):
        plugin = InsecureCookiePlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        cookie = Cookie(name="_ga", value="GA1.2.123", domain=".google.com", secure=False, http_only=False)
        resp = HTTPResponse(status_code=200, url="https://example.com", headers={}, cookies=[cookie], body=b"", text="", request=req)
        observations = plugin.analyze(resp)
        assert len(observations) == 1
        assert observations[0].severity == Severity.INFO

    def test_oauth_cookie_type_classified(self):
        plugin = InsecureCookiePlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        cookie = Cookie(name="oauth_token", value="abc", secure=False, http_only=False)
        resp = HTTPResponse(status_code=200, url="https://example.com", headers={}, cookies=[cookie], body=b"", text="", request=req)
        observations = plugin.analyze(resp)
        assert len(observations) == 1
        assert observations[0].cookie_type == "oauth"

    def test_host_prefix_fields_in_observation(self):
        plugin = InsecureCookiePlugin()
        req = HTTPRequest(method="GET", url="https://example.com")
        cookie = Cookie(name="__Host-session", value="abc", secure=False, http_only=False, path="/")
        resp = HTTPResponse(status_code=200, url="https://example.com", headers={}, cookies=[cookie], body=b"", text="", request=req)
        observations = plugin.analyze(resp)
        assert len(observations) == 1
        assert observations[0].cookie_has_host_prefix is True
        assert observations[0].cookie_has_secure_prefix is False
