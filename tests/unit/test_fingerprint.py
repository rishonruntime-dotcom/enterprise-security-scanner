"""Comprehensive tests for technology fingerprinting."""
import pytest
from unittest.mock import MagicMock

from scanner.intelligence.models import TechnologyCategory, Fingerprint, TechnologyProfile, DetectionRule
from scanner.intelligence.detectors import TechnologyDetector, RegexMatcher
from scanner.intelligence.signatures import JSONSignatureProvider


class TestRegexMatcher:
    """Test version extraction from Wappalyzer-style patterns."""

    def test_simple_match_no_version(self):
        pattern = "nginx"
        match, version = RegexMatcher.match_and_extract_version(pattern, "Server: nginx/1.18.0")
        assert match is True
        assert version is None

    def test_version_extraction(self):
        pattern = r"nginx(?:/([\d.]+))?\;version:\1"
        match, version = RegexMatcher.match_and_extract_version(pattern, "nginx/1.18.0")
        assert match is True
        assert version == "1.18.0"

    def test_no_match(self):
        pattern = r"nginx(?:/([\d.]+))?\;version:\1"
        match, version = RegexMatcher.match_and_extract_version(pattern, "Apache/2.4.41")
        assert match is False
        assert version is None

    def test_match_without_version_group(self):
        pattern = r"nginx(?:/([\d.]+))?\;version:\1"
        match, version = RegexMatcher.match_and_extract_version(pattern, "nginx")
        assert match is True
        assert version is None

    def test_multiple_version_groups(self):
        pattern = r"CloudFront(?:/([\d.]+))?\;version:\1"
        match, version = RegexMatcher.match_and_extract_version(pattern, "CloudFront/2.0.0")
        assert match is True
        assert version == "2.0.0"

    def test_case_insensitive_match(self):
        pattern = r"nginx(?:/([\d.]+))?\;version:\1"
        match, version = RegexMatcher.match_and_extract_version(pattern, "NGINX/1.18.0")
        assert match is True
        assert version == "1.18.0"

    def test_invalid_regex_returns_no_match(self):
        pattern = r"nginx(?:/([\d.]+))?\;version:\1"
        match, version = RegexMatcher.match_and_extract_version(pattern, None)
        assert match is False
        assert version is None


class TestSignatureLoading:
    """Test that signatures.json loads correctly."""

    def test_signatures_load(self):
        provider = JSONSignatureProvider("dummy.json")
        rules = provider.get_rules()
        assert len(rules) > 0

    def test_all_new_technologies_present(self):
        provider = JSONSignatureProvider("dummy.json")
        rules = provider.get_rules()
        rule_names = {r.name for r in rules}
        
        expected = {
            "Nginx", "Apache", "IIS", "LiteSpeed", "Caddy", "Tomcat",
            "Cloudflare", "Fastly", "Akamai", "AWS", "Azure", "GCP", "Vercel", "Netlify",
            "WordPress", "Drupal",
            "Django", "Flask", "Laravel", "Rails", "Spring Boot", "Express",
            "React", "Vue.js", "Angular", "Svelte",
            "Next.js", "Nuxt.js", "Astro",
            "GraphQL", "REST", "SOAP", "gRPC",
            "Service Workers", "HTTP/2", "HTTP/3", "Brotli",
            "PHP", "Node.js", "Python", "Java", "Ruby", "Jinja",
            "MySQL", "PostgreSQL", "MongoDB", "Redis",
            "WAF",
        }
        missing = expected - rule_names
        assert not missing, f"Missing signatures: {missing}"

    def test_categories_are_valid(self):
        provider = JSONSignatureProvider("dummy.json")
        rules = provider.get_rules()
        valid_categories = {c.value for c in TechnologyCategory}
        
        for rule in rules:
            assert rule.category in valid_categories, f"Invalid category '{rule.category}' for {rule.name}"


class TestWebServerDetection:
    """Test web server fingerprinting."""

    @pytest.fixture
    def detector(self):
        provider = JSONSignatureProvider("dummy.json")
        return TechnologyDetector(provider)

    def test_nginx_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "nginx/1.18.0"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Nginx" in names

    def test_nginx_version_extracted(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "nginx/1.18.0"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        nginx = next(fp for fp in fps if fp.name == "Nginx")
        assert nginx.version == "1.18.0"

    def test_apache_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "Apache/2.4.41"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Apache" in names

    def test_iis_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "Microsoft-IIS/10.0"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "IIS" in names

    def test_litespeed_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "LiteSpeed/5.4.11"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "LiteSpeed" in names

    def test_caddy_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "Caddy/2.6.4"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Caddy" in names

    def test_tomcat_detected_via_header(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "Apache-Coyote/1.1"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Tomcat" in names

    def test_tomcat_detected_via_html(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = []
        response.text = "<html><body>Apache Tomcat/9.0.50</body></html>"
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Tomcat" in names


class TestCDNCloudDetection:
    """Test CDN and cloud platform fingerprinting."""

    @pytest.fixture
    def detector(self):
        provider = JSONSignatureProvider("dummy.json")
        return TechnologyDetector(provider)

    def test_cloudflare_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "cloudflare", "CF-RAY": "12345"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Cloudflare" in names

    def test_fastly_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "fastly", "X-Fastly-Request-ID": "abc123"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Fastly" in names

    def test_akamai_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "AkamaiGHost", "X-Akamai-Transformed": "1"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Akamai" in names

    def test_aws_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "CloudFront", "X-Amz-Cf-Id": "xyz"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "AWS" in names

    def test_azure_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"X-Azure-Ref": "ref123"}
        response.cookies = {"ARRAffinity": "cookie123"}
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Azure" in names

    def test_gcp_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "Google Frontend", "X-Cloud-Trace-Context": "trace123"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "GCP" in names

    def test_vercel_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "Vercel", "X-Vercel-Id": "vercel123"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Vercel" in names

    def test_netlify_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "Netlify", "X-NF-Request-ID": "netlify123"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Netlify" in names


class TestFrameworkDetection:
    """Test web framework fingerprinting."""

    @pytest.fixture
    def detector(self):
        provider = JSONSignatureProvider("dummy.json")
        return TechnologyDetector(provider)

    def test_django_detected_via_html(self, detector):
        response = MagicMock()
        response.url = "http://example.com/admin/"
        response.headers = {}
        response.cookies = []
        response.text = '<input type="hidden" name="csrfmiddlewaretoken" value="abc">'
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Django" in names

    def test_flask_detected_via_header(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "Werkzeug/2.0.0"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Flask" in names

    def test_laravel_detected_via_cookies(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = {"laravel_session": "abc123", "XSRF-TOKEN": "xyz"}
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Laravel" in names

    def test_spring_boot_detected_via_html(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = {"JSESSIONID": "session123"}
        response.text = "<html><body>Whitelabel Error Page</body></html>"
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Spring Boot" in names

    def test_express_detected_via_header(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"X-Powered-By": "Express"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Express" in names

    def test_rails_detected_via_html(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = []
        response.text = '<script src="/assets/rails-ujs.js"></script>'
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Rails" in names

    def test_rails_detected_via_csrf_token(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = []
        response.text = '<meta name="csrf-token" content="abc123">'
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Rails" in names


class TestFrontendDetection:
    """Test frontend framework fingerprinting."""

    @pytest.fixture
    def detector(self):
        provider = JSONSignatureProvider("dummy.json")
        return TechnologyDetector(provider)

    def test_svelte_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = []
        response.text = '<div class="svelte-1a2b3c">Hello</div>'
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Svelte" in names

    def test_astro_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = []
        response.text = '<astro-island uid="abc"></astro-island>'
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Astro" in names

    def test_angular_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = []
        response.text = '<html ng-app="myApp">'
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Angular" in names

    def test_nextjs_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = []
        response.text = '<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>'
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Next.js" in names

    def test_nuxtjs_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = []
        response.text = '<script>window.__NUXT__={}</script>'
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Nuxt.js" in names


class TestAPIDetection:
    """Test API technology fingerprinting."""

    @pytest.fixture
    def detector(self):
        provider = JSONSignatureProvider("dummy.json")
        return TechnologyDetector(provider)

    def test_graphql_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com/graphql"
        response.headers = {}
        response.cookies = []
        response.text = '{"data": {"__typename": "Query"}}'
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "GraphQL" in names

    def test_rest_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com/api/v1/users"
        response.headers = {}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "REST" in names

    def test_soap_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com/service?wsdl"
        response.headers = {"Content-Type": "text/xml"}
        response.cookies = []
        response.text = '<soap:Envelope><soap:Body></soap:Body></soap:Envelope>'
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "SOAP" in names

    def test_grpc_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com/grpc"
        response.headers = {"Content-Type": "application/grpc"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "gRPC" in names


class TestSecurityDetection:
    """Test security technology fingerprinting."""

    @pytest.fixture
    def detector(self):
        provider = JSONSignatureProvider("dummy.json")
        return TechnologyDetector(provider)

    def test_waf_detected_via_cloudflare(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "cloudflare"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "WAF" in names

    def test_waf_detected_via_cookies(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = {"incap_ses": "abc123", "visid_incap": "xyz"}
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "WAF" in names


class TestProtocolDetection:
    """Test protocol and encoding fingerprinting."""

    @pytest.fixture
    def detector(self):
        provider = JSONSignatureProvider("dummy.json")
        return TechnologyDetector(provider)

    def test_http2_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"alt-svc": 'h2=":443"'}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "HTTP/2" in names

    def test_http3_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"alt-svc": 'h3=":443"'}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "HTTP/3" in names

    def test_brotli_detected(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Content-Encoding": "br"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Brotli" in names


class TestVersionDetection:
    """Test version extraction accuracy."""

    @pytest.fixture
    def detector(self):
        provider = JSONSignatureProvider("dummy.json")
        return TechnologyDetector(provider)

    def test_nginx_version(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "nginx/1.20.2"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        nginx = next((fp for fp in fps if fp.name == "Nginx"), None)
        assert nginx is not None
        assert nginx.version == "1.20.2"

    def test_apache_version(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "Apache/2.4.41"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        apache = next((fp for fp in fps if fp.name == "Apache"), None)
        assert apache is not None
        assert apache.version == "2.4.41"

    def test_cloudflare_version(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "cloudflare/22.0.0"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        cf = next((fp for fp in fps if fp.name == "Cloudflare"), None)
        assert cf is not None
        assert cf.version == "22.0.0"

    def test_wordpress_version_from_meta(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = []
        response.text = '<meta name="generator" content="WordPress 6.2.1">'
        
        fps = detector.analyze(response)
        wp = next((fp for fp in fps if fp.name == "WordPress"), None)
        assert wp is not None
        assert wp.version == "6.2.1"

    def test_aspnet_version_from_header(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"X-AspNet-Version": "4.0.30319"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        asp = next((fp for fp in fps if fp.name == "ASP.NET"), None)
        assert asp is not None
        assert asp.version == "4.0.30319"

    def test_rails_version_from_header(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"X-Rails-Version": "7.0.8"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        rails = next((fp for fp in fps if fp.name == "Rails"), None)
        assert rails is not None
        assert rails.version == "7.0.8"

    def test_ruby_detected_via_x_powered_by(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"X-Powered-By": "Ruby/3.2.2"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Ruby" in names


class TestConfidenceScoring:
    """Test confidence scoring for different detection methods."""

    @pytest.fixture
    def detector(self):
        provider = JSONSignatureProvider("dummy.json")
        return TechnologyDetector(provider)

    def test_header_match_high_confidence(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {"Server": "nginx/1.18.0"}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        nginx = next(fp for fp in fps if fp.name == "Nginx")
        assert nginx.confidence >= 90

    def test_html_match_medium_confidence(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = []
        response.text = '<div class="svelte-1a2b3c">Hello</div>'
        
        fps = detector.analyze(response)
        svelte = next((fp for fp in fps if fp.name == "Svelte"), None)
        if svelte:
            assert svelte.confidence >= 70

    def test_cookie_match_confidence(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = {"laravel_session": "abc"}
        response.text = ""
        
        fps = detector.analyze(response)
        laravel = next((fp for fp in fps if fp.name == "Laravel"), None)
        if laravel:
            assert laravel.confidence >= 70


class TestTechnologyProfile:
    """Test TechnologyProfile aggregation."""

    def test_add_fingerprint(self):
        profile = TechnologyProfile()
        fp = Fingerprint(name="Nginx", category=TechnologyCategory.WEB_SERVER, confidence=95, version="1.18.0")
        profile.add_fingerprint(fp)
        assert len(profile.technologies) == 1
        assert profile.technologies[0].name == "Nginx"

    def test_merge_fingerprint(self):
        profile = TechnologyProfile()
        fp1 = Fingerprint(name="Nginx", category=TechnologyCategory.WEB_SERVER, confidence=90, version="1.18.0")
        fp2 = Fingerprint(name="Nginx", category=TechnologyCategory.WEB_SERVER, confidence=95, version="1.20.0")
        profile.add_fingerprint(fp1)
        profile.add_fingerprint(fp2)
        assert len(profile.technologies) == 1
        assert profile.technologies[0].confidence == 95
        assert "1.18.0" in profile.technologies[0].versions
        assert "1.20.0" in profile.technologies[0].versions

    def test_multiple_technologies(self):
        profile = TechnologyProfile()
        fps = [
            Fingerprint(name="Nginx", category=TechnologyCategory.WEB_SERVER, confidence=95),
            Fingerprint(name="Cloudflare", category=TechnologyCategory.CDN, confidence=90),
            Fingerprint(name="React", category=TechnologyCategory.JS_FRAMEWORK, confidence=85),
        ]
        for fp in fps:
            profile.add_fingerprint(fp)
        assert len(profile.technologies) == 3


class TestImpliedTechnologies:
    """Test implied technology resolution."""

    @pytest.fixture
    def detector(self):
        provider = JSONSignatureProvider("dummy.json")
        return TechnologyDetector(provider)

    def test_wordpress_implies_php(self, detector):
        response = MagicMock()
        response.url = "http://example.com/wp-content/themes"
        response.headers = {}
        response.cookies = []
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "WordPress" in names
        assert "PHP" in names

    def test_nextjs_implies_react(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = []
        response.text = '<script id="__NEXT_DATA__" type="application/json">{}</script>'
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Next.js" in names
        assert "React" in names

    def test_laravel_implies_php(self, detector):
        response = MagicMock()
        response.url = "http://example.com"
        response.headers = {}
        response.cookies = {"laravel_session": "abc"}
        response.text = ""
        
        fps = detector.analyze(response)
        names = [fp.name for fp in fps]
        assert "Laravel" in names
        assert "PHP" in names
