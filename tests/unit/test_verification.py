import pytest
import re
import urllib.parse
from unittest.mock import AsyncMock, MagicMock

from scanner.models.finding import Finding, Evidence, Severity, Confidence, VerificationStatus, DetectionMethod
from scanner.correlation.verification import EvidenceVerificationStep, VerificationEngine
from scanner.active.models import DetectionCandidate, Payload, PayloadTechnique, BaselineResult
from scanner.passive.models import PassiveObservation, PluginMetadata
from scanner.network.models import HTTPRequest, HTTPResponse
from scanner.correlation.pipeline import FindingPipeline
from scanner.crawler.models import Endpoint


class MockHTTPClient:
    def __init__(self, response_text="", headers=None, latency=0.0, status_code=200, redirect_location=None):
        self.response_text = response_text
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.latency = latency
        self.status_code = status_code
        self.redirect_location = redirect_location
        self.call_count = 0

    async def send(self, request):
        self.call_count += 1
        import asyncio
        if self.latency > 0:
            await asyncio.sleep(min(self.latency, 0.1))
        headers = dict(self.headers)
        if self.redirect_location:
            headers["location"] = self.redirect_location
        return type('HTTPResponse', (), {
            'status_code': self.status_code,
            'text': self.response_text,
            'headers': headers,
            'latency': self.latency,
            'url': request.url if hasattr(request, 'url') else '',
        })()

    async def close(self):
        pass


class MockHTTPManager:
    def __init__(self, client):
        self.client = client

    def get_shared_client(self):
        return self.client


class MockBrowserManager:
    async def create_context(self):
        return self

    async def get_page_content(self, url):
        return "<html><body><script>alert(1)</script></body></html>"

    async def close(self):
        pass


# ── Active Candidate Verification Tests ─────────────────────────────────────

class TestActiveCandidateVerification:
    """Test verification of active DetectionCandidates."""

    @pytest.mark.asyncio
    async def test_xss_verified_with_browser(self):
        req = HTTPRequest(method="GET", url="https://example.com/page?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="<html><body><script>alert(1)</script></body></html>", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-XSS-001",
            vulnerability_type="xss",
            technique=PayloadTechnique.CONTEXT_BREAKOUT,
            endpoint="https://example.com/page",
            parameter="q",
            payload=Payload(value="<script>alert(1)</script>"),
            fuzzed_request=req,
            fuzzed_response=resp,
            reflection_context="html_body",
        )
        
        client = MockHTTPClient(response_text='<html><body><script>alert(1)</script></body></html>')
        browser = MockBrowserManager()
        engine = VerificationEngine(http_manager=MockHTTPManager(client), browser_manager=browser)
        
        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.confidence == Confidence.CERTAIN  # browser gives CERTAIN (0.95)
        assert finding.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_xss_verified_without_browser(self):
        req = HTTPRequest(method="GET", url="https://example.com/page?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="<html><body><script>alert(1)</script></body></html>", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-XSS-001",
            vulnerability_type="xss",
            technique=PayloadTechnique.CONTEXT_BREAKOUT,
            endpoint="https://example.com/page",
            parameter="q",
            payload=Payload(value="<script>alert(1)</script>"),
            fuzzed_request=req,
            fuzzed_response=resp,
            reflection_context="html_body",
        )
        
        client = MockHTTPClient(response_text='<html><body><script>alert(1)</script></body></html>')
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.confidence_score >= 0.88

    @pytest.mark.asyncio
    async def test_xss_encoded_payload_drops_verification(self):
        req = HTTPRequest(method="GET", url="https://example.com/page?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-XSS-001",
            vulnerability_type="xss",
            technique=PayloadTechnique.CONTEXT_BREAKOUT,
            endpoint="https://example.com/page",
            parameter="q",
            payload=Payload(value="<script>alert(1)</script>"),
            fuzzed_request=req,
            fuzzed_response=resp,
            reflection_context="html_body",
        )
        
        client = MockHTTPClient(response_text="<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>")
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is None

    @pytest.mark.asyncio
    async def test_xss_fallback_to_original_response(self):
        req = HTTPRequest(method="GET", url="https://example.com/page?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="<html><body><script>alert(1)</script></body></html>", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-XSS-001",
            vulnerability_type="xss",
            technique=PayloadTechnique.CONTEXT_BREAKOUT,
            endpoint="https://example.com/page",
            parameter="q",
            payload=Payload(value="<script>alert(1)</script>"),
            fuzzed_request=req,
            fuzzed_response=resp,
            reflection_context="html_body",
        )
        
        client = MockHTTPClient(response_text="<html><body>Safe</body></html>")
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.confidence_score >= 0.88

    @pytest.mark.asyncio
    async def test_sqli_error_based_verified(self):
        req = HTTPRequest(method="GET", url="https://example.com/page?id=1%27")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-SQLI-001",
            vulnerability_type="sqli",
            technique=PayloadTechnique.ERROR_BASED,
            endpoint="https://example.com/page",
            parameter="id",
            payload=Payload(value="1'", technique=PayloadTechnique.ERROR_BASED, category="sqli"),
            fuzzed_request=req,
            fuzzed_response=resp,
            matched_signature=r"SQL syntax.*?MySQL",
            detection_evidence={"db_type": "MySQL"},
        )
        
        client = MockHTTPClient(response_text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_sqli_boolean_based_verified(self):
        req_t = HTTPRequest(method="GET", url="https://example.com/page?id=1%20AND%201%3D1")
        resp_t = HTTPResponse(status_code=200, url=req_t.url, headers={}, cookies=[], body=b"a" * 100, text="a" * 100, request=req_t)
        req_f = HTTPRequest(method="GET", url="https://example.com/page?id=1%20AND%201%3D2")
        resp_f = HTTPResponse(status_code=200, url=req_f.url, headers={}, cookies=[], body=b"b" * 50, text="b" * 50, request=req_f)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-SQLI-001",
            vulnerability_type="sqli",
            technique=PayloadTechnique.BOOLEAN_BASED,
            endpoint="https://example.com/page",
            parameter="id",
            payload=Payload(value="1 AND 1=1", technique=PayloadTechnique.BOOLEAN_BASED, category="sqli"),
            fuzzed_request=req_t,
            fuzzed_response=resp_t,
            false_response=resp_f,
            detection_evidence={"true_length": 100, "false_length": 50},
        )
        
        engine = VerificationEngine(http_manager=MockHTTPManager(MockHTTPClient()))
        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED

    @pytest.mark.asyncio
    async def test_path_traversal_verified(self):
        req = HTTPRequest(method="GET", url="https://example.com/page?file=../../../../etc/passwd")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="root:x:0:0:root:/root:/bin/bash", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-TRAV-001",
            vulnerability_type="path_traversal",
            technique=PayloadTechnique.FILE_READ,
            endpoint="https://example.com/page",
            parameter="file",
            payload=Payload(value="../../../../etc/passwd", technique=PayloadTechnique.FILE_READ, category="path_traversal"),
            fuzzed_request=req,
            fuzzed_response=resp,
            file_marker=r"root:x:0:0:",
            detection_evidence={"target_file": "/etc/passwd"},
        )
        
        class ConditionalMockClient:
            async def send(self, request):
                if "nonexistent_file_xyzzy" in request.url:
                    return HTTPResponse(status_code=200, url=request.url, headers={}, cookies=[], body=b"", text="File not found", request=request)
                return HTTPResponse(status_code=200, url=request.url, headers={}, cookies=[], body=b"", text="root:x:0:0:root:/root:/bin/bash", request=request)
            async def close(self):
                pass
        
        client = ConditionalMockClient()
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_path_traversal_false_positive_dropped(self):
        req = HTTPRequest(method="GET", url="https://example.com/page?file=../../../../etc/passwd")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="root:x:0:0:", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-TRAV-001",
            vulnerability_type="path_traversal",
            technique=PayloadTechnique.FILE_READ,
            endpoint="https://example.com/page",
            parameter="file",
            payload=Payload(value="../../../../etc/passwd", technique=PayloadTechnique.FILE_READ, category="path_traversal"),
            fuzzed_request=req,
            fuzzed_response=resp,
            file_marker=r"root:x:0:0:",
        )
        
        client = MockHTTPClient(response_text="Static index: root:x:0:0:")
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is None

    @pytest.mark.asyncio
    async def test_ssrf_verified(self):
        req = HTTPRequest(method="GET", url="https://example.com/proxy?url=http://169.254.169.254/latest/meta-data/")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="ami-12345678\ninstance-id=i-1234567890abcdef0", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-SSRF-001",
            vulnerability_type="ssrf",
            technique=PayloadTechnique.PROTOCOL_ABUSE,
            endpoint="https://example.com/proxy",
            parameter="url",
            payload=Payload(value="http://169.254.169.254/latest/meta-data/", technique=PayloadTechnique.PROTOCOL_ABUSE, category="ssrf"),
            fuzzed_request=req,
            fuzzed_response=resp,
            matched_signature=r"ami-[a-f0-9]+|instance-id",
            detection_evidence={"ssrf_category": "aws_metadata"},
        )
        
        client = MockHTTPClient(response_text="ami-12345678\ninstance-id=i-1234567890abcdef0")
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_open_redirect_verified(self):
        req = HTTPRequest(method="GET", url="https://example.com/redirect?next=https://evil.com")
        resp = HTTPResponse(status_code=302, url=req.url, headers={"Location": "https://evil.com"}, cookies=[], body=b"", text="", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-REDIR-001",
            vulnerability_type="open_redirect",
            technique=PayloadTechnique.PROTOCOL_ABUSE,
            endpoint="https://example.com/redirect",
            parameter="next",
            payload=Payload(value="https://evil.com", technique=PayloadTechnique.PROTOCOL_ABUSE, category="open_redirect"),
            fuzzed_request=req,
            fuzzed_response=resp,
            matched_signature="https://evil.com",
            detection_evidence={"redirect_location": "https://evil.com"},
        )
        
        client = MockHTTPClient(response_text="", headers={}, status_code=302, redirect_location="https://evil.com")
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.severity == Severity.MEDIUM
        assert finding.confidence_score >= 0.85

    @pytest.mark.asyncio
    async def test_open_redirect_baseline_redirect_dropped(self):
        req = HTTPRequest(method="GET", url="https://example.com/redirect?next=https://evil.com")
        resp = HTTPResponse(status_code=302, url=req.url, headers={"Location": "https://evil.com"}, cookies=[], body=b"", text="", request=req)
        
        baseline = BaselineResult(
            request=HTTPRequest(method="GET", url="https://example.com/redirect?next=/home"),
            response=HTTPResponse(status_code=302, url="https://example.com/redirect?next=/home", headers={"Location": "https://evil.com"}, cookies=[], body=b"", text="", request=HTTPRequest(method="GET", url="https://example.com/redirect?next=/home")),
        )
        
        candidate = DetectionCandidate(
            plugin_id="ACT-REDIR-001",
            vulnerability_type="open_redirect",
            technique=PayloadTechnique.PROTOCOL_ABUSE,
            endpoint="https://example.com/redirect",
            parameter="next",
            payload=Payload(value="https://evil.com", technique=PayloadTechnique.PROTOCOL_ABUSE, category="open_redirect"),
            fuzzed_request=req,
            fuzzed_response=resp,
            baseline=baseline,
            matched_signature="https://evil.com",
            detection_evidence={"redirect_location": "https://evil.com"},
        )
        
        client = MockHTTPClient(response_text="", headers={}, status_code=302, redirect_location="https://evil.com")
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is None

    @pytest.mark.asyncio
    async def test_cmdi_verified(self):
        req = HTTPRequest(method="GET", url="https://example.com/exec?cmd=%3B+id")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="uid=1000(test) gid=1000(test) groups=1000(test)", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-CMDI-001",
            vulnerability_type="cmdi",
            technique=PayloadTechnique.COMMAND_OUTPUT,
            endpoint="https://example.com/exec",
            parameter="cmd",
            payload=Payload(value="; id", technique=PayloadTechnique.COMMAND_OUTPUT, category="cmdi"),
            fuzzed_request=req,
            fuzzed_response=resp,
            matched_signature=r"uid=\d+\(\w+\)\s+gid=\d+",
            detection_evidence={"os": "linux"},
        )
        
        client = MockHTTPClient(response_text="uid=1000(test) gid=1000(test) groups=1000(test)")
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_xxe_verified(self):
        req = HTTPRequest(method="POST", url="https://example.com/xml", headers={"Content-Type": "application/xml"}, body='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>')
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="root:x:0:0:root:/root:/bin/bash", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-XXE-001",
            vulnerability_type="xxe",
            technique=PayloadTechnique.FILE_READ,
            endpoint="https://example.com/xml",
            parameter="XML body",
            payload=Payload(value='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>', technique=PayloadTechnique.FILE_READ, category="xxe"),
            fuzzed_request=req,
            fuzzed_response=resp,
            matched_signature=r"root:.:0:0:",
            detection_evidence={"xxe_type": "basic_entity"},
        )
        
        client = MockHTTPClient(response_text="root:x:0:0:root:/root:/bin/bash")
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_ssti_verified(self):
        req = HTTPRequest(method="GET", url="https://example.com/template?name={{7*7}}")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="The result calculation evaluated to 49!", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-SSTI-001",
            vulnerability_type="ssti",
            technique=PayloadTechnique.TEMPLATE_EVAL,
            endpoint="https://example.com/template",
            parameter="name",
            payload=Payload(value="{{7*7}}", technique=PayloadTechnique.TEMPLATE_EVAL, category="ssti"),
            fuzzed_request=req,
            fuzzed_response=resp,
            detection_evidence={"detected_engine": "jinja2", "expected_result": "49"},
        )
        
        client = MockHTTPClient(response_text="The result calculation evaluated to 49!")
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_unknown_vulnerability_type_dropped(self):
        req = HTTPRequest(method="GET", url="https://example.com/test")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="test", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-UNKNOWN-001",
            vulnerability_type="unknown_type",
            technique=PayloadTechnique.ERROR_BASED,
            endpoint="https://example.com/test",
            parameter="q",
            payload=Payload(value="test"),
            fuzzed_request=req,
            fuzzed_response=resp,
        )
        
        client = MockHTTPClient(response_text="test")
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_candidate(candidate)
        assert finding is None


# ── Passive Observation Verification Tests ──────────────────────────────────

class TestPassiveObservationVerification:
    """Test active verification of passive observations."""

    @pytest.mark.asyncio
    async def test_missing_hsts_verified(self):
        obs = PassiveObservation(
            plugin_id="PASS-001",
            observation_type="missing_header",
            title="Missing Strict-Transport-Security (HSTS) Header",
            description="The server does not enforce encrypted connections via HSTS.",
            endpoint="https://example.com",
            severity=Severity.LOW,
            evidence=[Evidence(type="missing_header", description="No HSTS", data={"missing_header": "Strict-Transport-Security"})],
        )
        
        client = MockHTTPClient(headers={})
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_observation(obs)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.confidence_score == 0.95

    @pytest.mark.asyncio
    async def test_missing_csp_verified_active(self):
        obs = PassiveObservation(
            plugin_id="PASS-006",
            observation_type="csp_policy_assessment",
            title="Missing Content-Security-Policy Header",
            description="No CSP header detected.",
            endpoint="https://example.com",
            severity=Severity.LOW,
            evidence=[Evidence(type="missing_csp", description="CSP absent", data={"header": "Content-Security-Policy"})],
        )
        
        client = MockHTTPClient(headers={})
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_observation(obs)
        assert finding is not None
        assert "CSP header is absent" in finding.how_verified
        assert finding.confidence_score >= 0.85

    @pytest.mark.asyncio
    async def test_present_csp_verified_active(self):
        obs = PassiveObservation(
            plugin_id="PASS-006",
            observation_type="csp_policy_assessment",
            title="CSP Policy: Strong Protection",
            description="CSP is present and strong.",
            endpoint="https://example.com",
            severity=Severity.INFO,
            evidence=[Evidence(type="csp_policy_assessment", description="CSP present", data={"header": "Content-Security-Policy"})],
        )
        
        client = MockHTTPClient(headers={"Content-Security-Policy": "default-src 'self'"})
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_observation(obs)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.confidence_score >= 0.90

    @pytest.mark.asyncio
    async def test_missing_xfo_verified_active(self):
        obs = PassiveObservation(
            plugin_id="PASS-001",
            observation_type="missing_header",
            title="Missing Anti-Clickjacking Headers",
            description="No X-Frame-Options or frame-ancestors.",
            endpoint="https://example.com",
            severity=Severity.LOW,
            evidence=[Evidence(type="missing_header", description="No clickjacking protection", data={})],
        )
        
        client = MockHTTPClient(headers={})
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_observation(obs)
        assert finding is not None
        assert "X-Frame-Options or CSP frame-ancestors" in finding.how_verified
        assert finding.verification_status == VerificationStatus.VERIFIED

    @pytest.mark.asyncio
    async def test_present_xfo_verified_active(self):
        obs = PassiveObservation(
            plugin_id="PASS-001",
            observation_type="missing_header",
            title="Missing Anti-Clickjacking Headers",
            description="No X-Frame-Options or frame-ancestors.",
            endpoint="https://example.com",
            severity=Severity.LOW,
            evidence=[Evidence(type="missing_header", description="No clickjacking protection", data={})],
        )
        
        client = MockHTTPClient(headers={"X-Frame-Options": "DENY"})
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_observation(obs)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.NOT_ACTIVELY_VERIFIED
        assert finding.confidence_score <= 0.40

    @pytest.mark.asyncio
    async def test_cookie_observation_verified_active(self):
        obs = PassiveObservation(
            plugin_id="PASS-002",
            observation_type="cookie_flag",
            title="Cookie Missing Secure Flag",
            description="Cookie does not have Secure flag.",
            endpoint="https://example.com",
            severity=Severity.LOW,
            evidence=[Evidence(type="cookie_flag", description="Missing Secure", data={"cookie": "session"})],
        )
        
        client = MockHTTPClient(headers={})
        engine = VerificationEngine(http_manager=MockHTTPManager(client))
        
        finding = await engine.verify_observation(obs)
        assert finding is not None
        assert "response cookies analyzed for Secure" in finding.how_verified

    @pytest.mark.asyncio
    async def test_passive_verification_no_http_manager(self):
        obs = PassiveObservation(
            plugin_id="PASS-001",
            observation_type="missing_header",
            title="Missing HSTS",
            description="No HSTS.",
            endpoint="https://example.com",
            severity=Severity.LOW,
            evidence=[],
        )
        
        engine = VerificationEngine(http_manager=None)
        finding = await engine.verify_observation(obs)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.NOT_ACTIVELY_VERIFIED
        assert finding.confidence_score == 0.90


# ── Pipeline Integration Tests ──────────────────────────────────────────────

class TestPipelineVerificationIntegration:
    """Test that verification runs in the pipeline."""

    @pytest.mark.asyncio
    async def test_active_candidate_verified_in_pipeline(self):
        from scanner.active.models import DetectionCandidate, Payload, PayloadTechnique
        from scanner.network.models import HTTPRequest, HTTPResponse
        
        req = HTTPRequest(method="GET", url="https://example.com/page?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="<html><body><script>alert(1)</script></body></html>", request=req)
        
        candidate = DetectionCandidate(
            plugin_id="ACT-XSS-001",
            vulnerability_type="xss",
            technique=PayloadTechnique.CONTEXT_BREAKOUT,
            endpoint="https://example.com/page",
            parameter="q",
            payload=Payload(value="<script>alert(1)</script>"),
            fuzzed_request=req,
            fuzzed_response=resp,
            reflection_context="html_body",
        )
        
        client = MockHTTPClient(response_text='<html><body><script>alert(1)</script></body></html>')
        step = EvidenceVerificationStep(http_manager=MockHTTPManager(client))
        pipeline = FindingPipeline(steps=[step])
        
        result = await pipeline.process(candidate)
        assert result is not None
        assert result.is_verified is True
        assert result.verification_status == VerificationStatus.VERIFIED

    @pytest.mark.asyncio
    async def test_passive_observation_verified_in_pipeline(self):
        obs = PassiveObservation(
            plugin_id="PASS-001",
            observation_type="missing_header",
            title="Missing Content-Security-Policy Header",
            description="No CSP header.",
            endpoint="https://example.com",
            severity=Severity.LOW,
            evidence=[Evidence(type="missing_csp", description="CSP absent", data={"header": "Content-Security-Policy"})],
        )
        
        client = MockHTTPClient(headers={})
        step = EvidenceVerificationStep(http_manager=MockHTTPManager(client))
        pipeline = FindingPipeline(steps=[step])
        
        result = await pipeline.process(obs)
        assert result is not None
        assert "CSP header is absent" in result.how_verified


# ── Open Redirect Plugin Tests ──────────────────────────────────────────────

class TestOpenRedirectPlugin:
    """Test the Open Redirect active plugin."""

    @pytest.mark.asyncio
    async def test_open_redirect_detection(self):
        from scanner.active.plugins.open_redirect import OpenRedirectPlugin
        
        plugin = OpenRedirectPlugin()
        
        class MockVulnerableClient:
            async def send(self, request):
                parsed = urllib.parse.urlparse(request.url)
                params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                for k, v in params:
                    if "evil.com" in v:
                        return HTTPResponse(
                            status_code=302,
                            url=request.url,
                            headers={"Location": "https://evil.com"},
                            cookies=[],
                            body=b"",
                            text="",
                            request=request,
                        )
                return HTTPResponse(
                    status_code=302,
                    url=request.url,
                    headers={"Location": "/home"},
                    cookies=[],
                    body=b"",
                    text="",
                    request=request,
                )
            
            async def close(self):
                pass
        
        class MockHTTPManager:
            def __init__(self, client):
                self.client = client
            def get_shared_client(self):
                return self.client
        
        from scanner.network.http.manager import HTTPClientManager
        manager = MockHTTPManager(MockVulnerableClient())
        
        ep = Endpoint(url="https://example.com/redirect?next=/home", method="GET", parameters={"next": "/home"})
        candidates = await plugin.execute(ep, manager)
        
        assert len(candidates) == 1
        assert candidates[0].plugin_id == "ACT-REDIR-001"
        assert candidates[0].parameter == "next"
        assert candidates[0].vulnerability_type == "open_redirect"
        assert candidates[0].matched_signature == "https://evil.com"

    @pytest.mark.asyncio
    async def test_open_redirect_no_redirect_response(self):
        from scanner.active.plugins.open_redirect import OpenRedirectPlugin
        
        plugin = OpenRedirectPlugin()
        
        class MockClient:
            async def send(self, request):
                return HTTPResponse(status_code=200, url=request.url, headers={}, cookies=[], body=b"OK", text="OK", request=request)
            async def close(self):
                pass
        
        class MockHTTPManager:
            def __init__(self, client):
                self.client = client
            def get_shared_client(self):
                return self.client
        
        manager = MockHTTPManager(MockClient())
        ep = Endpoint(url="https://example.com/redirect?next=/home", method="GET", parameters={"next": "/home"})
        candidates = await plugin.execute(ep, manager)
        
        assert len(candidates) == 0

    @pytest.mark.asyncio
    async def test_open_redirect_baseline_has_same_redirect(self):
        from scanner.active.plugins.open_redirect import OpenRedirectPlugin
        
        plugin = OpenRedirectPlugin()
        
        class MockClient:
            async def send(self, request):
                parsed = urllib.parse.urlparse(request.url)
                params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                for k, v in params:
                    if "evil.com" in v or "/home" in v:
                        return HTTPResponse(
                            status_code=302,
                            url=request.url,
                            headers={"Location": "https://evil.com"},
                            cookies=[],
                            body=b"",
                            text="",
                            request=request,
                        )
                return HTTPResponse(status_code=200, url=request.url, headers={}, cookies=[], body=b"OK", text="OK", request=request)
            async def close(self):
                pass

        class MockHTTPManager:
            def __init__(self, client):
                self.client = client
            def get_shared_client(self):
                return self.client

        manager = MockHTTPManager(MockClient())
        ep = Endpoint(url="https://example.com/redirect?next=/home", method="GET", parameters={"next": "/home"})
        candidates = await plugin.execute(ep, manager)

        assert len(candidates) == 0

    @pytest.mark.asyncio
    async def test_file_upload_verified(self):
        req = HTTPRequest(method="POST", url="https://example.com/upload", headers={"Content-Type": "multipart/form-data"}, body="file=test.php")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="File uploaded successfully: test.php", request=req)

        candidate = DetectionCandidate(
            plugin_id="ACT-UPLOAD-001",
            vulnerability_type="file_upload",
            technique=PayloadTechnique.FILE_READ,
            endpoint="https://example.com/upload",
            parameter="file",
            payload=Payload(value="test.php", technique=PayloadTechnique.FILE_READ, category="file_upload", metadata={"extension": ".php"}),
            fuzzed_request=req,
            fuzzed_response=resp,
            matched_signature="test.php",
            detection_evidence={"uploaded_filename": "test.php", "extension": ".php"},
        )

        client = MockHTTPClient(response_text="File uploaded successfully: test.php")
        engine = VerificationEngine(http_manager=MockHTTPManager(client))

        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_idor_verified(self):
        req = HTTPRequest(method="GET", url="https://example.com/account/2")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="User: attacker@example.com\nEmail: attacker@example.com\nBalance: $1000", request=req)

        candidate = DetectionCandidate(
            plugin_id="ACT-IDOR-001",
            vulnerability_type="idor",
            technique=PayloadTechnique.BOOLEAN_BASED,
            endpoint="https://example.com/account",
            parameter="id",
            payload=Payload(value="2", technique=PayloadTechnique.BOOLEAN_BASED, category="idor"),
            fuzzed_request=req,
            fuzzed_response=resp,
            matched_signature="idor_param_id",
            detection_evidence={"original_value": "1", "test_value": "2", "response_differs": True},
        )

        baseline = BaselineResult(
            request=HTTPRequest(method="GET", url="https://example.com/account/1"),
            response=HTTPResponse(status_code=200, url="https://example.com/account/1", headers={}, cookies=[], body=b"", text="User: victim@example.com\nEmail: victim@example.com\nBalance: $500", request=HTTPRequest(method="GET", url="https://example.com/account/1")),
        )
        candidate.baseline = baseline

        class ConditionalMockClient:
            async def send(self, request):
                if "account/2" in request.url:
                    return HTTPResponse(status_code=200, url=request.url, headers={}, cookies=[], body=b"", text="User: attacker@example.com\nEmail: attacker@example.com\nBalance: $1000", request=request)
                return HTTPResponse(status_code=200, url=request.url, headers={}, cookies=[], body=b"", text="User: victim@example.com\nEmail: victim@example.com\nBalance: $500", request=request)
            async def close(self):
                pass

        client = ConditionalMockClient()
        engine = VerificationEngine(http_manager=MockHTTPManager(client))

        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_csrf_verified(self):
        req = HTTPRequest(method="POST", url="https://example.com/transfer", headers={"Content-Type": "application/x-www-form-urlencoded"}, body="amount=1000&to=attacker")
        resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="Transfer successful", request=req)

        candidate = DetectionCandidate(
            plugin_id="ACT-CSRF-001",
            vulnerability_type="csrf",
            technique=PayloadTechnique.BOOLEAN_BASED,
            endpoint="https://example.com/transfer",
            parameter="amount",
            payload=Payload(value="csrf_test_payload", technique=PayloadTechnique.BOOLEAN_BASED, category="csrf", metadata={"missing_token": True}),
            fuzzed_request=req,
            fuzzed_response=resp,
            matched_signature="state_changing_POST",
            detection_evidence={"http_method": "POST", "response_status": 200, "has_csrf_token": False, "response_indicators": ["success_response"]},
        )

        client = MockHTTPClient(response_text="Transfer successful", status_code=200)
        engine = VerificationEngine(http_manager=MockHTTPManager(client))

        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_waf_detection_reduces_confidence(self):
        req = HTTPRequest(method="GET", url="https://example.com/page?id=1%27")
        resp = HTTPResponse(status_code=200, url=req.url, headers={"Server": "cloudflare", "CF-RAY": "abc123"}, cookies=[], body=b"", text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", request=req)

        candidate = DetectionCandidate(
            plugin_id="ACT-SQLI-001",
            vulnerability_type="sqli",
            technique=PayloadTechnique.ERROR_BASED,
            endpoint="https://example.com/page",
            parameter="id",
            payload=Payload(value="1'", technique=PayloadTechnique.ERROR_BASED, category="sqli"),
            fuzzed_request=req,
            fuzzed_response=resp,
            matched_signature=r"SQL syntax.*?MySQL",
            detection_evidence={"db_type": "MySQL"},
        )

        client = MockHTTPClient(response_text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", headers={"Server": "cloudflare", "CF-RAY": "abc123"})
        engine = VerificationEngine(http_manager=MockHTTPManager(client))

        finding = await engine.verify_candidate(candidate)
        assert finding is not None
        assert finding.verification_status == VerificationStatus.VERIFIED
        assert finding.confidence_score <= 0.80

    @pytest.mark.asyncio
    async def test_stability_check_drops_inconsistent_finding(self):
        req = HTTPRequest(method="GET", url="https://example.com/page?id=1%27")
        resp1 = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="SQL syntax error", request=req)
        resp2 = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="Normal page", request=req)

        candidate = DetectionCandidate(
            plugin_id="ACT-SQLI-001",
            vulnerability_type="sqli",
            technique=PayloadTechnique.ERROR_BASED,
            endpoint="https://example.com/page",
            parameter="id",
            payload=Payload(value="1'", technique=PayloadTechnique.ERROR_BASED, category="sqli"),
            fuzzed_request=req,
            fuzzed_response=resp1,
            matched_signature=r"SQL syntax.*?MySQL",
            detection_evidence={"db_type": "MySQL"},
        )

        class InconsistentMockClient:
            call_count = 0
            async def send(self, request):
                self.call_count += 1
                if self.call_count == 1:
                    return resp1
                return resp2
            async def close(self):
                pass

        client = InconsistentMockClient()
        engine = VerificationEngine(http_manager=MockHTTPManager(client))

        finding = await engine.verify_candidate(candidate)
        assert finding is None

    @pytest.mark.asyncio
    async def test_response_fingerprint_differs(self):
        resp_a = HTTPResponse(status_code=200, url="https://example.com", headers={}, cookies=[], body=b"", text="Response A", request=HTTPRequest(method="GET", url="https://example.com"))
        resp_b = HTTPResponse(status_code=200, url="https://example.com", headers={}, cookies=[], body=b"", text="Response B", request=HTTPRequest(method="GET", url="https://example.com"))

        engine = VerificationEngine(http_manager=MockHTTPManager(MockHTTPClient()))
        assert engine._response_differs(resp_a, resp_b) is True
        assert engine._response_differs(resp_a, resp_a) is False
        assert engine._response_differs(None, resp_b) is True

    @pytest.mark.asyncio
    async def test_waf_detection(self):
        engine = VerificationEngine(http_manager=MockHTTPManager(MockHTTPClient()))

        resp_cloudflare = HTTPResponse(status_code=200, url="https://example.com", headers={"Server": "cloudflare", "CF-RAY": "abc123"}, cookies=[], body=b"", text="test", request=HTTPRequest(method="GET", url="https://example.com"))
        detected, waf_type = engine._detect_waf(resp_cloudflare)
        assert detected is True
        assert waf_type == "cloudflare"

        resp_akamai = HTTPResponse(status_code=200, url="https://example.com", headers={"X-Akamai-Transformed": "123"}, cookies=[], body=b"", text="test", request=HTTPRequest(method="GET", url="https://example.com"))
        detected, waf_type = engine._detect_waf(resp_akamai)
        assert detected is True
        assert waf_type == "akamai"

        resp_clean = HTTPResponse(status_code=200, url="https://example.com", headers={}, cookies=[], body=b"", text="test", request=HTTPRequest(method="GET", url="https://example.com"))
        detected, waf_type = engine._detect_waf(resp_clean)
        assert detected is False
