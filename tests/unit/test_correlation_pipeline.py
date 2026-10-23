import pytest
from scanner.models.finding import Finding, Evidence, Severity, Confidence
from scanner.correlation.models import EnrichedFinding
from scanner.correlation.pipeline import FindingPipeline
from scanner.correlation.verification import EvidenceVerificationStep
from scanner.correlation.deduplication import DeduplicationStep
from scanner.correlation.intelligence import IntelligenceEnrichmentStep

class MockHTTPClient:
    def __init__(self, response_text="", headers=None, latency=0.0):
        self.response_text = response_text
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.latency = latency

    async def send(self, request):
        import asyncio
        if self.latency > 0:
            await asyncio.sleep(min(self.latency, 0.1)) # Don't block test execution long
        return type('HTTPResponse', (), {
            'status_code': 200,
            'text': self.response_text,
            'headers': self.headers
        })()

class MockHTTPManager:
    def __init__(self, client):
        self.client = client

    def get_shared_client(self):
        return self.client


@pytest.mark.asyncio
async def test_evidence_verification_fallback():
    from scanner.passive.models import PassiveObservation
    client = MockHTTPClient(response_text="Test", headers={})
    step = EvidenceVerificationStep(http_manager=MockHTTPManager(client))
    pipeline = FindingPipeline(steps=[step])
    
    obs = PassiveObservation(
        plugin_id="PASS-01", observation_type="missing_header", title="Test", description="Test", endpoint="https://example.com",
        evidence=[Evidence(type="test", description="test", data="test")]
    )
    result = await pipeline.process(obs)
    assert result is not None
    assert result.title == "Test"


@pytest.mark.asyncio
async def test_xss_context_aware_verification():
    from scanner.active.models import DetectionCandidate, Payload, PayloadTechnique
    from scanner.network.models import HTTPRequest, HTTPResponse
    
    req = HTTPRequest(method="GET", url="https://example.com/page?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
    resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="", request=req)
    
    candidate = DetectionCandidate(
        plugin_id="ACT-XSS-001",
        vulnerability_type="xss",
        technique=PayloadTechnique.REFLECTION,
        endpoint="https://example.com/page",
        parameter="q",
        payload=Payload(value="<script>alert(1)</script>"),
        fuzzed_request=req,
        fuzzed_response=resp,
        reflection_context="html"
    )
    
    # 1. Non-HTML content-type test (should drop XSS)
    client_json = MockHTTPClient(
        response_text='{"data": "<script>alert(1)</script>"}',
        headers={"Content-Type": "application/json"}
    )
    step_json = EvidenceVerificationStep(http_manager=MockHTTPManager(client_json))
    
    res_json = await step_json.process(candidate)
    assert res_json is None # Dropped due to JSON context

    # 2. Executable HTML context test (should verify XSS)
    client_html = MockHTTPClient(
        response_text='<html><body><script>alert(1)</script></body></html>',
        headers={"Content-Type": "text/html"}
    )
    step_html = EvidenceVerificationStep(http_manager=MockHTTPManager(client_html))
    res_html = await step_html.process(candidate)
    assert res_html is not None
    assert res_html.is_verified is True


@pytest.mark.asyncio
async def test_path_traversal_control_check():
    from scanner.active.models import DetectionCandidate, Payload, PayloadTechnique, BaselineResult
    from scanner.network.models import HTTPRequest, HTTPResponse
    
    req = HTTPRequest(method="GET", url="https://example.com/page?file=../../../../etc/passwd")
    resp = HTTPResponse(status_code=200, url=req.url, headers={}, cookies=[], body=b"", text="root:x:0:0:", request=req)
    
    baseline = BaselineResult(
        request=HTTPRequest(method="GET", url="https://example.com/page?file=fuzz"),
        response=HTTPResponse(status_code=200, url="https://example.com/page?file=fuzz", headers={}, cookies=[], body=b"", text="Safe page", request=HTTPRequest(method="GET", url="https://example.com/page?file=fuzz"))
    )

    candidate = DetectionCandidate(
        plugin_id="ACT-TRAV-001",
        vulnerability_type="path_traversal",
        technique=PayloadTechnique.FILE_READ,
        endpoint="https://example.com/page",
        parameter="file",
        payload=Payload(value="../../../../etc/passwd"),
        fuzzed_request=req,
        fuzzed_response=resp,
        baseline=baseline,
        file_marker="root:x:0:0:"
    )

    # 1. False positive check: both fuzzed and invalid control match signature (should drop)
    client_fp = MockHTTPClient(response_text='Static index: root:x:0:0:')
    step_fp = EvidenceVerificationStep(http_manager=MockHTTPManager(client_fp))
    
    res_fp = await step_fp.process(candidate)
    assert res_fp is None # Dropped due to static match on control file


@pytest.mark.asyncio
async def test_deduplication():
    step = DeduplicationStep()
    pipeline = FindingPipeline(steps=[step])
    
    f1 = EnrichedFinding(
        plugin_id="TEST-01", title="Test Param 'q'", description="Test", severity=Severity.LOW, confidence=Confidence.LOW, endpoint="https://example.com",
        evidence=[Evidence(type="test", description="test", data="test")]
    )
    
    # First time should pass
    result1 = await pipeline.process(f1, scan_id="scan-1")
    assert result1 is not None
    
    # Second time exact same finding should drop
    result2 = await pipeline.process(f1, scan_id="scan-1")
    assert result2 is None
    
    # Different parameter (title change) should pass
    f2 = EnrichedFinding(
        plugin_id="TEST-01", title="Test Param 'id'", description="Test", severity=Severity.LOW, confidence=Confidence.LOW, endpoint="https://example.com",
        evidence=[Evidence(type="test", description="test", data="test")]
    )
    result3 = await pipeline.process(f2, scan_id="scan-1")
    assert result3 is not None


@pytest.mark.asyncio
async def test_intelligence_enrichment():
    step = IntelligenceEnrichmentStep()
    pipeline = FindingPipeline(steps=[step])
    
    f1 = EnrichedFinding(
        plugin_id="ACT-XSS-001", title="XSS", description="Test", severity=Severity.HIGH, confidence=Confidence.HIGH, endpoint="https://example.com",
        evidence=[Evidence(type="test", description="test", data="test")]
    )
    
    result = await pipeline.process(f1)
    assert result is not None
    assert result.intelligence is not None
    assert result.intelligence.cwe_id == "CWE-79"
    assert "Cross-site Scripting" in result.intelligence.cwe_name
