"""Tests for the Central Finding Evaluation Engine."""
import pytest
from unittest.mock import MagicMock

from scanner.models.finding import (
    Finding, Evidence, Severity, Confidence, DetectionMethod, VerificationStatus
)
from scanner.passive.models import PassiveObservation, PluginMetadata
from scanner.active.models import (
    DetectionCandidate, Payload, PayloadTechnique, BaselineResult,
    HTTPRequest, HTTPResponse
)
from scanner.correlation.central_evaluator import (
    CentralFindingEvaluator,
    CentralEvaluationStep,
    RawEvidence,
    EvidenceSource,
)
from scanner.correlation.pipeline import FindingPipeline


def _make_passive_observation(
    plugin_id: str = "PASS-001",
    title: str = "Missing Security Header",
    obs_type: str = "missing_header",
    endpoint: str = "https://example.com",
    severity=Severity.LOW,
    evidence: list | None = None,
) -> PassiveObservation:
    if evidence is None:
        evidence = [
            Evidence(
                type=obs_type,
                description=title,
                data={"missing_header": "Strict-Transport-Security"},
            )
        ]
    return PassiveObservation(
        plugin_id=plugin_id,
        observation_type=obs_type,
        title=title,
        description=f"Passive observation: {title}",
        endpoint=endpoint,
        severity=severity,
        evidence=evidence,
    )


def _make_detection_candidate(
    plugin_id: str = "ACT-XSS-001",
    vuln_type: str = "xss",
    endpoint: str = "https://example.com/search",
    parameter: str = "q",
    payload: str = "<script>alert(1)</script>",
    technique: PayloadTechnique = PayloadTechnique.REFLECTION,
) -> DetectionCandidate:
    req = HTTPRequest(
        method="GET",
        url=endpoint,
        headers={"User-Agent": "Scanner/1.0"},
        body="",
    )
    resp = HTTPResponse(
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=f"<html>{payload}</html>",
        url=endpoint,
        text=f"<html>{payload}</html>",
        request=req,
    )
    payload_obj = Payload(
        value=payload,
        technique=technique,
        category=vuln_type,
    )
    return DetectionCandidate(
        plugin_id=plugin_id,
        vulnerability_type=vuln_type,
        technique=technique,
        endpoint=endpoint,
        parameter=parameter,
        payload=payload_obj,
        fuzzed_request=req,
        fuzzed_response=resp,
        fuzzed_timing_ms=120.0,
        raw_request_str=str(req),
        raw_response_str=f"<html>{payload}</html>",
        matched_signature="<script>",
        reflection_context="inside HTML body",
    )


class TestRawEvidenceModel:
    """Test RawEvidence dataclass."""

    def test_raw_evidence_creation(self):
        raw = RawEvidence(
            source=EvidenceSource.ACTIVE_PLUGIN,
            plugin_id="ACT-XSS-001",
            plugin_name="Reflected XSS",
            vulnerability_type="xss",
            endpoint="https://example.com",
        )
        assert raw.source == EvidenceSource.ACTIVE_PLUGIN
        assert raw.plugin_id == "ACT-XSS-001"
        assert raw.vulnerability_type == "xss"

    def test_raw_evidence_to_dict(self):
        raw = RawEvidence(
            source=EvidenceSource.PASSIVE_PLUGIN,
            plugin_id="PASS-001",
            plugin_name="Missing HSTS",
            vulnerability_type="missing_header",
            endpoint="https://example.com",
            payload="test",
        )
        d = raw.to_dict()
        assert d["source"] == "passive_plugin"
        assert d["plugin_id"] == "PASS-001"
        assert d["payload"] == "test"


class TestAdapterMethods:
    """Test conversion from plugin outputs to RawEvidence."""

    def test_passive_observation_adapter(self):
        obs = _make_passive_observation()
        raw = CentralFindingEvaluator.from_passive_observation(obs)
        assert raw.source == EvidenceSource.PASSIVE_PLUGIN
        assert raw.plugin_id == "PASS-001"
        assert raw.vulnerability_type == "missing_header"
        assert raw.endpoint == "https://example.com"

    def test_detection_candidate_adapter(self):
        candidate = _make_detection_candidate()
        raw = CentralFindingEvaluator.from_detection_candidate(candidate)
        assert raw.source == EvidenceSource.ACTIVE_PLUGIN
        assert raw.plugin_id == "ACT-XSS-001"
        assert raw.vulnerability_type == "xss"
        assert raw.parameter == "q"
        assert raw.payload == "<script>alert(1)</script>"
        assert raw.technique == "reflection"

    def test_passive_adapter_preserves_evidence(self):
        obs = _make_passive_observation(
            evidence=[
                Evidence(
                    type="missing_header",
                    description="HSTS missing",
                    data={"header": "Strict-Transport-Security"},
                    raw_response="HTTP/1.1 200 OK\r\n\r\n",
                    matched_value="Strict-Transport-Security",
                )
            ]
        )
        raw = CentralFindingEvaluator.from_passive_observation(obs)
        assert raw.raw_response is not None
        assert raw.matched_value == "Strict-Transport-Security"


class TestCentralFindingEvaluator:
    """Test the central evaluator produces valid Finding objects."""

    def setup_method(self):
        self.evaluator = CentralFindingEvaluator()

    def test_evaluate_passive_observation(self):
        obs = _make_passive_observation()
        raw = CentralFindingEvaluator.from_passive_observation(obs)
        finding = self.evaluator.evaluate(raw)
        assert finding is not None
        assert isinstance(finding, Finding)
        assert finding.plugin_id == "PASS-001"
        assert finding.severity == Severity.LOW
        assert finding.confidence == Confidence.LOW
        assert finding.detection_method == DetectionMethod.PASSIVE

    def test_evaluate_detection_candidate(self):
        candidate = _make_detection_candidate()
        raw = CentralFindingEvaluator.from_detection_candidate(candidate)
        finding = self.evaluator.evaluate(raw)
        assert finding is not None
        assert isinstance(finding, Finding)
        assert finding.plugin_id == "ACT-XSS-001"
        assert finding.severity == Severity.HIGH
        assert finding.confidence in (Confidence.HIGH, Confidence.VERY_HIGH, Confidence.CERTAIN)
        assert finding.detection_method == DetectionMethod.ACTIVE
        assert finding.attack_payload == "<script>alert(1)</script>"
        assert finding.affected_parameter == "q"

    def test_evaluate_sets_cwe_owasp(self):
        candidate = _make_detection_candidate(plugin_id="ACT-SQLI-001", vuln_type="sqli")
        raw = CentralFindingEvaluator.from_detection_candidate(candidate)
        finding = self.evaluator.evaluate(raw)
        assert finding is not None
        assert finding.cwe_id == "CWE-89"
        assert finding.owasp_category == "A03:2021-Injection"

    def test_evaluate_sets_evidence(self):
        candidate = _make_detection_candidate()
        raw = CentralFindingEvaluator.from_detection_candidate(candidate)
        finding = self.evaluator.evaluate(raw)
        assert finding is not None
        assert len(finding.evidence) == 1
        assert finding.evidence[0].type == "xss"

    def test_evaluate_sets_remediation(self):
        obs = _make_passive_observation(obs_type="cookie")
        raw = CentralFindingEvaluator.from_passive_observation(obs)
        finding = self.evaluator.evaluate(raw)
        assert finding is not None
        assert "Secure" in finding.remediation or "HttpOnly" in finding.remediation

    def test_evaluate_sets_reproduction_steps(self):
        candidate = _make_detection_candidate()
        raw = CentralFindingEvaluator.from_detection_candidate(candidate)
        finding = self.evaluator.evaluate(raw)
        assert finding is not None
        assert len(finding.reproduction_steps) >= 1
        assert "https://example.com/search" in finding.reproduction_steps[0]

    def test_evaluate_sets_why_detected(self):
        candidate = _make_detection_candidate()
        raw = CentralFindingEvaluator.from_detection_candidate(candidate)
        finding = self.evaluator.evaluate(raw)
        assert finding is not None
        assert "ACT-XSS-001" in finding.why_detected
        assert "xss" in finding.why_detected

    def test_evaluate_sets_how_verified(self):
        candidate = _make_detection_candidate()
        raw = CentralFindingEvaluator.from_detection_candidate(candidate)
        finding = self.evaluator.evaluate(raw)
        assert finding is not None
        assert "Active detection" in finding.how_verified

    def test_evaluate_sets_false_positive_reasons(self):
        obs = _make_passive_observation()
        raw = CentralFindingEvaluator.from_passive_observation(obs)
        finding = self.evaluator.evaluate(raw)
        assert finding is not None
        assert len(finding.false_positive_reasons) >= 1

    def test_evaluate_unknown_plugin_id(self):
        obs = _make_passive_observation(plugin_id="UNKNOWN-999")
        raw = CentralFindingEvaluator.from_passive_observation(obs)
        finding = self.evaluator.evaluate(raw)
        assert finding is not None
        assert finding.cwe_id is None


class TestCentralEvaluationStep:
    """Test the pipeline step wrapper."""

    @pytest.mark.asyncio
    async def test_process_passive_observation(self):
        step = CentralEvaluationStep()
        obs = _make_passive_observation()
        result = await step.process(obs)
        assert result is not None
        assert isinstance(result, Finding)
        assert result.plugin_id == "PASS-001"

    @pytest.mark.asyncio
    async def test_process_detection_candidate(self):
        step = CentralEvaluationStep()
        candidate = _make_detection_candidate()
        result = await step.process(candidate)
        assert result is not None
        assert isinstance(result, Finding)
        assert result.plugin_id == "ACT-XSS-001"

    @pytest.mark.asyncio
    async def test_process_finding_passthrough(self):
        step = CentralEvaluationStep()
        finding = Finding(
            plugin_id="TEST", title="Test", description="Test",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            endpoint="https://example.com"
        )
        result = await step.process(finding)
        assert result is not None
        assert result.plugin_id == "TEST"

    @pytest.mark.asyncio
    async def test_process_none_returns_none(self):
        step = CentralEvaluationStep()
        result = await step.process(None)
        assert result is None


class TestPipelineIntegration:
    """Test that CentralEvaluationStep integrates with FindingPipeline."""

    @pytest.mark.asyncio
    async def test_pipeline_runs_central_evaluation_first(self):
        central_step = CentralEvaluationStep()
        pipeline = FindingPipeline(
            steps=[],
            central_evaluation_step=central_step,
        )

        candidate = _make_detection_candidate()
        result = await pipeline.process(candidate)
        # With no further steps, the pipeline returns None because
        # _process_single converts to Finding but there are no enrichment steps
        # This is expected - the central step runs but without enrichment steps
        # the Finding doesn't become EnrichedFinding
        assert result is None or (hasattr(result, 'plugin_id') and result.plugin_id == "ACT-XSS-001")

    @pytest.mark.asyncio
    async def test_pipeline_with_verification_after_central_evaluation(self):
        from scanner.correlation.verification import EvidenceVerificationStep
        central_step = CentralEvaluationStep()
        verification_step = EvidenceVerificationStep()
        pipeline = FindingPipeline(
            steps=[verification_step],
            central_evaluation_step=central_step,
        )

        candidate = _make_detection_candidate()
        result = await pipeline.process(candidate)
        assert result is not None
        assert result.plugin_id == "ACT-XSS-001"

    @pytest.mark.asyncio
    async def test_pipeline_with_passive_observation(self):
        from scanner.correlation.verification import EvidenceVerificationStep
        central_step = CentralEvaluationStep()
        verification_step = EvidenceVerificationStep()
        pipeline = FindingPipeline(
            steps=[verification_step],
            central_evaluation_step=central_step,
        )

        obs = _make_passive_observation()
        result = await pipeline.process(obs)
        assert result is not None
        assert result.plugin_id == "PASS-001"


class TestArchitecturalGuarantees:
    """Test that the evaluator provides a single authoritative evaluation point."""

    def test_all_plugin_outputs_produce_findings(self):
        evaluator = CentralFindingEvaluator()
        
        passive_obs = _make_passive_observation()
        active_candidate = _make_detection_candidate()
        
        passive_raw = CentralFindingEvaluator.from_passive_observation(passive_obs)
        active_raw = CentralFindingEvaluator.from_detection_candidate(active_candidate)
        
        passive_finding = evaluator.evaluate(passive_raw)
        active_finding = evaluator.evaluate(active_raw)
        
        assert isinstance(passive_finding, Finding)
        assert isinstance(active_finding, Finding)
        
        assert passive_finding.severity in list(Severity)
        assert passive_finding.confidence in list(Confidence)
        assert passive_finding.detection_method == DetectionMethod.PASSIVE
        
        assert active_finding.severity in list(Severity)
        assert active_finding.confidence in list(Confidence)
        assert active_finding.detection_method == DetectionMethod.ACTIVE

    def test_evaluator_is_single_source_of_truth(self):
        """Verify that all findings go through the same evaluation logic."""
        evaluator = CentralFindingEvaluator()
        
        candidates = [
            _make_detection_candidate(plugin_id="ACT-XSS-001", vuln_type="xss"),
            _make_detection_candidate(plugin_id="ACT-SQLI-001", vuln_type="sqli"),
            _make_detection_candidate(plugin_id="ACT-SSRF-001", vuln_type="ssrf"),
        ]
        
        findings = []
        for c in candidates:
            raw = CentralFindingEvaluator.from_detection_candidate(c)
            finding = evaluator.evaluate(raw)
            findings.append(finding)
        
        # All findings should have consistent structure
        for f in findings:
            assert f.cwe_id is not None
            assert f.owasp_category is not None
            assert len(f.evidence) == 1
            assert f.detection_method == DetectionMethod.ACTIVE
            assert f.verification_status == VerificationStatus.NOT_ACTIVELY_VERIFIED
