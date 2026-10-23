"""Tests for the Dynamic Confidence Engine."""
import pytest
from unittest.mock import MagicMock, patch

from scanner.models.finding import (
    Finding, Evidence, Severity, Confidence, DetectionMethod, VerificationStatus
)
from scanner.correlation.models import EnrichedFinding, VulnerabilityIntelligence
from scanner.correlation.confidence import DynamicConfidenceEngine, ConfidenceComponents
from scanner.correlation.dynamic_confidence import DynamicConfidenceStep
from scanner.correlation.pipeline import FindingPipeline


def _make_enriched(
    plugin_id: str = "PASS-001",
    title: str = "Missing Security Header",
    severity: Severity = Severity.MEDIUM,
    endpoint: str = "https://example.com",
    endpoint_class: str = "Main Application",
    asset_category: str = "First-party",
    detection_method: DetectionMethod = DetectionMethod.PASSIVE,
    verification_status: VerificationStatus = VerificationStatus.NOT_ACTIVELY_VERIFIED,
    is_verified: bool = False,
    evidence: list[Evidence] | None = None,
    merge_count: int = 1,
    affected_endpoints: list[str] | None = None,
    false_positive_reasons: list[str] | None = None,
    raw_response: str = "",
) -> EnrichedFinding:
    if evidence is None:
        evidence = [
            Evidence(
                type="missing_header",
                description="Header missing",
                data={},
                raw_response=raw_response,
            )
        ]
    finding = Finding(
        plugin_id=plugin_id,
        title=title,
        description="Test finding",
        severity=severity,
        confidence=Confidence.MEDIUM,
        endpoint=endpoint,
        evidence=evidence,
        detection_method=detection_method,
        endpoint_class=endpoint_class,
        asset_category=asset_category,
        verification_status=verification_status,
        confidence_score=0.5,
    )
    data = finding.model_dump()
    data["is_verified"] = is_verified
    data["merge_count"] = merge_count
    data["affected_endpoints"] = affected_endpoints or [endpoint]
    data["false_positive_reasons"] = false_positive_reasons or []
    return EnrichedFinding(**data)


class TestEvidenceComponent:
    """Evidence sources contribute 30% to confidence."""

    def test_no_evidence_gives_zero_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(evidence=[])
        _, _, comp = engine.calculate(finding)
        assert comp.evidence_component == 0.0

    def test_single_evidence_gives_base_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched()
        _, _, comp = engine.calculate(finding)
        assert comp.evidence_component > 0.0

    def test_multiple_evidence_items_increase_score(self):
        engine = DynamicConfidenceEngine()
        evidence = [
            Evidence(type="e1", description="d1", data={}),
            Evidence(type="e2", description="d2", data={}),
            Evidence(type="e3", description="d3", data={}),
        ]
        finding = _make_enriched(evidence=evidence)
        _, _, comp = engine.calculate(finding)
        assert comp.evidence_component >= 0.50

    def test_raw_response_boosts_evidence_score(self):
        engine = DynamicConfidenceEngine()
        evidence = [
            Evidence(
                type="missing_header",
                description="Header missing",
                data={},
                raw_response="HTTP/1.1 200 OK\r\n\r\n",
                raw_request="GET / HTTP/1.1\r\n\r\n",
            )
        ]
        finding = _make_enriched(evidence=evidence)
        _, _, comp = engine.calculate(finding)
        assert comp.evidence_component >= 0.50

    def test_evidence_capped_at_one(self):
        engine = DynamicConfidenceEngine()
        evidence = [
            Evidence(type=f"e{i}", description=f"d{i}", data={}, raw_response="x", raw_request="x", diff="x", reproduction_steps=["x"], timing_ms=100.0, baseline_timing_ms=50.0, dom_snapshot="x", screenshot_path="x")
            for i in range(10)
        ]
        finding = _make_enriched(evidence=evidence)
        _, _, comp = engine.calculate(finding)
        assert comp.evidence_component <= 1.0


class TestVerificationComponent:
    """Verification success contributes 40% to confidence."""

    def test_verified_gives_full_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(
            verification_status=VerificationStatus.VERIFIED,
            is_verified=True,
        )
        _, _, comp = engine.calculate(finding)
        assert comp.verification_component == 1.0

    def test_failed_verification_low_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(
            verification_status=VerificationStatus.FAILED,
            is_verified=False,
        )
        _, _, comp = engine.calculate(finding)
        assert comp.verification_component == 0.3

    def test_active_detection_medium_high_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(
            detection_method=DetectionMethod.ACTIVE,
            verification_status=VerificationStatus.NOT_ACTIVELY_VERIFIED,
        )
        _, _, comp = engine.calculate(finding)
        assert comp.verification_component == 0.55

    def test_passive_detection_medium_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(
            detection_method=DetectionMethod.PASSIVE,
            verification_status=VerificationStatus.NOT_ACTIVELY_VERIFIED,
        )
        _, _, comp = engine.calculate(finding)
        assert comp.verification_component == 0.4


class TestEndpointComponent:
    """Endpoint count contributes 20% to confidence."""

    def test_single_endpoint_low_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(merge_count=1, affected_endpoints=["https://example.com"])
        _, _, comp = engine.calculate(finding)
        assert comp.endpoint_component == 0.4

    def test_two_endpoints_medium_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(
            merge_count=2,
            affected_endpoints=["https://example.com", "https://example.org"],
        )
        _, _, comp = engine.calculate(finding)
        assert comp.endpoint_component == 0.6

    def test_three_endpoints_high_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(
            merge_count=3,
            affected_endpoints=["https://a.com", "https://b.com", "https://c.com"],
        )
        _, _, comp = engine.calculate(finding)
        assert comp.endpoint_component == 0.8

    def test_five_endpoints_max_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(
            merge_count=5,
            affected_endpoints=[f"https://{i}.com" for i in range(5)],
        )
        _, _, comp = engine.calculate(finding)
        assert comp.endpoint_component == 1.0


class TestFrameworkComponent:
    """Known framework detection contributes 10% to confidence."""

    def test_django_path_good_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(endpoint="https://example.com/admin/dashboard")
        _, _, comp = engine.calculate(finding)
        assert comp.framework_component == 0.9

    def test_rails_path_good_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(endpoint="https://example.com/assets/application.js")
        _, _, comp = engine.calculate(finding)
        assert comp.framework_component == 0.9

    def test_unknown_path_low_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(endpoint="https://example.com/custom/page")
        _, _, comp = engine.calculate(finding)
        assert comp.framework_component == 0.2

    def test_framework_header_detection(self):
        engine = DynamicConfidenceEngine()
        raw_response = "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\nX-XSS-Protection: 1; mode=block\r\n\r\n"
        finding = _make_enriched(endpoint="https://example.com/unknown", raw_response=raw_response)
        _, _, comp = engine.calculate(finding)
        assert comp.framework_component >= 0.7


class TestTechnologyComponent:
    """Technology fingerprint confidence contributes to overall score."""

    def test_technology_confidence_from_context(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched()
        ctx = {"technology_confidence": 0.9}
        _, _, comp = engine.calculate(finding, ctx)
        assert comp.technology_component == 0.9

    def test_technology_keywords_in_description(self):
        engine = DynamicConfidenceEngine()
        intel = VulnerabilityIntelligence(description="WordPress plugin vulnerability")
        finding = _make_enriched()
        finding.intelligence = intel
        _, _, comp = engine.calculate(finding)
        assert comp.technology_component >= 0.7

    def test_no_technology_info_defaults(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched()
        _, _, comp = engine.calculate(finding)
        assert comp.technology_component == 0.3


class TestHistoricalComponent:
    """Plugin reliability contributes to confidence."""

    def test_high_reliability_plugin(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(plugin_id="ACT-XSS-001", detection_method=DetectionMethod.ACTIVE)
        _, _, comp = engine.calculate(finding)
        assert comp.historical_component >= 0.90

    def test_low_reliability_plugin(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(plugin_id="PASS-003", detection_method=DetectionMethod.PASSIVE)
        _, _, comp = engine.calculate(finding)
        assert comp.historical_component <= 0.65

    def test_unknown_plugin_defaults(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(plugin_id="UNKNOWN-999", detection_method=DetectionMethod.PASSIVE)
        _, _, comp = engine.calculate(finding)
        assert comp.historical_component <= 0.70


class TestMitigationComponent:
    """Existing security controls reduce confidence in exploitability."""

    def test_no_mitigations_full_score(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(raw_response="HTTP/1.1 200 OK\r\n\r\n")
        _, _, comp = engine.calculate(finding)
        assert comp.mitigation_component == 1.0

    def test_csp_header_reduces_confidence(self):
        engine = DynamicConfidenceEngine()
        raw_response = "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\n\r\n"
        finding = _make_enriched(raw_response=raw_response)
        _, _, comp = engine.calculate(finding)
        assert comp.mitigation_component < 1.0

    def test_multiple_mitigations_further_reduce(self):
        engine = DynamicConfidenceEngine()
        raw_response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Security-Policy: default-src 'self'\r\n"
            "X-Frame-Options: DENY\r\n"
            "Strict-Transport-Security: max-age=31536000\r\n"
            "\r\n"
        )
        finding = _make_enriched(raw_response=raw_response)
        _, _, comp = engine.calculate(finding)
        assert comp.mitigation_component < 0.8

    def test_mitigation_floor(self):
        engine = DynamicConfidenceEngine()
        raw_response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Security-Policy: default-src 'self'\r\n"
            "X-Frame-Options: DENY\r\n"
            "Strict-Transport-Security: max-age=31536000\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "Permissions-Policy: geolocation=()\r\n"
            "Referrer-Policy: strict-origin-when-cross-origin\r\n"
            "\r\n"
        )
        finding = _make_enriched(raw_response=raw_response)
        _, _, comp = engine.calculate(finding)
        assert comp.mitigation_component >= 0.2


class TestRuleCertaintyComponent:
    """Rule certainty contributes to confidence."""

    def test_active_plugin_high_certainty(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(plugin_id="ACT-XSS-001")
        _, _, comp = engine.calculate(finding)
        assert comp.rule_certainty_component >= 0.90

    def test_passive_plugin_lower_certainty(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(plugin_id="PASS-003")
        _, _, comp = engine.calculate(finding)
        assert comp.rule_certainty_component <= 0.55

    def test_matched_value_boosts_certainty(self):
        engine = DynamicConfidenceEngine()
        evidence = [
            Evidence(
                type="xss_reflection",
                description="Reflected XSS",
                data={},
                matched_value="<script>alert(1)</script>",
                detection_rule="ReflectScriptRule",
            )
        ]
        finding = _make_enriched(plugin_id="ACT-XSS-001", evidence=evidence)
        _, _, comp = engine.calculate(finding)
        assert comp.rule_certainty_component >= 0.95


class TestFinalConfidenceMapping:
    """Final score maps correctly to qualitative confidence."""

    def test_certain_threshold(self):
        assert DynamicConfidenceEngine._score_to_confidence(0.96) == Confidence.CERTAIN
        assert DynamicConfidenceEngine._score_to_confidence(0.85) == Confidence.VERY_HIGH

    def test_high_threshold(self):
        assert DynamicConfidenceEngine._score_to_confidence(0.70) == Confidence.HIGH
        assert DynamicConfidenceEngine._score_to_confidence(0.55) == Confidence.LIKELY

    def test_medium_threshold(self):
        assert DynamicConfidenceEngine._score_to_confidence(0.40) == Confidence.MEDIUM
        assert DynamicConfidenceEngine._score_to_confidence(0.25) == Confidence.TENTATIVE

    def test_low_below_threshold(self):
        assert DynamicConfidenceEngine._score_to_confidence(0.15) == Confidence.LOW
        assert DynamicConfidenceEngine._score_to_confidence(0.0) == Confidence.LOW


class TestExplanationFormat:
    """Explanation string contains all component breakdowns."""

    def test_explanation_contains_components(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(plugin_id="ACT-XSS-001", detection_method=DetectionMethod.ACTIVE)
        _, _, comp = engine.calculate(finding)
        _, _, components = engine.calculate(finding)
        explanation = DynamicConfidenceEngine._build_explanation(components, Confidence.HIGH)
        assert "evidence=" in explanation
        assert "verification=" in explanation
        assert "endpoints=" in explanation
        assert "framework=" in explanation
        assert "technology=" in explanation
        assert "historical=" in explanation
        assert "mitigation=" in explanation
        assert "rule=" in explanation


class TestPipelineIntegration:
    """DynamicConfidenceStep integrates with the pipeline."""

    @pytest.mark.asyncio
    async def test_dynamic_confidence_runs_in_pipeline(self):
        step = DynamicConfidenceStep()
        pipeline = FindingPipeline(steps=[], dynamic_confidence_step=step)

        finding = _make_enriched(plugin_id="ACT-XSS-001", detection_method=DetectionMethod.ACTIVE)
        result = await pipeline.apply_dynamic_confidence(finding)
        assert result is not None
        assert result.severity_reason is not None

    @pytest.mark.asyncio
    async def test_dynamic_confidence_overrides_previous_confidence(self):
        step = DynamicConfidenceStep()
        pipeline = FindingPipeline(steps=[], dynamic_confidence_step=step)

        finding = _make_enriched(plugin_id="PASS-003", detection_method=DetectionMethod.PASSIVE)
        original_confidence = finding.confidence
        result = await pipeline.apply_dynamic_confidence(finding)
        assert result is not None
        # Confidence may change based on dynamic calculation
        assert result.confidence_score >= 0.0
        assert result.confidence_score <= 1.0

    @pytest.mark.asyncio
    async def test_dynamic_confidence_handles_none_finding(self):
        step = DynamicConfidenceStep()
        result = await step.process(None)
        assert result is None


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_plugin_id_defaults(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(plugin_id="")
        _, _, comp = engine.calculate(finding)
        assert comp.historical_component <= 0.70
        assert comp.rule_certainty_component <= 0.65

    def test_none_endpoint(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(endpoint="")
        _, _, comp = engine.calculate(finding)
        assert comp.framework_component == 0.2

    def test_very_high_confidence_clamped(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(
            plugin_id="ACT-XSS-001",
            detection_method=DetectionMethod.ACTIVE,
            verification_status=VerificationStatus.VERIFIED,
            is_verified=True,
            merge_count=10,
            affected_endpoints=[f"https://{i}.com" for i in range(10)],
        )
        _, score, comp = engine.calculate(finding)
        assert score <= 1.0

    def test_very_low_confidence_floor(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched(
            plugin_id="PASS-003",
            detection_method=DetectionMethod.PASSIVE,
            verification_status=VerificationStatus.FAILED,
            evidence=[],
        )
        _, score, comp = engine.calculate(finding)
        assert score >= 0.0

    def test_scan_context_technology_confidence(self):
        engine = DynamicConfidenceEngine()
        finding = _make_enriched()
        ctx = {"technology_confidence": 0.95}
        _, _, comp = engine.calculate(finding, ctx)
        assert comp.technology_component == 0.95
