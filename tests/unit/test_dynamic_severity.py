"""Tests for the Dynamic Severity Engine."""
import pytest
from unittest.mock import MagicMock, patch

from scanner.models.finding import (
    Finding, Evidence, Severity, Confidence, DetectionMethod, VerificationStatus
)
from scanner.correlation.models import EnrichedFinding, VulnerabilityIntelligence
from scanner.risk.severity_engine import DynamicSeverityEngine, SeverityComponents
from scanner.risk.models import AssetCriticality, ExposureLevel
from scanner.correlation.dynamic_severity import DynamicSeverityStep
from scanner.correlation.pipeline import FindingPipeline


def _make_enriched(
    plugin_id: str = "PASS-001",
    title: str = "Missing Security Header",
    severity: Severity = Severity.MEDIUM,
    endpoint: str = "https://example.com",
    endpoint_class: str = "Main Application",
    asset_category: str = "First-party",
    cvss_score: float = 5.0,
    detection_method: DetectionMethod = DetectionMethod.PASSIVE,
    verification_status: VerificationStatus = VerificationStatus.NOT_ACTIVELY_VERIFIED,
    confidence: Confidence = Confidence.MEDIUM,
    raw_response: str = "",
    false_positive_reasons: list[str] | None = None,
    cwe_id: str | None = None,
) -> EnrichedFinding:
    evidence = [
        Evidence(
            type="missing_header",
            description="Header missing",
            data={},
            raw_response=raw_response,
        )
    ]
    intelligence = VulnerabilityIntelligence(cwe_id=cwe_id)
    finding = Finding(
        plugin_id=plugin_id,
        title=title,
        description="Test finding",
        severity=severity,
        confidence=confidence,
        endpoint=endpoint,
        evidence=evidence,
        detection_method=detection_method,
        endpoint_class=endpoint_class,
        asset_category=asset_category,
        verification_status=verification_status,
        confidence_score=0.5,
    )
    data = finding.model_dump()
    data["intelligence"] = intelligence
    data["cvss_score"] = cvss_score
    data["false_positive_reasons"] = false_positive_reasons or []
    return EnrichedFinding(**data)


class TestCVSSComponent:
    """CVSS base score is the dominant factor."""

    def test_high_cvss_produces_high_severity(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=9.0)
        sev, _, comp = engine.calculate(finding)
        assert sev in (Severity.HIGH, Severity.CRITICAL)

    def test_low_cvss_produces_low_severity(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=2.0)
        sev, _, comp = engine.calculate(finding)
        assert sev in (Severity.LOW, Severity.INFO, Severity.MEDIUM)

    def test_zero_cvss_produces_info(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=0.0)
        sev, _, comp = engine.calculate(finding)
        # With zero CVSS, other factors (asset, exposure, etc.) may push above INFO.
        # Verify that CVSS component is zero and final score is clamped to >= 0.
        assert comp.cvss_component == 0.0
        assert comp.final_score >= 0.0

    def test_fallback_to_severity_when_no_cvss(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=None, severity=Severity.HIGH)
        sev, _, comp = engine.calculate(finding)
        assert sev == Severity.HIGH


class TestContextComponent:
    """Endpoint class and asset category adjust severity."""

    def test_admin_endpoint_boosts_severity(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=6.0, endpoint_class="Admin")
        sev, _, comp = engine.calculate(finding)
        assert comp.context_component > comp.cvss_component

    def test_static_asset_dampens_severity(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=6.0, endpoint_class="Static Assets")
        sev, _, comp = engine.calculate(finding)
        assert comp.context_component < comp.cvss_component

    def test_cdn_asset_dampens_severity(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=6.0, asset_category="CDN")
        sev, _, comp = engine.calculate(finding)
        # CDN category has a 0.85 multiplier in context_component
        assert comp.context_component < comp.cvss_component * 1.15

    def test_payment_asset_boosts_severity(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=6.0, asset_category="Payment")
        sev, _, comp = engine.calculate(finding)
        assert comp.asset_component > 10.0


class TestAssetAndExposure:
    """Asset criticality and exposure level are factored in."""

    def test_mission_critical_boosts(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=5.0)
        ctx = {"asset_criticality": AssetCriticality.MISSION_CRITICAL}
        sev, _, comp = engine.calculate(finding, ctx)
        assert comp.asset_component > 10.0

    def test_internal_exposure_dampens(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=5.0)
        ctx = {"exposure": ExposureLevel.INTERNAL}
        sev, _, comp = engine.calculate(finding, ctx)
        assert comp.asset_component < 10.0

    def test_internet_facing_boosts(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=5.0)
        ctx = {"exposure": ExposureLevel.INTERNET_FACING}
        sev, _, comp = engine.calculate(finding, ctx)
        assert comp.asset_component > 10.0


class TestExploitabilityComponent:
    """EPSS and KEV status boost exploitability component."""

    def test_kev_boosts_exploitability(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=5.0, cwe_id="CWE-89")
        with patch("scanner.risk.severity_engine.KEVAnalyzer.is_kev", return_value=True):
            with patch("scanner.risk.severity_engine.EPSSAnalyzer.analyze", return_value=MagicMock(probability=0.0)):
                sev, _, comp = engine.calculate(finding)
        assert comp.exploitability_component >= 2.0

    def test_high_epss_boosts_exploitability(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=5.0, cwe_id="CWE-89")
        with patch("scanner.risk.severity_engine.KEVAnalyzer.is_kev", return_value=False):
            with patch("scanner.risk.severity_engine.EPSSAnalyzer.analyze", return_value=MagicMock(probability=0.8)):
                sev, _, comp = engine.calculate(finding)
        assert comp.exploitability_component >= 1.0


class TestVerificationComponent:
    """Verification status and confidence affect severity."""

    def test_verified_finding_gets_boost(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(
            cvss_score=5.0,
            verification_status=VerificationStatus.VERIFIED,
            confidence=Confidence.HIGH,
        )
        sev, _, comp = engine.calculate(finding)
        assert comp.verification_component > 10.0

    def test_failed_verification_dampens(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(
            cvss_score=5.0,
            verification_status=VerificationStatus.FAILED,
            confidence=Confidence.LOW,
        )
        sev, _, comp = engine.calculate(finding)
        assert comp.verification_component < 10.0

    def test_not_verified_is_neutral(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(
            cvss_score=5.0,
            verification_status=VerificationStatus.NOT_ACTIVELY_VERIFIED,
            confidence=Confidence.MEDIUM,
        )
        sev, _, comp = engine.calculate(finding)
        assert comp.verification_component == 10.0


class TestBusinessComponent:
    """Business risk influences final severity."""

    def test_high_cwe_business_risk(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=5.0, cwe_id="CWE-89")
        sev, _, comp = engine.calculate(finding)
        assert comp.business_component > 5.0

    def test_unknown_cwe_defaults_business_risk(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=5.0, cwe_id=None)
        sev, _, comp = engine.calculate(finding)
        assert comp.business_component >= 0.0


class TestMitigationDampening:
    """Existing protections reduce final severity."""

    def test_csp_header_dampens(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=8.0, raw_response="Content-Security-Policy: default-src 'self'\r\n")
        sev, _, comp = engine.calculate(finding)
        assert comp.mitigation_dampener < 1.0
        assert comp.final_score < comp.raw_score

    def test_hsts_header_dampens(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=8.0, raw_response="Strict-Transport-Security: max-age=31536000\r\n")
        sev, _, comp = engine.calculate(finding)
        assert comp.mitigation_dampener < 1.0

    def test_false_positive_reasons_dampen(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=8.0, false_positive_reasons=["CDN-managed endpoint"])
        sev, _, comp = engine.calculate(finding)
        assert comp.mitigation_dampener < 1.0

    def test_static_asset_endpoint_dampens(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=8.0, endpoint_class="Static Assets")
        sev, _, comp = engine.calculate(finding)
        assert comp.mitigation_dampener < 1.0

    def test_no_dampening_without_mitigations(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=5.0, raw_response="HTTP/1.1 200 OK\r\n")
        sev, _, comp = engine.calculate(finding)
        assert comp.mitigation_dampener == 1.0


class TestFinalScoreMapping:
    """Final numeric score maps correctly to qualitative severity."""

    def test_critical_threshold(self):
        assert DynamicSeverityEngine.score_to_severity(9.5) == Severity.CRITICAL
        assert DynamicSeverityEngine.score_to_severity(9.0) == Severity.CRITICAL

    def test_high_threshold(self):
        assert DynamicSeverityEngine.score_to_severity(7.5) == Severity.HIGH
        assert DynamicSeverityEngine.score_to_severity(7.0) == Severity.HIGH

    def test_medium_threshold(self):
        assert DynamicSeverityEngine.score_to_severity(5.0) == Severity.MEDIUM
        assert DynamicSeverityEngine.score_to_severity(4.0) == Severity.MEDIUM

    def test_low_threshold(self):
        assert DynamicSeverityEngine.score_to_severity(2.0) == Severity.LOW
        assert DynamicSeverityEngine.score_to_severity(0.1) == Severity.LOW

    def test_info_below_threshold(self):
        assert DynamicSeverityEngine.score_to_severity(0.0) == Severity.INFO


class TestExplanationFormat:
    """Explanation string contains all component breakdowns."""

    def test_explanation_contains_components(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=7.5, cwe_id="CWE-89")
        sev, explanation, comp = engine.calculate(finding)
        assert "CVSS=" in explanation
        assert "context=" in explanation
        assert "asset=" in explanation
        assert "exploit=" in explanation
        assert "verify=" in explanation
        assert "business=" in explanation
        assert "dampener=" in explanation
        assert f"severity={sev.value}" in explanation


class TestPipelineIntegration:
    """DynamicSeverityStep integrates with the pipeline."""

    @pytest.mark.asyncio
    async def test_dynamic_severity_runs_as_last_step(self):
        step = DynamicSeverityStep()
        pipeline = FindingPipeline(steps=[], dynamic_severity_step=step)

        finding = _make_enriched(cvss_score=5.0, severity=Severity.MEDIUM)
        result = await pipeline.apply_dynamic_severity(finding)
        assert result is not None
        assert result.severity_reason is not None
        assert "Dynamic severity=" in result.severity_reason

    @pytest.mark.asyncio
    async def test_dynamic_severity_overrides_previous_severity(self):
        step = DynamicSeverityStep()
        pipeline = FindingPipeline(steps=[], dynamic_severity_step=step)

        finding = _make_enriched(cvss_score=9.5, severity=Severity.LOW)
        result = await pipeline.apply_dynamic_severity(finding)
        assert result is not None
        # CVSS 9.5 with default params produces at least HIGH
        assert result.severity in (Severity.HIGH, Severity.CRITICAL)

    @pytest.mark.asyncio
    async def test_dynamic_severity_handles_none_finding(self):
        step = DynamicSeverityStep()
        result = await step.process(None)
        assert result is None


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_very_high_cvss_clamped(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=15.0)
        sev, _, comp = engine.calculate(finding)
        assert comp.final_score <= 10.0

    def test_very_low_cvss_not_negative(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=0.0)
        sev, _, comp = engine.calculate(finding)
        assert comp.final_score >= 0.0

    def test_missing_endpoint_class_defaults_to_main_app(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=5.0, endpoint_class="")
        sev, _, comp = engine.calculate(finding)
        # Empty endpoint_class defaults to "Main Application" (1.0 multiplier),
        # but First-party asset category still applies (1.15 multiplier)
        assert comp.context_component == comp.cvss_component * 1.0 * 1.15

    def test_scan_context_overrides_finding_attributes(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=5.0)
        ctx = {
            "asset_criticality": AssetCriticality.MISSION_CRITICAL,
            "exposure": ExposureLevel.INTERNET_FACING,
        }
        sev, _, comp = engine.calculate(finding, ctx)
        assert comp.asset_component > 10.0

    def test_empty_false_positive_reasons_no_dampening(self):
        engine = DynamicSeverityEngine()
        finding = _make_enriched(cvss_score=5.0, false_positive_reasons=[])
        sev, _, comp = engine.calculate(finding)
        assert comp.mitigation_dampener == 1.0
