"""Tests for the False Positive Reduction Engine."""
import pytest
from unittest.mock import MagicMock

from scanner.models.finding import Finding, Evidence, Severity, Confidence, DetectionMethod, VerificationStatus
from scanner.correlation.models import EnrichedFinding, VulnerabilityIntelligence
from scanner.correlation.false_positive import (
    FalsePositiveReductionEngine,
    FalsePositiveReductionStep,
    FPRReason,
)
from scanner.correlation.pipeline import FindingPipeline


def _make_finding(
    plugin_id: str = "PASS-001",
    title: str = "Missing Security Header",
    severity: Severity = Severity.MEDIUM,
    endpoint: str = "https://example.com",
    asset_category: str = "First-party",
    raw_response: str = "",
    detection_method: DetectionMethod = DetectionMethod.PASSIVE,
    endpoint_class: str = "Main Application",
) -> EnrichedFinding:
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
        confidence=Confidence.HIGH,
        endpoint=endpoint,
        evidence=evidence,
        detection_method=detection_method,
        endpoint_class=endpoint_class,
        asset_category=asset_category,
    )
    return EnrichedFinding(**finding.model_dump())


class TestCDNException:
    """Layer 1: CDN / hosting provider exceptions."""

    def test_cdn_missing_header_downgraded(self):
        engine = FalsePositiveReductionEngine()
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            asset_category="CDN",
            endpoint="https://cdn.example.com/page",
        )
        result = engine.reduce(finding)
        assert result.action == "downgrade"
        assert result.final_severity == Severity.INFO
        assert result.reason == FPRReason.CDN_EXCEPTION
        assert "CDN-managed endpoint" in result.reasoning_chain[0]

    def test_first_party_not_affected_by_cdn_rule(self):
        engine = FalsePositiveReductionEngine()
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            asset_category="First-party",
        )
        result = engine.reduce(finding)
        assert result.reason != FPRReason.CDN_EXCEPTION
        assert result.final_severity == Severity.MEDIUM

    def test_active_findings_not_downgraded_by_cdn_rule(self):
        engine = FalsePositiveReductionEngine()
        finding = _make_finding(
            plugin_id="ACT-XSS-001",
            title="Reflected XSS",
            asset_category="CDN",
            detection_method=DetectionMethod.ACTIVE,
            severity=Severity.HIGH,
        )
        result = engine.reduce(finding)
        assert result.reason != FPRReason.CDN_EXCEPTION
        assert result.final_severity == Severity.HIGH


class TestReverseProxyException:
    """Layer 2: Reverse proxy / load balancer exceptions."""

    def test_proxy_present_missing_hsts_downgraded(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nX-Forwarded-For: 203.0.113.1\r\nX-Cache: HIT\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "downgrade"
        assert result.final_severity == Severity.INFO
        assert result.reason == FPRReason.REVERSE_PROXY_EXCEPTION
        assert "Reverse-proxy" in result.reasoning_chain[0]

    def test_no_proxy_headers_no_exception(self):
        engine = FalsePositiveReductionEngine()
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            raw_response="HTTP/1.1 200 OK\r\n\r\n",
        )
        result = engine.reduce(finding)
        assert result.reason != FPRReason.REVERSE_PROXY_EXCEPTION
        assert result.final_severity == Severity.MEDIUM

    def test_proxy_present_non_hsts_finding_kept(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nX-Forwarded-For: 203.0.113.1\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing Permissions-Policy Header",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.reason != FPRReason.REVERSE_PROXY_EXCEPTION
        assert result.final_severity == Severity.MEDIUM


class TestFrameworkException:
    """Layer 3: Framework / platform exceptions."""

    def test_django_path_with_xfo_header_dropped(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing X-Frame-Options Header",
            endpoint="https://example.com/admin/dashboard",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "drop"
        assert result.dropped is True
        assert result.reason == FPRReason.FRAMEWORK_EXCEPTION
        assert "Django" in result.reasoning_chain[0]

    def test_rails_path_with_content_type_options_dropped(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing X-Content-Type-Options Header",
            endpoint="https://example.com/assets/application.js",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "drop"
        assert result.dropped is True
        assert "Rails" in result.reasoning_chain[0]

    def test_unknown_framework_no_exception(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing X-Frame-Options Header",
            endpoint="https://example.com/custom/page",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.reason != FPRReason.FRAMEWORK_EXCEPTION
        assert result.dropped is False


class TestBrowserProtection:
    """Layer 4: Browser-native protection exceptions."""

    def test_cookie_finding_with_secure_httponly_downgraded(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc; Secure; HttpOnly\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-002",
            title="Cookie Missing Secure Flag",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "downgrade"
        assert result.final_severity == Severity.INFO
        assert result.reason == FPRReason.BROWSER_PROTECTION
        assert "Browser-native" in result.reasoning_chain[0]

    def test_xss_finding_with_csp_downgraded(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-006",
            title="CSP Policy Weakness: Insufficient Protection Against XSS",
            raw_response=raw_response,
            detection_method=DetectionMethod.PASSIVE,
        )
        result = engine.reduce(finding)
        assert result.action == "downgrade"
        assert result.final_severity == Severity.MEDIUM
        assert result.reason == FPRReason.BROWSER_PROTECTION
        assert "Content-Security-Policy" in result.reasoning_chain[0]

    def test_active_findings_not_affected_by_browser_cookie_rule(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc; Secure\r\n\r\n"
        finding = _make_finding(
            plugin_id="ACT-XSS-001",
            title="Reflected XSS",
            raw_response=raw_response,
            detection_method=DetectionMethod.ACTIVE,
            severity=Severity.HIGH,
        )
        result = engine.reduce(finding)
        assert result.reason != FPRReason.BROWSER_PROTECTION
        assert result.final_severity == Severity.HIGH


class TestSecureConfiguration:
    """Layer 5: Known secure configuration / framework defaults."""

    def test_hsts_preload_dropped(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "drop"
        assert result.dropped is True
        assert result.reason == FPRReason.SECURE_CONFIGURATION
        assert "known secure configuration" in result.reasoning_chain[0].lower()

    def test_csp_strict_dynamic_with_nonce_downgraded(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src 'self' 'nonce-abc' 'strict-dynamic'\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-006",
            title="CSP Policy Weakness: Insufficient Protection Against XSS",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "downgrade"
        assert result.final_severity == Severity.INFO
        assert result.reason == FPRReason.SECURE_CONFIGURATION
        assert any("strict-dynamic" in r for r in result.reasoning_chain)

    def test_permissions_policy_present_dropped(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nPermissions-Policy: geolocation=()\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing Permissions-Policy Header",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "drop"
        assert result.dropped is True
        assert result.reason == FPRReason.SECURE_CONFIGURATION

    def test_referrer_policy_present_dropped(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nReferrer-Policy: strict-origin-when-cross-origin\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing Referrer-Policy Header",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "drop"
        assert result.dropped is True
        assert result.reason == FPRReason.SECURE_CONFIGURATION

    def test_framework_default_x_frame_options_dropped(self):
        """Django/Rails default X-Frame-Options should drop the finding."""
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing X-Frame-Options Header",
            endpoint="https://example.com/admin/dashboard",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "drop"
        assert result.dropped is True
        assert "framework" in result.reasoning_chain[0].lower()

    def test_framework_default_xss_protection_dropped(self):
        """X-XSS-Protection header present should drop the finding."""
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nX-XSS-Protection: 1; mode=block\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing X-XSS-Protection Header",
            endpoint="https://example.com/assets/application.js",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "drop"
        assert result.dropped is True
        assert "x-xss-protection" in result.reasoning_chain[0].lower()


class TestMitigationsPresent:
    """Layer 5: Multiple security mitigations reduce severity."""

    def test_multiple_mitigations_downgrade_to_info(self):
        engine = FalsePositiveReductionEngine()
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
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            severity=Severity.MEDIUM,
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "downgrade"
        assert result.final_severity == Severity.INFO
        assert result.reason == FPRReason.MITIGATIONS_PRESENT
        assert "Multiple security mitigations" in result.reasoning_chain[0]

    def test_two_mitigations_reduce_confidence(self):
        engine = FalsePositiveReductionEngine()
        raw_response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Security-Policy: default-src 'self'\r\n"
            "X-Frame-Options: DENY\r\n"
            "\r\n"
        )
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            severity=Severity.LOW,
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "downgrade"
        assert result.final_severity == Severity.INFO
        assert result.reason == FPRReason.MITIGATIONS_PRESENT
        assert "Security mitigations present" in result.reasoning_chain[0]

    def test_single_mitigation_no_downgrade(self):
        engine = FalsePositiveReductionEngine()
        raw_response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Security-Policy: default-src 'self'\r\n"
            "\r\n"
        )
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            severity=Severity.MEDIUM,
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.action == "keep"
        assert result.final_severity == Severity.MEDIUM


class TestLowValueEndpoint:
    """Layer 6: Low-value endpoint calibration."""

    def test_static_asset_medium_finding_downgraded(self):
        engine = FalsePositiveReductionEngine()
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing X-Frame-Options Header",
            severity=Severity.MEDIUM,
            endpoint_class="Static Assets",
        )
        result = engine.reduce(finding)
        assert result.action == "downgrade"
        assert result.final_severity == Severity.INFO
        assert "static assets" in result.reasoning_chain[0].lower()

    def test_media_low_finding_downgraded(self):
        engine = FalsePositiveReductionEngine()
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing Content-Security-Policy Header",
            severity=Severity.LOW,
            endpoint_class="Media",
        )
        result = engine.reduce(finding)
        assert result.action == "downgrade"
        assert result.final_severity == Severity.INFO
        assert "media" in result.reasoning_chain[0].lower()

    def test_main_app_finding_not_downgraded(self):
        engine = FalsePositiveReductionEngine()
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing X-Frame-Options Header",
            severity=Severity.MEDIUM,
            endpoint_class="Main Application",
        )
        result = engine.reduce(finding)
        assert result.action == "keep"
        assert result.final_severity == Severity.MEDIUM


class TestReasoningChain:
    """Test that reasoning chains are properly built."""

    def test_multiple_layers_build_chain(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            severity=Severity.MEDIUM,
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert len(result.reasoning_chain) >= 1
        assert any("Reverse-proxy" in r for r in result.reasoning_chain)

    def test_no_exception_adds_default_reasoning(self):
        engine = FalsePositiveReductionEngine()
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            raw_response="HTTP/1.1 200 OK\r\n\r\n",
        )
        result = engine.reduce(finding)
        assert len(result.reasoning_chain) == 1
        assert "No false-positive exceptions detected" in result.reasoning_chain[0]


class TestPipelineIntegration:
    """Test that false-positive reduction runs as the last pipeline step."""

    @pytest.mark.asyncio
    async def test_finding_survives_pipeline_with_fp_reduction(self):
        step = FalsePositiveReductionStep()
        pipeline = FindingPipeline(steps=[], false_positive_step=step)

        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            severity=Severity.MEDIUM,
            raw_response="HTTP/1.1 200 OK\r\n\r\n",
        )
        result = await pipeline.apply_false_positive_reduction(finding)
        assert result is not None
        assert result.severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_finding_dropped_by_fp_reduction(self):
        step = FalsePositiveReductionStep()
        pipeline = FindingPipeline(steps=[], false_positive_step=step)

        raw_response = "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing X-Frame-Options Header",
            endpoint="https://example.com/admin/dashboard",
            raw_response=raw_response,
        )
        result = await pipeline.apply_false_positive_reduction(finding)
        assert result is None

    @pytest.mark.asyncio
    async def test_fp_reduction_is_last_step(self):
        """Verify that FP reduction runs after all other steps."""
        step = FalsePositiveReductionStep()
        pipeline = FindingPipeline(steps=[], false_positive_step=step)

        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing Permissions-Policy Header",
            severity=Severity.MEDIUM,
            raw_response="HTTP/1.1 200 OK\r\nPermissions-Policy: geolocation=()\r\n\r\n",
        )
        result = await pipeline.apply_false_positive_reduction(finding)
        assert result is None  # Should be dropped by secure config check


class TestConfidenceAdjustment:
    """Test that confidence is adjusted alongside severity."""

    def test_cdn_downgrade_adjusts_confidence(self):
        engine = FalsePositiveReductionEngine()
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            asset_category="CDN",
            severity=Severity.MEDIUM,
        )
        result = engine.reduce(finding)
        assert result.confidence_adjustment > 0
        assert result.final_severity == Severity.INFO

    def test_dropped_finding_has_zero_confidence_adjustment(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.dropped is True
        assert result.confidence_adjustment == 0.0


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_raw_response(self):
        engine = FalsePositiveReductionEngine()
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            raw_response="",
        )
        result = engine.reduce(finding)
        assert result is not None
        assert result.final_severity == Severity.MEDIUM

    def test_none_endpoint(self):
        engine = FalsePositiveReductionEngine()
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            endpoint="",
        )
        result = engine.reduce(finding)
        assert result is not None

    def test_critical_finding_not_dropped_lightly(self):
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n"
        finding = _make_finding(
            plugin_id="ACT-SQLI-001",
            title="SQL Injection in 'id'",
            severity=Severity.CRITICAL,
            raw_response=raw_response,
            detection_method=DetectionMethod.ACTIVE,
        )
        result = engine.reduce(finding)
        assert result.dropped is False
        assert result.final_severity == Severity.CRITICAL

    def test_missing_header_on_cdn_with_proxy_downgrades_once(self):
        """When multiple layers match, the final reason reflects the last matching layer."""
        engine = FalsePositiveReductionEngine()
        raw_response = "HTTP/1.1 200 OK\r\nX-Forwarded-For: 1.2.3.4\r\nX-Cache: HIT\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            asset_category="CDN",
            raw_response=raw_response,
        )
        result = engine.reduce(finding)
        assert result.reason == FPRReason.REVERSE_PROXY_EXCEPTION
        assert len(result.reasoning_chain) == 2


class TestPerFindingFalsePositiveProbability:
    """Test per-finding false-positive probability computation."""

    @pytest.mark.asyncio
    async def test_verified_active_finding_has_low_fp_probability(self):
        step = FalsePositiveReductionStep()
        finding = _make_finding(
            plugin_id="ACT-XSS-001",
            title="Verified Reflected XSS",
            severity=Severity.HIGH,
            endpoint="https://example.com/search",
            asset_category="First-party",
            raw_response="HTTP/1.1 200 OK\r\n\r\n",
            detection_method=DetectionMethod.ACTIVE,
        )
        finding.is_verified = True
        finding.verification_status = VerificationStatus.VERIFIED
        result = await step.process(finding)
        assert result is not None
        assert result.false_positive_probability < 0.3
        assert result.false_positive_probability >= 0.0

    @pytest.mark.asyncio
    async def test_passive_finding_has_higher_fp_probability(self):
        step = FalsePositiveReductionStep()
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            severity=Severity.MEDIUM,
            endpoint="https://example.com",
            detection_method=DetectionMethod.PASSIVE,
        )
        finding.confidence_score = 0.6
        result = await step.process(finding)
        assert result is not None
        assert result.false_positive_probability > 0.2
        assert result.false_positive_probability < 0.7

    @pytest.mark.asyncio
    async def test_downgraded_finding_has_higher_fp_probability(self):
        step = FalsePositiveReductionStep()
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            severity=Severity.MEDIUM,
            asset_category="CDN",
            endpoint="https://cdn.example.com",
            detection_method=DetectionMethod.PASSIVE,
        )
        finding.confidence_score = 0.6
        result = await step.process(finding)
        assert result is not None
        assert result.severity == Severity.INFO
        assert result.false_positive_probability > 0.4

    @pytest.mark.asyncio
    async def test_dropped_finding_has_unit_probability(self):
        step = FalsePositiveReductionStep()
        raw_response = "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n\r\n"
        finding = _make_finding(
            plugin_id="PASS-001",
            title="Missing HSTS Header",
            raw_response=raw_response,
        )
        result = await step.process(finding)
        assert result is None  # Dropped findings are not returned

    @pytest.mark.asyncio
    async def test_severity_consistency_between_evidence_and_finding(self):
        """Finding severity and evidence data severity should not conflict."""
        from scanner.correlation.central_evaluator import CentralFindingEvaluator, CentralEvaluationStep, RawEvidence
        from scanner.passive.models import PassiveObservation

        obs = PassiveObservation(
            plugin_id="PASS-001",
            observation_type="missing_header",
            title="Missing HSTS Header",
            description="HSTS not present",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            endpoint="https://example.com/login",
            evidence=[],
        )
        raw = CentralFindingEvaluator.from_passive_observation(obs)
        evaluator = CentralFindingEvaluator()
        step = CentralEvaluationStep(evaluator=evaluator)

        finding = await step.process(raw)
        assert finding is not None
        assert finding.original_severity == Severity.LOW

        # Evidence data should NOT contain a 'severity' key inside the observation
        for ev in finding.evidence:
            observation_data = ev.data.get("detection_evidence", {}).get("observation", {}) if isinstance(ev.data, dict) else {}
            assert "severity" not in observation_data

    @pytest.mark.asyncio
    async def test_high_confidence_verified_finding_has_low_fp_probability(self):
        step = FalsePositiveReductionStep()
        finding = _make_finding(
            plugin_id="ACT-SQLI-001",
            title="SQL Injection in 'id'",
            severity=Severity.CRITICAL,
            endpoint="https://example.com/id",
            detection_method=DetectionMethod.ACTIVE,
        )
        finding.is_verified = True
        finding.verification_status = VerificationStatus.VERIFIED
        finding.confidence_score = 1.0
        result = await step.process(finding)
        assert result is not None
        assert result.false_positive_probability < 0.1
