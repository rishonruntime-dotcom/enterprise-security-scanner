"""Tests for the Enterprise Risk Intelligence and Weighted Scoring Engine."""
import pytest
from typing import Optional
from unittest.mock import MagicMock

from scanner.models.finding import (
    Finding, Evidence, Severity, Confidence, VerificationStatus, DetectionMethod
)
from scanner.risk.models import (
    AssetCriticality, ExposureLevel, RiskScore, CVSSScore, EPSSScore, BusinessRisk
)
from scanner.risk.intelligence_models import (
    RiskIntelligence, ExploitIntelligence, MitigationIntelligence,
    EnvironmentIntelligence, SecurityMaturityIntelligence, BusinessIntelligence,
    CSPQuality, HSTSStatus, TrustedTypesStatus, SecurityMaturityLevel,
)
from scanner.risk.intelligence_collector import RiskIntelligenceCollector
from scanner.risk.weighted_engine import WeightedRiskEngine
from scanner.risk.engine import RiskEngine
from scanner.correlation.models import EnrichedFinding, VulnerabilityIntelligence
from scanner.correlation.risk_step import RiskCalculationStep


def _make_finding(
    plugin_id: str = "ACT-SQLI-001",
    title: str = "SQL Injection",
    severity: Severity = Severity.HIGH,
    cwe_id: str = "CWE-89",
    cvss_score: float = 8.5,
    verification_status: VerificationStatus = VerificationStatus.VERIFIED,
    confidence_score: float = 0.9,
    epss_score: Optional[float] = None,
    kev_status: Optional[bool] = None,
) -> Finding:
    return Finding(
        plugin_id=plugin_id,
        title=title,
        description="Test finding",
        severity=severity,
        confidence=Confidence.HIGH,
        endpoint="https://example.com/api",
        evidence=[
            Evidence(
                type="sqli_error",
                description="SQL error detected",
                data={"error": "SQL syntax error"},
                raw_request="GET /api?id=1 HTTP/1.1",
                raw_response="500 SQL syntax error",
                response_headers={"Content-Type": "application/json"},
                timing_ms=120.0,
                baseline_timing_ms=80.0,
                reproduction_steps=["1. GET /api?id=1"],
            )
        ],
        verification_status=verification_status,
        confidence_score=confidence_score,
        cwe_id=cwe_id,
        cvss_score=cvss_score,
        epss_score=epss_score,
        kev_status=kev_status,
        detection_method=DetectionMethod.ACTIVE,
    )


def _make_enriched_finding(**kwargs) -> EnrichedFinding:
    finding = _make_finding(**kwargs)
    return EnrichedFinding(**finding.model_dump())


class TestRiskIntelligenceModels:
    """Test RiskIntelligence model and weighted calculation."""

    def test_mitigation_score_calculation_absent(self):
        mit = MitigationIntelligence()
        score = mit.calculate_score()
        assert score == 0.0

    def test_mitigation_score_calculation_strong(self):
        mit = MitigationIntelligence(
            csp_quality=CSPQuality.STRONG,
            csp_strict_dynamic=True,
            csp_nonce=True,
            hsts_status=HSTSStatus.PRELOAD,
            hsts_max_age=31536000,
            hsts_include_subdomains=True,
            trusted_types=TrustedTypesStatus.ENFORCED,
            x_frame_options=True,
            x_content_type_options=True,
            referrer_policy=True,
            permissions_policy=True,
        )
        score = mit.calculate_score()
        assert score > 0.8

    def test_environment_score_calculation(self):
        env = EnvironmentIntelligence(
            asset_criticality="MissionCritical",
            exposure="InternetFacing",
            endpoint_count=200,
            parameterized_endpoints=100,
            api_endpoints=50,
            admin_endpoints=10,
            authenticated_endpoints=30,
            technology_count=25,
            framework_count=5,
        )
        metrics = env.calculate_metrics()
        assert metrics["attack_surface_score"] > 5.0
        assert metrics["criticality_multiplier"] == 1.6
        assert metrics["exposure_multiplier"] == 1.2

    def test_security_maturity_calculation(self):
        maturity = SecurityMaturityIntelligence(
            security_headers_present=7,
            security_headers_total=7,
            cookie_security_score=1.0,
            tls_configuration_score=1.0,
        )
        score = maturity.calculate_maturity()
        assert score > 0.8
        assert maturity.maturity_level == SecurityMaturityLevel.ADVANCED

    def test_business_impact_calculation(self):
        biz = BusinessIntelligence(
            data_sensitivity="Critical",
            compliance_requirements=["PCI DSS", "HIPAA", "GDPR"],
            user_base_size="Enterprise",
            revenue_impact="Critical",
        )
        score = biz.calculate_business_impact()
        assert score >= 8.0

    def test_exploit_intelligence_calculation(self):
        exploit = ExploitIntelligence(
            epss_probability=0.95,
            epss_percentile=0.99,
            is_kev=True,
            active_exploit_success=True,
            exploit_maturity="High",
        )
        score = exploit.calculate_exploitability()
        assert score >= 8.0

    def test_weighted_risk_differentiates_enterprise_vs_dev(self):
        """
        Test that enterprise sites score higher than dev sites for the same vulnerability.
        Enterprise: MissionCritical, InternetFacing, large attack surface, strong mitigations
        Dev: Low, Internal, small attack surface, weak mitigations
        """
        vuln_intel = VulnerabilityIntelligence(cwe_id="CWE-89", cvss_score=8.5)
        
        # Enterprise context
        enterprise_intel = RiskIntelligence(
            vulnerability_intelligence=vuln_intel,
            exploit_intelligence=ExploitIntelligence(
                epss_probability=0.95,
                is_kev=True,
                active_exploit_success=True,
                exploit_maturity="High",
            ),
            mitigation_intelligence=MitigationIntelligence(
                csp_quality=CSPQuality.STRONG,
                csp_strict_dynamic=True,
                hsts_status=HSTSStatus.PRELOAD,
                trusted_types=TrustedTypesStatus.ENFORCED,
                x_frame_options=True,
                x_content_type_options=True,
                referrer_policy=True,
                permissions_policy=True,
            ),
            environment_intelligence=EnvironmentIntelligence(
                asset_criticality="MissionCritical",
                exposure="InternetFacing",
                endpoint_count=500,
                parameterized_endpoints=200,
                api_endpoints=100,
                admin_endpoints=20,
                authenticated_endpoints=100,
                technology_count=30,
                framework_count=8,
            ),
            security_maturity_intelligence=SecurityMaturityIntelligence(
                security_headers_present=7,
                security_headers_total=7,
                cookie_security_score=1.0,
                tls_configuration_score=1.0,
            ),
            business_intelligence=BusinessIntelligence(
                data_sensitivity="Critical",
                compliance_requirements=["PCI DSS", "HIPAA", "GDPR"],
                user_base_size="Enterprise",
                revenue_impact="Critical",
            ),
        )
        
        # Dev site context
        dev_intel = RiskIntelligence(
            vulnerability_intelligence=vuln_intel,
            exploit_intelligence=ExploitIntelligence(
                epss_probability=0.95,
                is_kev=True,
                active_exploit_success=True,
                exploit_maturity="High",
            ),
            mitigation_intelligence=MitigationIntelligence(
                csp_quality=CSPQuality.ABSENT,
                hsts_status=HSTSStatus.ABSENT,
                trusted_types=TrustedTypesStatus.ABSENT,
            ),
            environment_intelligence=EnvironmentIntelligence(
                asset_criticality="Low",
                exposure="Internal",
                endpoint_count=10,
                parameterized_endpoints=2,
                api_endpoints=1,
                admin_endpoints=0,
                authenticated_endpoints=0,
                technology_count=3,
                framework_count=1,
            ),
            security_maturity_intelligence=SecurityMaturityIntelligence(
                security_headers_present=1,
                security_headers_total=7,
                cookie_security_score=0.0,
                tls_configuration_score=0.3,
            ),
            business_intelligence=BusinessIntelligence(
                data_sensitivity="Low",
                compliance_requirements=[],
                user_base_size="Small",
                revenue_impact="Low",
            ),
        )
        
        ent_score, _ = enterprise_intel.calculate_weighted_risk()
        dev_score, _ = dev_intel.calculate_weighted_risk()
        
        # Enterprise should score significantly higher
        assert ent_score > dev_score
        assert ent_score - dev_score >= 2.0, f"Enterprise ({ent_score}) should be at least 2 points higher than dev ({dev_score})"


class TestRiskIntelligenceCollector:
    """Test the risk intelligence collector."""

    def test_collector_aggregates_findings(self):
        collector = RiskIntelligenceCollector()
        f1 = _make_finding(cwe_id="CWE-89", cvss_score=8.5, epss_score=0.95, kev_status=True)
        f2 = _make_finding(cwe_id="CWE-79", cvss_score=6.5, epss_score=0.65, kev_status=False)
        collector.add_finding(f1)
        collector.add_finding(f2)
        
        intel = collector.collect()
        assert intel.exploit_intelligence.epss_probability == 0.95
        assert intel.exploit_intelligence.is_kev is True

    def test_collector_detects_csp(self):
        collector = RiskIntelligenceCollector()
        collector.add_header("content-security-policy", "default-src 'self'; script-src 'self' 'nonce-abc'")
        collector.add_header("strict-transport-security", "max-age=31536000; includeSubDomains; preload")
        
        intel = collector.collect()
        assert intel.mitigation_intelligence.csp_quality in [CSPQuality.MODERATE, CSPQuality.STRONG]
        assert intel.mitigation_intelligence.csp_nonce is True
        assert intel.mitigation_intelligence.hsts_status == HSTSStatus.PRELOAD

    def test_collector_detects_trusted_types(self):
        collector = RiskIntelligenceCollector()
        collector.add_header("content-security-policy", "require-trusted-types-for 'script'; trusted-types 'none'")
        
        intel = collector.collect()
        assert intel.mitigation_intelligence.trusted_types == TrustedTypesStatus.ENFORCED

    def test_collector_counts_endpoints(self):
        collector = RiskIntelligenceCollector()
        collector.add_endpoint({"path": "/api/users", "parameters": ["id", "name"], "class": "API"})
        collector.add_endpoint({"path": "/admin", "parameters": [], "class": "Admin"})
        collector.add_endpoint({"path": "/", "parameters": [], "class": "Main Application"})
        
        intel = collector.collect()
        assert intel.environment_intelligence.endpoint_count == 3
        assert intel.environment_intelligence.api_endpoints == 1
        assert intel.environment_intelligence.admin_endpoints == 1

    def test_collector_assesses_security_maturity(self):
        collector = RiskIntelligenceCollector()
        collector.add_header("strict-transport-security", "max-age=31536000")
        collector.add_header("x-frame-options", "DENY")
        collector.add_header("x-content-type-options", "nosniff")
        collector.add_header("referrer-policy", "strict-origin-when-cross-origin")
        
        intel = collector.collect()
        assert intel.security_maturity_intelligence.security_headers_present >= 3
        maturity_score = intel.security_maturity_intelligence.calculate_maturity()
        assert maturity_score > 0.3


class TestWeightedRiskEngine:
    """Test the weighted risk engine."""

    def setup_method(self):
        self.engine = WeightedRiskEngine()

    def test_assess_returns_risk_score(self):
        finding = _make_enriched_finding()
        intel = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-89", cvss_score=8.5),
        )
        risk = self.engine.assess(finding, intel)
        assert isinstance(risk, RiskScore)
        assert 0.0 <= risk.final_priority <= 10.0

    def test_assess_enterprise_scores_higher_than_dev(self):
        finding = _make_enriched_finding()
        
        enterprise_intel = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-89", cvss_score=8.5),
            environment_intelligence=EnvironmentIntelligence(
                asset_criticality="MissionCritical",
                exposure="InternetFacing",
                endpoint_count=500,
            ),
            business_intelligence=BusinessIntelligence(
                data_sensitivity="Critical",
                compliance_requirements=["PCI DSS"],
                user_base_size="Enterprise",
                revenue_impact="Critical",
            ),
        )
        
        dev_intel = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-89", cvss_score=8.5),
            environment_intelligence=EnvironmentIntelligence(
                asset_criticality="Low",
                exposure="Internal",
                endpoint_count=5,
            ),
            business_intelligence=BusinessIntelligence(
                data_sensitivity="Low",
                compliance_requirements=[],
                user_base_size="Small",
                revenue_impact="Low",
            ),
        )
        
        ent_risk = self.engine.assess(finding, enterprise_intel)
        dev_risk = self.engine.assess(finding, dev_intel)
        
        assert ent_risk.final_priority > dev_risk.final_priority
        assert ent_risk.component_scores["business_impact"] > dev_risk.component_scores["business_impact"]

    def test_assess_mitigations_reduce_risk(self):
        finding = _make_enriched_finding()
        
        no_mitigation = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-79", cvss_score=6.5),
            mitigation_intelligence=MitigationIntelligence(
                csp_quality=CSPQuality.ABSENT,
                hsts_status=HSTSStatus.ABSENT,
                trusted_types=TrustedTypesStatus.ABSENT,
            ),
        )
        
        strong_mitigation = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-79", cvss_score=6.5),
            mitigation_intelligence=MitigationIntelligence(
                csp_quality=CSPQuality.STRONG,
                csp_strict_dynamic=True,
                csp_nonce=True,
                hsts_status=HSTSStatus.PRELOAD,
                hsts_max_age=31536000,
                hsts_include_subdomains=True,
                trusted_types=TrustedTypesStatus.ENFORCED,
                x_frame_options=True,
                x_content_type_options=True,
                referrer_policy=True,
                permissions_policy=True,
            ),
        )
        
        no_mit_risk = self.engine.assess(finding, no_mitigation)
        strong_mit_risk = self.engine.assess(finding, strong_mitigation)
        
        assert no_mit_risk.final_priority > strong_mit_risk.final_priority

    def test_assess_kev_boosts_exploitability(self):
        finding = _make_enriched_finding()
        
        kev_intel = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-89", cvss_score=7.0),
            exploit_intelligence=ExploitIntelligence(
                epss_probability=0.9,
                is_kev=True,
                active_exploit_success=True,
                exploit_maturity="High",
            ),
        )
        
        no_kev_intel = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-89", cvss_score=7.0),
            exploit_intelligence=ExploitIntelligence(
                epss_probability=0.1,
                is_kev=False,
                active_exploit_success=False,
                exploit_maturity="Unknown",
            ),
        )
        
        kev_risk = self.engine.assess(finding, kev_intel)
        no_kev_risk = self.engine.assess(finding, no_kev_intel)
        
        assert kev_risk.final_priority > no_kev_risk.final_priority
        assert kev_risk.exploitability_score > no_kev_risk.exploitability_score

    def test_assess_evidence_quality_affects_score(self):
        finding_low = _make_enriched_finding(
            verification_status=VerificationStatus.NOT_ACTIVELY_VERIFIED,
            confidence_score=0.3,
        )
        finding_high = _make_enriched_finding(
            verification_status=VerificationStatus.VERIFIED,
            confidence_score=0.95,
        )
        
        intel = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-89", cvss_score=7.0),
        )
        
        low_risk = self.engine.assess(finding_low, intel)
        high_risk = self.engine.assess(finding_high, intel)
        
        assert high_risk.evidence_quality_score > low_risk.evidence_quality_score

    def test_component_scores_populated(self):
        finding = _make_enriched_finding()
        intel = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-89", cvss_score=8.5),
            environment_intelligence=EnvironmentIntelligence(
                asset_criticality="High",
                exposure="InternetFacing",
                endpoint_count=100,
            ),
        )
        
        risk = self.engine.assess(finding, intel)
        assert "vulnerability" in risk.component_scores
        assert "exploitability" in risk.component_scores
        assert "attack_surface" in risk.component_scores
        assert "mitigations" in risk.component_scores
        assert "maturity" in risk.component_scores
        assert "business_impact" in risk.component_scores


class TestRiskEngineIntegration:
    """Test RiskEngine integration with weighted scoring."""

    def test_risk_engine_assess_with_context(self):
        engine = RiskEngine(
            default_criticality="High",
            default_exposure="InternetFacing",
            target_context={
                "data_sensitivity": "High",
                "compliance_requirements": ["PCI DSS"],
            },
        )
        
        finding = _make_enriched_finding()
        risk = engine.assess(finding)
        
        assert isinstance(risk, RiskScore)
        assert risk.asset_criticality == AssetCriticality.HIGH
        assert risk.exposure == ExposureLevel.INTERNET_FACING

    def test_risk_engine_batch_assess(self):
        engine = RiskEngine()
        findings = [_make_enriched_finding(plugin_id=f"ACT-{i}-001") for i in range(3)]
        risks = engine.assess_batch(findings)
        
        assert len(risks) == 3
        assert all(isinstance(r, RiskScore) for r in risks)

    def test_risk_engine_with_intelligence_collector(self):
        engine = RiskEngine()
        
        finding = _make_enriched_finding()
        engine.add_finding(finding)
        engine.add_header("content-security-policy", "default-src 'self'")
        engine.add_header("strict-transport-security", "max-age=31536000; preload")
        engine.add_endpoint({"path": "/api", "parameters": ["id"], "class": "API"})
        
        risk = engine.assess(finding)
        assert risk.mitigation_score > 0.0
        assert risk.attack_surface_score > 0.0


class TestRiskCalculationStep:
    """Test the risk calculation pipeline step."""

    @pytest.mark.asyncio
    async def test_risk_step_with_new_engine(self):
        engine = RiskEngine(default_criticality=AssetCriticality.MISSION_CRITICAL)
        step = RiskCalculationStep(risk_engine=engine)
        
        f1 = _make_enriched_finding(
            plugin_id="ACT-XSS-001",
            cwe_id="CWE-79",
            cvss_score=6.5,
        )
        
        result = await step.process(f1)
        
        assert result is not None
        assert result.risk is not None
        assert result.risk.final_priority >= 0.0
        assert result.risk.final_priority <= 10.0
        assert result.vulnerability_score >= 0.0
        assert result.mitigation_score >= 0.0
        assert result.maturity_score >= 0.0

    @pytest.mark.asyncio
    async def test_risk_step_sets_component_scores(self):
        engine = RiskEngine()
        step = RiskCalculationStep(risk_engine=engine)
        
        f1 = _make_enriched_finding(cwe_id="CWE-89", cvss_score=8.5)
        result = await step.process(f1)
        
        assert result.vulnerability_score == 8.5
        assert "vulnerability" in result.risk.component_scores
        assert "exploitability" in result.risk.component_scores

    @pytest.mark.asyncio
    async def test_risk_step_none_returns_none(self):
        engine = RiskEngine()
        step = RiskCalculationStep(risk_engine=engine)
        
        result = await step.process(None)
        assert result is None


class TestArchitecturalDifferentiation:
    """Test that the new scoring differentiates site types properly."""

    def test_enterprise_vs_dev_score_difference(self):
        """
        Verify that enterprise sites score higher than dev sites for the same vulnerability.
        
        This addresses the core issue: YouTube ≈ 75, Facebook ≈ 75, Xanadu ≈ 78, Aufinja ≈ 78
        The new model should produce more spread-out scores.
        """
        engine = WeightedRiskEngine()
        
        # Same critical SQLi vulnerability for all sites
        vuln = VulnerabilityIntelligence(cwe_id="CWE-89", cvss_score=8.5)
        
        # YouTube-like: Mission critical, internet-facing, massive attack surface, strong mitigations
        youtube = RiskIntelligence(
            vulnerability_intelligence=vuln,
            exploit_intelligence=ExploitIntelligence(
                epss_probability=0.97,
                is_kev=True,
                active_exploit_success=True,
                exploit_maturity="High",
            ),
            mitigation_intelligence=MitigationIntelligence(
                csp_quality=CSPQuality.STRONG,
                csp_strict_dynamic=True,
                csp_nonce=True,
                hsts_status=HSTSStatus.PRELOAD,
                hsts_max_age=31536000,
                hsts_include_subdomains=True,
                trusted_types=TrustedTypesStatus.ENFORCED,
                x_frame_options=True,
                x_content_type_options=True,
                referrer_policy=True,
                permissions_policy=True,
            ),
            environment_intelligence=EnvironmentIntelligence(
                asset_criticality="MissionCritical",
                exposure="InternetFacing",
                endpoint_count=10000,
                parameterized_endpoints=5000,
                api_endpoints=2000,
                admin_endpoints=100,
                authenticated_endpoints=5000,
                technology_count=50,
                framework_count=10,
            ),
            security_maturity_intelligence=SecurityMaturityIntelligence(
                security_headers_present=7,
                security_headers_total=7,
                cookie_security_score=1.0,
                tls_configuration_score=1.0,
            ),
            business_intelligence=BusinessIntelligence(
                data_sensitivity="Critical",
                compliance_requirements=["PCI DSS", "HIPAA", "GDPR", "SOC 2"],
                user_base_size="Enterprise",
                revenue_impact="Critical",
            ),
        )
        
        # Dev site: Low criticality, internal, small surface, weak mitigations
        dev_site = RiskIntelligence(
            vulnerability_intelligence=vuln,
            exploit_intelligence=ExploitIntelligence(
                epss_probability=0.97,
                is_kev=True,
                active_exploit_success=True,
                exploit_maturity="High",
            ),
            mitigation_intelligence=MitigationIntelligence(
                csp_quality=CSPQuality.ABSENT,
                hsts_status=HSTSStatus.ABSENT,
                trusted_types=TrustedTypesStatus.ABSENT,
            ),
            environment_intelligence=EnvironmentIntelligence(
                asset_criticality="Low",
                exposure="Internal",
                endpoint_count=10,
                parameterized_endpoints=2,
                api_endpoints=1,
                admin_endpoints=0,
                authenticated_endpoints=0,
                technology_count=2,
                framework_count=1,
            ),
            security_maturity_intelligence=SecurityMaturityIntelligence(
                security_headers_present=1,
                security_headers_total=7,
                cookie_security_score=0.0,
                tls_configuration_score=0.3,
            ),
            business_intelligence=BusinessIntelligence(
                data_sensitivity="Low",
                compliance_requirements=[],
                user_base_size="Small",
                revenue_impact="Low",
            ),
        )
        
        finding = _make_enriched_finding()
        youtube_risk = engine.assess(finding, youtube)
        dev_risk = engine.assess(finding, dev_site)
        
        # YouTube should score significantly higher than dev site
        assert youtube_risk.final_priority > dev_risk.final_priority
        score_diff = youtube_risk.final_priority - dev_risk.final_priority
        assert score_diff >= 2.0, f"Score difference ({score_diff}) should be >= 2.0 for proper differentiation"
        
        # Component scores should also differ
        assert youtube_risk.business_impact_score > dev_risk.business_impact_score
        assert youtube_risk.attack_surface_score > dev_risk.attack_surface_score

    def test_mitigations_differentiate_secure_vs_insecure(self):
        """
        Test that strong mitigations (CSP, HSTS, Trusted Types) reduce risk significantly.
        """
        engine = WeightedRiskEngine()
        finding = _make_enriched_finding(cwe_id="CWE-79", cvss_score=6.5)
        
        # Insecure: No CSP, no HSTS, no Trusted Types
        insecure = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-79", cvss_score=6.5),
            mitigation_intelligence=MitigationIntelligence(
                csp_quality=CSPQuality.ABSENT,
                hsts_status=HSTSStatus.ABSENT,
                trusted_types=TrustedTypesStatus.ABSENT,
            ),
            environment_intelligence=EnvironmentIntelligence(
                asset_criticality="Medium",
                exposure="InternetFacing",
                endpoint_count=50,
            ),
        )
        
        # Secure: Strong CSP with strict-dynamic + nonce, HSTS preload, Trusted Types enforced
        secure = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-79", cvss_score=6.5),
            mitigation_intelligence=MitigationIntelligence(
                csp_quality=CSPQuality.STRONG,
                csp_strict_dynamic=True,
                csp_nonce=True,
                hsts_status=HSTSStatus.PRELOAD,
                hsts_max_age=31536000,
                trusted_types=TrustedTypesStatus.ENFORCED,
                x_frame_options=True,
                x_content_type_options=True,
            ),
            environment_intelligence=EnvironmentIntelligence(
                asset_criticality="Medium",
                exposure="InternetFacing",
                endpoint_count=50,
            ),
        )
        
        insecure_risk = engine.assess(finding, insecure)
        secure_risk = engine.assess(finding, secure)
        
        assert insecure_risk.final_priority > secure_risk.final_priority
        diff = insecure_risk.final_priority - secure_risk.final_priority
        assert diff >= 0.5, f"Mitigation difference ({diff}) should be >= 0.5"

    def test_maturity_differentiates_sites(self):
        """
        Test that security maturity reduces risk.
        """
        engine = WeightedRiskEngine()
        finding = _make_enriched_finding(cwe_id="CWE-614", cvss_score=4.0)
        
        immature = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-614", cvss_score=4.0),
            security_maturity_intelligence=SecurityMaturityIntelligence(
                security_headers_present=0,
                security_headers_total=7,
                cookie_security_score=0.0,
                tls_configuration_score=0.0,
            ),
        )
        
        mature = RiskIntelligence(
            vulnerability_intelligence=VulnerabilityIntelligence(cwe_id="CWE-614", cvss_score=4.0),
            security_maturity_intelligence=SecurityMaturityIntelligence(
                security_headers_present=7,
                security_headers_total=7,
                cookie_security_score=1.0,
                tls_configuration_score=1.0,
            ),
        )
        
        immature_risk = engine.assess(finding, immature)
        mature_risk = engine.assess(finding, mature)
        
        assert immature_risk.final_priority > mature_risk.final_priority