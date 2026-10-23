"""
Enterprise Weighted Risk Engine.

Computes risk scores using a weighted multi-factor model that considers:
- Vulnerability severity (CVSS-based): 35%
- Exploitability (EPSS + KEV + active success): 25%
- Environment/Attack Surface: 20%
- Security Maturity (risk reduction): 10%
- Business Impact: 10%

This produces more differentiated scores than simple finding-count models.
"""
from typing import Any, Dict, Optional, Tuple
import structlog

from .intelligence_models import RiskIntelligence
from .models import RiskScore, AssetCriticality, ExposureLevel, CVSSScore, EPSSScore, BusinessRisk, RiskBreakdown

logger = structlog.get_logger(__name__)


class WeightedRiskEngine:
    """
    Computes enterprise risk scores using weighted risk intelligence.
    
    Unlike simple finding-count models, this engine considers:
    1. Vulnerability characteristics (CVSS, CWE)
    2. Exploitability (EPSS, KEV, active success)
    3. Target environment (attack surface, exposure, criticality)
    4. Security posture (mitigations, maturity)
    5. Business context (data sensitivity, compliance, revenue)
    """

    def __init__(
        self,
        default_criticality: str = "Medium",
        default_exposure: str = "InternetFacing",
    ):
        self.default_criticality = default_criticality
        self.default_exposure = default_exposure

    def assess(
        self,
        finding: Any,
        risk_intelligence: RiskIntelligence,
        asset_criticality: Optional[AssetCriticality] = None,
        exposure: Optional[ExposureLevel] = None,
    ) -> RiskScore:
        """
        Assess risk for a finding using weighted intelligence.
        
        Args:
            finding: The enriched finding
            risk_intelligence: Comprehensive risk intelligence profile
            asset_criticality: Optional asset criticality override
            exposure: Optional exposure level override
        """
        # Calculate weighted risk score
        final_score, explanation = risk_intelligence.calculate_weighted_risk()
        
        # Override vulnerability score from finding if available
        finding_cvss = getattr(finding, "cvss_score", None)
        if finding_cvss is not None and finding_cvss > 0:
            risk_intelligence.vulnerability_score = finding_cvss
        
        # Map criticality
        crit = asset_criticality or self._map_criticality(self.default_criticality)
        exp = exposure or self._map_exposure(self.default_exposure)
        
        # Build CVSS score
        cvss = self._build_cvss_score(finding, risk_intelligence)
        
        # Build EPSS score
        epss = self._build_epss_score(risk_intelligence)
        
        # Build business risk
        business_risk = self._build_business_risk(risk_intelligence, crit, exp)

        # Build per-finding risk breakdown
        risk_breakdown = self._build_risk_breakdown(
            finding, risk_intelligence, crit, final_score, explanation
        )

        return RiskScore(
            cvss=cvss,
            epss=epss,
            is_kev=risk_intelligence.exploit_intelligence.is_kev,
            is_kev_authoritative=True,
            asset_criticality=crit,
            exposure=exp,
            business_risk=business_risk,
            evidence_quality_score=self._compute_evidence_quality(finding),
            final_priority=final_score,
            risk_explanation=explanation,
            vulnerability_score=risk_intelligence.vulnerability_score,
            exploitability_score=risk_intelligence.exploit_intelligence.exploitability_score,
            attack_surface_score=risk_intelligence.environment_intelligence.attack_surface_score,
            mitigation_score=risk_intelligence.mitigation_intelligence.mitigation_score,
            maturity_score=risk_intelligence.security_maturity_intelligence.maturity_score,
            business_impact_score=risk_intelligence.business_intelligence.business_impact_score,
            component_scores=risk_intelligence.component_scores,
            risk_breakdown=risk_breakdown,
        )

    def _map_criticality(self, value: str) -> AssetCriticality:
        """Map string to AssetCriticality enum."""
        mapping = {
            "low": AssetCriticality.LOW,
            "medium": AssetCriticality.MEDIUM,
            "high": AssetCriticality.HIGH,
            "missioncritical": AssetCriticality.MISSION_CRITICAL,
            "mission_critical": AssetCriticality.MISSION_CRITICAL,
        }
        return mapping.get(value.lower().strip(), AssetCriticality.MEDIUM)

    def _map_exposure(self, value: str) -> ExposureLevel:
        """Map string to ExposureLevel enum."""
        mapping = {
            "internal": ExposureLevel.INTERNAL,
            "external": ExposureLevel.EXTERNAL,
            "internetfacing": ExposureLevel.INTERNET_FACING,
            "internet_facing": ExposureLevel.INTERNET_FACING,
        }
        return mapping.get(value.lower().strip(), ExposureLevel.INTERNET_FACING)

    def _build_cvss_score(self, finding: Any, risk_intel: RiskIntelligence) -> CVSSScore:
        """Build CVSS score from finding and intelligence."""
        cvss_score = getattr(finding, "cvss_score", None) or 0.0
        cvss_vector = getattr(finding, "cvss_vector", None) or ""
        
        if risk_intel.vulnerability_intelligence:
            if hasattr(risk_intel.vulnerability_intelligence, "cvss"):
                cvss_obj = risk_intel.vulnerability_intelligence.cvss
                if cvss_obj and cvss_obj.base_score:
                    cvss_score = cvss_obj.base_score
                    cvss_vector = cvss_obj.vector or cvss_vector
        
        return CVSSScore(
            base_score=cvss_score,
            vector=cvss_vector,
        )

    def _build_epss_score(self, risk_intel: RiskIntelligence) -> EPSSScore:
        """Build EPSS score from intelligence."""
        exp_intel = risk_intel.exploit_intelligence
        return EPSSScore(
            probability=exp_intel.epss_probability or 0.0,
            percentile=exp_intel.epss_percentile or 0.0,
            is_authoritative=exp_intel.epss_probability is not None,
            cwe_based=True,
        )

    def _build_business_risk(
        self,
        risk_intel: RiskIntelligence,
        criticality: AssetCriticality,
        exposure: ExposureLevel,
    ) -> BusinessRisk:
        """Build business risk from intelligence."""
        biz_intel = risk_intel.business_intelligence
        profile = self._get_cwe_business_profile(getattr(risk_intel.vulnerability_intelligence, "cwe_id", None))
        
        crit_mult = self._criticality_multiplier(criticality)
        exp_mult = self._exposure_multiplier(exposure)
        combined = crit_mult * exp_mult
        
        data_risk = min(profile["data"] * combined, 10.0)
        compliance_risk = min(profile["compliance"] * combined, 10.0)
        reputation_risk = min(profile["reputation"] * combined, 10.0)
        ops_risk = min(profile["ops"] * combined, 10.0)
        
        overall = round(
            (data_risk * 0.35 + compliance_risk * 0.25 + reputation_risk * 0.25 + ops_risk * 0.15),
            1
        )
        
        return BusinessRisk(
            data_exposure_risk=round(data_risk, 1),
            compliance_risk=round(compliance_risk, 1),
            reputational_risk=round(reputation_risk, 1),
            operational_risk=round(ops_risk, 1),
            overall_business_risk=overall,
            risk_explanation=(
                f"Business risk for {criticality.value}/{exposure.value}: "
                f"data={data_risk:.1f}, compliance={compliance_risk:.1f}, "
                f"reputation={reputation_risk:.1f}, ops={ops_risk:.1f}"
            ),
        )

    def _get_cwe_business_profile(self, cwe_id: Optional[str]) -> Dict[str, float]:
        """Get business risk profile for CWE."""
        profiles = {
            "CWE-89": {"data": 9.5, "compliance": 9.0, "reputation": 8.0, "ops": 7.0},
            "CWE-79": {"data": 7.0, "compliance": 7.5, "reputation": 8.5, "ops": 5.0},
            "CWE-78": {"data": 9.5, "compliance": 9.5, "reputation": 9.0, "ops": 9.5},
            "CWE-22": {"data": 8.5, "compliance": 8.0, "reputation": 7.0, "ops": 6.0},
            "CWE-918": {"data": 9.0, "compliance": 8.5, "reputation": 8.0, "ops": 8.0},
            "CWE-611": {"data": 8.5, "compliance": 8.0, "reputation": 7.5, "ops": 6.5},
            "CWE-1336": {"data": 9.5, "compliance": 9.5, "reputation": 9.0, "ops": 9.5},
            "CWE-614": {"data": 6.0, "compliance": 7.0, "reputation": 5.0, "ops": 4.0},
            "CWE-693": {"data": 5.0, "compliance": 6.0, "reputation": 4.0, "ops": 3.0},
            "CWE-200": {"data": 7.0, "compliance": 7.5, "reputation": 6.0, "ops": 4.0},
            "CWE-937": {"data": 6.5, "compliance": 7.0, "reputation": 6.0, "ops": 5.0},
            "CWE-319": {"data": 8.0, "compliance": 8.5, "reputation": 7.0, "ops": 5.0},
        }
        return profiles.get(cwe_id or "", {"data": 5.0, "compliance": 5.0, "reputation": 5.0, "ops": 5.0})

    def _criticality_multiplier(self, criticality: AssetCriticality) -> float:
        """Get asset criticality multiplier."""
        return {
            AssetCriticality.LOW: 0.8,
            AssetCriticality.MEDIUM: 1.0,
            AssetCriticality.HIGH: 1.3,
            AssetCriticality.MISSION_CRITICAL: 1.6,
        }.get(criticality, 1.0)

    def _exposure_multiplier(self, exposure: ExposureLevel) -> float:
        """Get exposure multiplier."""
        return {
            ExposureLevel.INTERNAL: 0.8,
            ExposureLevel.EXTERNAL: 1.0,
            ExposureLevel.INTERNET_FACING: 1.2,
        }.get(exposure, 1.0)

    def _compute_evidence_quality(self, finding: Any) -> float:
        """Compute evidence quality score 0.0-1.0 with natural variation."""
        from ..models.finding import VerificationStatus

        score = 0.0

        # Verification status (30%)
        status = getattr(finding, "verification_status", None)
        if status == VerificationStatus.VERIFIED:
            score += 0.30
        elif status == VerificationStatus.NOT_ACTIVELY_VERIFIED:
            score += 0.10

        # Confidence score (15%)
        confidence = getattr(finding, "confidence_score", 0.0) or 0.0
        score += min(confidence, 1.0) * 0.15

        # Evidence richness (25%)
        evidence = getattr(finding, "evidence", []) or []
        if evidence:
            score += 0.05
            ev = evidence[0]
            if getattr(ev, "raw_request", None):
                score += 0.03
            if getattr(ev, "raw_response", None):
                score += 0.03
            if getattr(ev, "diff", None):
                score += 0.04
            if getattr(ev, "reproduction_steps", None):
                score += 0.04
            if getattr(ev, "timing_ms", None) is not None and getattr(ev, "baseline_timing_ms", None) is not None:
                score += 0.03
            # Bonus for multiple evidence items from different sources
            if len(evidence) >= 2:
                score += 0.03
            if len(evidence) >= 4:
                score += 0.02

        # Number of endpoints affected (5%)
        affected_eps = getattr(finding, "affected_endpoints", []) or []
        if len(affected_eps) >= 1:
            score += 0.02
        if len(affected_eps) >= 3:
            score += 0.02

        # Detection reliability based on detection method (10%)
        det_method = getattr(finding, "detection_method", None)
        if det_method:
            det_value = det_method.value if hasattr(det_method, "value") else str(det_method)
            if det_value in ("active", "fingerprinting"):
                score += 0.05
            elif det_value in ("passive", "network_banner"):
                score += 0.03

        # False positive probability adjustment (5%)
        fp_prob = getattr(finding, "false_positive_probability", 0.0) or 0.0
        score += (1.0 - min(fp_prob, 1.0)) * 0.05

        return min(score, 1.0)

    def _build_risk_breakdown(
        self,
        finding: Any,
        risk_intelligence: RiskIntelligence,
        criticality: AssetCriticality,
        final_score: float,
        explanation: str,
    ) -> RiskBreakdown:
        """Build a per-finding risk breakdown: Likelihood, Impact, Exploitability, Confidence, Risk."""

        from ..models.finding import VerificationStatus, Confidence as ConfidenceEnum

        vuln_score = risk_intelligence.vulnerability_score
        exploit_score = risk_intelligence.exploit_intelligence.exploitability_score
        evidence_quality = self._compute_evidence_quality(finding)

        # Impact: CVSS base score or finding severity mapped to 0-10
        cvss_score = getattr(finding, "cvss_score", None) or 0.0
        if cvss_score:
            impact = min(float(cvss_score), 10.0)
        else:
            from ..risk.severity_engine import DynamicSeverityEngine
            from ..models.finding import Severity
            finding_severity = getattr(finding, "severity", None) or Severity.MEDIUM
            impact = DynamicSeverityEngine._severity_to_score(finding_severity)

        # Exploitability: derived from EPSS, KEV, active verification, and attack complexity
        exp_intel = risk_intelligence.exploit_intelligence
        epss_prob = exp_intel.epss_probability or 0.0
        is_kev = exp_intel.is_kev
        active_success = exp_intel.active_exploit_success
        is_verified = getattr(finding, "verification_status", None) == VerificationStatus.VERIFIED

        exploitability = 0.0
        exploitability += min(epss_prob * 10.0, 10.0) * 0.40
        if is_kev is True:
            exploitability += 10.0 * 0.30
        elif is_kev is None:
            exploitability += 5.0 * 0.30
        if active_success is True:
            exploitability += 10.0 * 0.20
        elif is_verified:
            exploitability += 7.0 * 0.20
        elif active_success is False:
            exploitability += 3.0 * 0.20
        exploitability = min(exploitability, 10.0)

        # Likelihood: blends vulnerability severity, exploitability, and criticality
        crit_mult = self._criticality_multiplier(criticality)
        crit_factor = min(crit_mult, 1.5)
        likelihood = min(
            (vuln_score * 0.35 + exploitability * 0.45 + (10.0 * crit_factor * 0.20)),
            10.0,
        )

        # Confidence: scanner confidence (0.0-1.0) based on evidence quality and verification
        confidence_conf = getattr(finding, "confidence", None)
        conf_boost = 0.2 if is_verified else 0.0
        confidence = min(evidence_quality * 0.6 + conf_boost, 1.0)
        if confidence_conf == ConfidenceEnum.CERTAIN:
            confidence = min(confidence + 0.15, 1.0)
        elif confidence_conf == ConfidenceEnum.HIGH:
            confidence = min(confidence + 0.10, 1.0)

        breakdown_explanation = (
            f"Likelihood={likelihood:.1f} (vuln={vuln_score:.1f}, exploit={exploitability:.1f}, crit={criticality.value}). "
            f"Impact={impact:.1f} (CVSS={cvss_score}). "
            f"Exploitability={exploitability:.1f} (EPSS={epss_prob:.2f}, KEV={is_kev}, verified={is_verified}). "
            f"Confidence={confidence:.2f} (evidence_quality={evidence_quality:.2f}). "
            f"Risk={final_score:.1f}."
        )

        return RiskBreakdown(
            likelihood=round(likelihood, 1),
            impact=round(impact, 1),
            exploitability=round(exploitability, 1),
            confidence=round(confidence, 2),
            risk=round(final_score, 1),
            explanation=breakdown_explanation,
        )
