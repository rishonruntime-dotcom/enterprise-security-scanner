"""
Enterprise Risk Intelligence Models.

Captures comprehensive intelligence about the target environment,
security posture, mitigations, and business context for weighted risk scoring.
"""
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class SecurityMaturityLevel(str, Enum):
    """Overall security maturity of the target."""
    IMMATURE = "Immature"
    DEVELOPING = "Developing"
    MATURE = "Mature"
    ADVANCED = "Advanced"


class CSPQuality(str, Enum):
    """Content Security Policy quality assessment."""
    ABSENT = "Absent"
    WEAK = "Weak"
    MODERATE = "Moderate"
    STRONG = "Strong"


class HSTSStatus(str, Enum):
    """HTTP Strict Transport Security status."""
    ABSENT = "Absent"
    PRESENT = "Present"
    PRELOAD = "Preload"


class TrustedTypesStatus(str, Enum):
    """Trusted Types enforcement status."""
    ABSENT = "Absent"
    REPORT_ONLY = "ReportOnly"
    ENFORCED = "Enforced"


class MitigationIntelligence(BaseModel):
    """Security mitigations detected on the target."""
    csp_quality: CSPQuality = Field(default=CSPQuality.ABSENT, description="CSP strength assessment")
    csp_strict_dynamic: bool = Field(default=False, description="CSP strict-dynamic present")
    csp_nonce: bool = Field(default=False, description="CSP nonce/hash-based whitelisting")
    hsts_status: HSTSStatus = Field(default=HSTSStatus.ABSENT, description="HSTS configuration")
    hsts_max_age: Optional[int] = Field(None, description="HSTS max-age in seconds")
    hsts_include_subdomains: bool = Field(default=False, description="HSTS includeSubDomains")
    trusted_types: TrustedTypesStatus = Field(default=TrustedTypesStatus.ABSENT, description="Trusted Types status")
    x_frame_options: bool = Field(default=False, description="X-Frame-Options present")
    x_content_type_options: bool = Field(default=False, description="X-Content-Type-Options present")
    referrer_policy: bool = Field(default=False, description="Referrer-Policy present")
    permissions_policy: bool = Field(default=False, description="Permissions-Policy present")
    
    # Calculated mitigation effectiveness
    mitigation_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Overall mitigation effectiveness 0.0-1.0")
    
    def calculate_score(self) -> float:
        """Calculate overall mitigation effectiveness score."""
        score = 0.0
        
        # CSP (40% weight)
        csp_score = 0.0
        if self.csp_quality == CSPQuality.ABSENT:
            csp_score = 0.0
        elif self.csp_quality == CSPQuality.WEAK:
            csp_score = 0.25
        elif self.csp_quality == CSPQuality.MODERATE:
            csp_score = 0.5
            if self.csp_strict_dynamic:
                csp_score += 0.15
            if self.csp_nonce:
                csp_score += 0.1
        elif self.csp_quality == CSPQuality.STRONG:
            csp_score = 0.75
            if self.csp_strict_dynamic:
                csp_score += 0.15
            if self.csp_nonce:
                csp_score += 0.1
        score += min(csp_score, 1.0) * 0.40
        
        # HSTS (25% weight)
        hsts_score = 0.0
        if self.hsts_status == HSTSStatus.ABSENT:
            hsts_score = 0.0
        elif self.hsts_status == HSTSStatus.PRESENT:
            hsts_score = 0.5
            if self.hsts_max_age and self.hsts_max_age >= 31536000:
                hsts_score = 0.7
            if self.hsts_include_subdomains:
                hsts_score = 0.8
        elif self.hsts_status == HSTSStatus.PRELOAD:
            hsts_score = 1.0
        score += hsts_score * 0.25
        
        # Trusted Types (20% weight)
        tt_score = 0.0
        if self.trusted_types == TrustedTypesStatus.ENFORCED:
            tt_score = 1.0
        elif self.trusted_types == TrustedTypesStatus.REPORT_ONLY:
            tt_score = 0.5
        score += tt_score * 0.20
        
        # Other headers (15% weight)
        header_count = sum([
            self.x_frame_options,
            self.x_content_type_options,
            self.referrer_policy,
            self.permissions_policy,
        ])
        header_score = min(header_count / 4.0, 1.0)
        score += header_score * 0.15
        
        self.mitigation_score = min(score, 1.0)
        return self.mitigation_score


class EnvironmentIntelligence(BaseModel):
    """Target environment and attack surface characteristics."""
    asset_criticality: str = Field(default="Medium", description="Asset criticality level")
    exposure: str = Field(default="InternetFacing", description="Exposure level")
    
    # Attack surface metrics
    endpoint_count: int = Field(default=0, description="Total discovered endpoints")
    parameterized_endpoints: int = Field(default=0, description="Endpoints with parameters")
    api_endpoints: int = Field(default=0, description="API endpoints")
    admin_endpoints: int = Field(default=0, description="Administrative endpoints")
    authenticated_endpoints: int = Field(default=0, description="Endpoints requiring authentication")
    
    # Technology stack complexity
    technology_count: int = Field(default=0, description="Distinct technologies detected")
    framework_count: int = Field(default=0, description="Frameworks detected")
    
    # Calculated metrics
    attack_surface_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Attack surface complexity 0.0-10.0")
    exposure_multiplier: float = Field(default=1.0, description="Exposure-based multiplier")
    criticality_multiplier: float = Field(default=1.0, description="Criticality-based multiplier")
    
    def calculate_metrics(self) -> Dict[str, float]:
        """Calculate attack surface and exposure metrics."""
        # Exposure multiplier
        exp_map = {"Internal": 0.7, "External": 1.0, "InternetFacing": 1.2}
        self.exposure_multiplier = exp_map.get(self.exposure, 1.0)
        
        # Criticality multiplier
        crit_map = {"Low": 0.8, "Medium": 1.0, "High": 1.3, "MissionCritical": 1.6}
        self.criticality_multiplier = crit_map.get(self.asset_criticality, 1.0)
        
        # Attack surface score (0-10)
        surface = 0.0
        surface += min(self.endpoint_count / 100.0, 1.0) * 2.0
        surface += min(self.parameterized_endpoints / 50.0, 1.0) * 2.0
        surface += min(self.api_endpoints / 30.0, 1.0) * 2.0
        surface += min(self.admin_endpoints / 10.0, 1.0) * 2.0
        surface += min(self.authenticated_endpoints / 20.0, 1.0) * 1.0
        surface += min(self.technology_count / 20.0, 1.0) * 0.5
        surface += min(self.framework_count / 5.0, 1.0) * 0.5
        self.attack_surface_score = min(surface, 10.0)
        
        return {
            "attack_surface_score": self.attack_surface_score,
            "exposure_multiplier": self.exposure_multiplier,
            "criticality_multiplier": self.criticality_multiplier,
        }


class SecurityMaturityIntelligence(BaseModel):
    """Security maturity assessment based on configurations and practices."""
    maturity_level: SecurityMaturityLevel = Field(default=SecurityMaturityLevel.DEVELOPING)
    
    # Header presence
    security_headers_present: int = Field(default=0, description="Count of security headers present")
    security_headers_total: int = Field(default=0, description="Total security headers checked")
    
    # Configuration quality
    cookie_security_score: float = Field(default=0.0, ge=0.0, le=1.0)
    tls_configuration_score: float = Field(default=0.0, ge=0.0, le=1.0)
    
    # Calculated maturity
    maturity_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Security maturity 0.0-1.0")
    
    def calculate_maturity(self) -> float:
        """Calculate security maturity score."""
        score = 0.0
        
        # Header coverage (40%)
        if self.security_headers_total > 0:
            header_coverage = self.security_headers_present / self.security_headers_total
            score += header_coverage * 0.40
        
        # Cookie security (20%)
        score += self.cookie_security_score * 0.20
        
        # TLS configuration (20%)
        score += self.tls_configuration_score * 0.20
        
        # Maturity level bonus (20%)
        maturity_map = {
            SecurityMaturityLevel.IMMATURE: 0.1,
            SecurityMaturityLevel.DEVELOPING: 0.3,
            SecurityMaturityLevel.MATURE: 0.6,
            SecurityMaturityLevel.ADVANCED: 0.9,
        }
        score += maturity_map.get(self.maturity_level, 0.3) * 0.20
        
        self.maturity_score = min(score, 1.0)
        
        # Update maturity level based on score
        if self.maturity_score >= 0.8:
            self.maturity_level = SecurityMaturityLevel.ADVANCED
        elif self.maturity_score >= 0.6:
            self.maturity_level = SecurityMaturityLevel.MATURE
        elif self.maturity_score >= 0.3:
            self.maturity_level = SecurityMaturityLevel.DEVELOPING
        else:
            self.maturity_level = SecurityMaturityLevel.IMMATURE
            
        return self.maturity_score


class BusinessIntelligence(BaseModel):
    """Business context and impact assessment."""
    data_sensitivity: str = Field(default="Low", description="Data sensitivity level")
    compliance_requirements: List[str] = Field(default_factory=list, description="Applicable compliance frameworks")
    user_base_size: str = Field(default="Small", description="User base size category")
    revenue_impact: str = Field(default="Low", description="Revenue impact category")
    
    # Calculated business risk
    business_impact_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Business impact 0.0-10.0")
    
    def calculate_business_impact(self) -> float:
        """Calculate business impact score."""
        score = 0.0
        
        # Data sensitivity (40%)
        data_map = {"Low": 2.0, "Medium": 5.0, "High": 8.0, "Critical": 10.0}
        score += data_map.get(self.data_sensitivity, 5.0) * 0.40
        
        # Compliance burden (25%)
        compliance_map = {"Low": 2.0, "Medium": 5.0, "High": 8.0, "Critical": 10.0}
        compliance_level = "Low"
        if len(self.compliance_requirements) >= 3:
            compliance_level = "Critical"
        elif len(self.compliance_requirements) >= 2:
            compliance_level = "High"
        elif len(self.compliance_requirements) >= 1:
            compliance_level = "Medium"
        score += compliance_map.get(compliance_level, 5.0) * 0.25
        
        # User base (20%)
        user_map = {"Small": 2.0, "Medium": 5.0, "Large": 8.0, "Enterprise": 10.0}
        score += user_map.get(self.user_base_size, 5.0) * 0.20
        
        # Revenue impact (15%)
        revenue_map = {"Low": 2.0, "Medium": 5.0, "High": 8.0, "Critical": 10.0}
        score += revenue_map.get(self.revenue_impact, 5.0) * 0.15
        
        self.business_impact_score = min(score, 10.0)
        return self.business_impact_score


class ExploitIntelligence(BaseModel):
    """Exploitability and active threat intelligence."""
    epss_probability: Optional[float] = Field(None, ge=0.0, le=1.0, description="EPSS exploitation probability")
    epss_percentile: Optional[float] = Field(None, ge=0.0, le=1.0, description="EPSS percentile")
    is_kev: Optional[bool] = Field(None, description="In CISA KEV catalog")
    active_exploit_success: Optional[bool] = Field(None, description="Active exploit succeeded during scan")
    exploit_maturity: str = Field(default="Unknown", description="Exploit code maturity")
    
    # Calculated exploitability
    exploitability_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Exploitability 0.0-10.0")
    
    def calculate_exploitability(self) -> float:
        """Calculate exploitability score."""
        score = 0.0
        
        # EPSS probability (40%)
        epss = self.epss_probability or 0.0
        score += epss * 10.0 * 0.40
        
        # KEV status (25%)
        if self.is_kev is True:
            score += 10.0 * 0.25
        elif self.is_kev is None:
            score += 5.0 * 0.25
        
        # Active exploit success (20%)
        if self.active_exploit_success is True:
            score += 10.0 * 0.20
        elif self.active_exploit_success is False:
            score += 3.0 * 0.20
        
        # Exploit maturity (15%)
        maturity_map = {"High": 10.0, "Functional": 8.0, "ProofOfConcept": 5.0, "Unknown": 3.0}
        score += maturity_map.get(self.exploit_maturity, 3.0) * 0.15
        
        self.exploitability_score = min(score, 10.0)
        return self.exploitability_score


class RiskIntelligence(BaseModel):
    """Comprehensive risk intelligence for weighted scoring."""
    vulnerability_intelligence: Optional[Any] = Field(None, description="Vulnerability details (CWE, OWASP, CVSS)")
    exploit_intelligence: ExploitIntelligence = Field(default_factory=ExploitIntelligence)
    mitigation_intelligence: MitigationIntelligence = Field(default_factory=MitigationIntelligence)
    environment_intelligence: EnvironmentIntelligence = Field(default_factory=EnvironmentIntelligence)
    security_maturity_intelligence: SecurityMaturityIntelligence = Field(default_factory=SecurityMaturityIntelligence)
    business_intelligence: BusinessIntelligence = Field(default_factory=BusinessIntelligence)
    
    # Calculated weighted scores
    vulnerability_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Vulnerability severity score")
    final_risk_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Final weighted risk score 0-10")
    risk_explanation: str = Field(default="", description="Human-readable risk calculation explanation")
    
    # Component scores for transparency
    component_scores: Dict[str, float] = Field(default_factory=dict, description="Individual component scores")
    
    def calculate_weighted_risk(self) -> tuple[float, str]:
        """
        Calculate final weighted risk score from all intelligence components.
        
        Weights:
        - Vulnerability severity (CVSS-based): 35%
        - Exploitability (EPSS + KEV + active success): 25%
        - Environment/Attack Surface: 20%
        - Security Maturity (risk reduction): 10%
        - Business Impact: 10%
        """
        # Get base vulnerability score from CVSS
        cvss_score = 0.0
        if self.vulnerability_intelligence:
            cvss_score = getattr(self.vulnerability_intelligence, "cvss_score", None) or 0.0
        self.vulnerability_score = cvss_score
        
        # Calculate component scores
        exploit_score = self.exploit_intelligence.calculate_exploitability()
        mitigation_score = self.mitigation_intelligence.calculate_score()
        maturity_score = self.security_maturity_intelligence.calculate_maturity()
        business_score = self.business_intelligence.calculate_business_impact()
        env_metrics = self.environment_intelligence.calculate_metrics()
        attack_surface = env_metrics["attack_surface_score"]
        
        # Store component scores
        self.component_scores = {
            "vulnerability": round(cvss_score, 2),
            "exploitability": round(exploit_score, 2),
            "attack_surface": round(attack_surface, 2),
            "mitigations": round(mitigation_score * 10.0, 2),
            "maturity": round(maturity_score * 10.0, 2),
            "business_impact": round(business_score, 2),
        }
        
        # Weighted calculation
        # Vulnerability: 35%
        vuln_component = cvss_score * 0.35
        
        # Exploitability: 25%
        exploit_component = exploit_score * 0.25
        
        # Environment/Attack Surface: 20%
        env_component = attack_surface * 0.20
        
        # Mitigations: 10% (risk reduction - higher mitigation = lower risk)
        mitigation_component = (1.0 - mitigation_score) * 10.0 * 0.10
        
        # Security Maturity: 10% (risk reduction)
        maturity_component = (1.0 - maturity_score) * 10.0 * 0.10
        
        # Business Impact: 10% (direct risk)
        business_component = business_score * 0.10
        
        # Apply exposure and criticality multipliers to environment component
        env_multiplier = env_metrics["exposure_multiplier"] * env_metrics["criticality_multiplier"]
        env_component *= env_multiplier
        
        # Calculate final score
        raw_score = (
            vuln_component
            + exploit_component
            + env_component
            + mitigation_component
            + maturity_component
            + business_component
        )
        
        self.final_risk_score = round(min(max(raw_score, 0.0), 10.0), 1)
        
        # Build explanation
        self.risk_explanation = (
            f"Weighted risk calculation: "
            f"Vulnerability={cvss_score:.1f}x0.35={vuln_component:.2f}, "
            f"Exploitability={exploit_score:.1f}x0.25={exploit_component:.2f}, "
            f"Environment={attack_surface:.1f}x0.15x{env_multiplier:.2f}={env_component:.2f}, "
            f"Mitigations={mitigation_score:.2f}->{mitigation_component:.2f}, "
            f"Maturity={maturity_score:.2f}->{maturity_component:.2f}, "
            f"Business={business_score:.1f}x0.10={business_component:.2f} "
            f"-> Final={self.final_risk_score}"
        )
        
        return self.final_risk_score, self.risk_explanation
