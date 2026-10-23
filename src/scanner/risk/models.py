"""
Enterprise Risk Models.

Full CVSS v3.1 base, temporal, and environmental scoring.
Dynamic risk with CIA impact, exposure, attack complexity, business criticality.
Weighted risk intelligence for differentiated scoring.
"""
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class AssetCriticality(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    MISSION_CRITICAL = "MissionCritical"


class ExposureLevel(str, Enum):
    INTERNAL = "Internal"
    EXTERNAL = "External"
    INTERNET_FACING = "InternetFacing"


class CVSSScore(BaseModel):
    """Full CVSS v3.1 score breakdown."""
    base_score: float = Field(default=0.0)
    temporal_score: Optional[float] = Field(default=None)
    environmental_score: Optional[float] = Field(default=None)
    vector: str = Field(default="")

    # CVSS metric breakdowns
    exploitability_score: Optional[float] = Field(default=None)
    impact_score: Optional[float] = Field(default=None)

    # Individual metric values
    attack_vector: Optional[str] = Field(default=None)
    attack_complexity: Optional[str] = Field(default=None)
    privileges_required: Optional[str] = Field(default=None)
    user_interaction: Optional[str] = Field(default=None)
    scope: Optional[str] = Field(default=None)
    confidentiality_impact: Optional[str] = Field(default=None)
    integrity_impact: Optional[str] = Field(default=None)
    availability_impact: Optional[str] = Field(default=None)


class EPSSScore(BaseModel):
    """Exploit Prediction Scoring System score."""
    probability: Optional[float] = Field(default=None, description="Probability of exploitation in next 30 days (0.0-1.0)")
    percentile: Optional[float] = Field(default=None, description="Percentile rank vs all CVEs (0.0-1.0)")
    is_authoritative: bool = Field(default=False, description="True if sourced from live EPSS API")
    cwe_based: bool = Field(default=False, description="True if estimated from CWE class statistics")


class BusinessRisk(BaseModel):
    """Business risk assessment beyond technical CVSS."""
    data_exposure_risk: float = Field(default=0.0, ge=0.0, le=10.0)
    compliance_risk: float = Field(default=0.0, ge=0.0, le=10.0)
    reputational_risk: float = Field(default=0.0, ge=0.0, le=10.0)
    operational_risk: float = Field(default=0.0, ge=0.0, le=10.0)
    overall_business_risk: float = Field(default=0.0, ge=0.0, le=10.0)
    risk_explanation: str = Field(default="")


class RiskBreakdown(BaseModel):
    """Per-finding risk score decomposition for analyst transparency."""
    likelihood: float = Field(default=0.0, ge=0.0, le=10.0, description="Probability of exploitation — blends CVSS exploitability, EPSS, and KEV")
    impact: float = Field(default=0.0, ge=0.0, le=10.0, description="Potential impact — derived from CVSS impact (CIA) or finding severity")
    exploitability: float = Field(default=0.0, ge=0.0, le=10.0, description="Ease of exploitation — EPSS, KEV, active verification, attack complexity")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Scanner confidence in the finding (0.0-1.0)")
    risk: float = Field(default=0.0, ge=0.0, le=10.0, description="Overall weighted risk score (0-10)")
    explanation: str = Field(default="", description="Human-readable explanation of each component")


class RiskScore(BaseModel):
    """Final computed risk for a finding — full enterprise weighted model."""
    cvss: CVSSScore = Field(default_factory=CVSSScore)
    epss: EPSSScore = Field(default_factory=EPSSScore)
    is_kev: Optional[bool] = Field(default=None, description="In CISA KEV catalog")
    is_kev_authoritative: bool = Field(default=False)
    asset_criticality: AssetCriticality = Field(default=AssetCriticality.MEDIUM)
    exposure: ExposureLevel = Field(default=ExposureLevel.INTERNET_FACING)
    business_risk: Optional[BusinessRisk] = Field(default=None)
    evidence_quality_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Quality of evidence supporting this finding")
    final_priority: float = Field(default=0.0, ge=0.0, le=10.0, description="Final weighted priority 0-10")
    risk_explanation: str = Field(default="", description="Human-readable explanation of risk calculation")
    
    # Weighted intelligence components
    vulnerability_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Vulnerability severity component")
    exploitability_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Exploitability component")
    attack_surface_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Attack surface component")
    mitigation_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Mitigation effectiveness 0.0-1.0")
    maturity_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Security maturity 0.0-1.0")
    business_impact_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Business impact component")
    component_scores: Dict[str, float] = Field(default_factory=dict, description="Individual component scores for transparency")
    risk_breakdown: Optional[RiskBreakdown] = Field(default=None, description="Per-finding breakdown: Likelihood, Impact, Exploitability, Confidence, Risk")
