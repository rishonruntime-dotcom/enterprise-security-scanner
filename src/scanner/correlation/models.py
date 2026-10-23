"""
Enterprise correlation models.

EnrichedFinding extends Finding with intelligence, verification, risk scoring,
and full enterprise metadata. VulnerabilityIntelligence holds CWE/OWASP/CAPEC/CVSS mappings.
"""
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

from ..models.finding import Finding, VerificationStatus
from ..risk.models import RiskScore


class VulnerabilityIntelligence(BaseModel):
    """Enrichment metadata for a vulnerability finding."""
    cwe_id: Optional[str] = Field(None, description="Common Weakness Enumeration ID (e.g., 'CWE-79')")
    cwe_name: Optional[str] = Field(None, description="CWE Name")
    owasp_category: Optional[str] = Field(None, description="OWASP Top 10 category (e.g., 'A03:2021-Injection')")
    description: Optional[str] = Field(None, description="Enriched description from threat intel")
    capec_id: Optional[str] = Field(None, description="Common Attack Pattern Enumeration and Classification ID")
    cvss_vector: Optional[str] = Field(None, description="CVSS Vector string")
    cvss_score: Optional[float] = Field(None, description="CVSS base score")
    references: List[str] = Field(default_factory=list, description="Reference URLs (CWE, OWASP, NVD)")
    business_impact: Optional[str] = Field(None, description="Business impact description")
    technical_impact: Optional[str] = Field(None, description="Technical impact description")


class EnrichedFinding(Finding):
    """A Finding enriched with intelligence, verification status, and risk score."""
    intelligence: VulnerabilityIntelligence = Field(default_factory=VulnerabilityIntelligence)
    is_verified: bool = Field(default=False, description="Has this finding passed verification?")
    deduplication_hash: Optional[str] = Field(None, description="Hash used to deduplicate this finding")
    risk: Optional[RiskScore] = Field(None, description="Computed risk and priority score")
    evidence_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Quality score of evidence (0.0 to 1.0)")
    merge_count: int = Field(default=1, description="Number of similar findings merged into this one")
    asset_category: Optional[str] = Field(default="First-party", description="Asset ownership/integration category")
    
    # Weighted intelligence components
    vulnerability_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Vulnerability severity component")
    exploitability_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Exploitability component")
    attack_surface_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Attack surface component")
    mitigation_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Mitigation effectiveness")
    maturity_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Security maturity")
    business_impact_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Business impact component")

    # Per-finding false-positive probability (0.0-1.0)
    false_positive_probability: float = Field(default=0.0, ge=0.0, le=1.0, description="Per-finding false-positive probability (0.0-1.0)")
