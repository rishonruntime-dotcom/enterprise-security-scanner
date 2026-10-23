"""
Enterprise Finding and Evidence models.

Every finding must contain: verification status, confidence score, evidence,
reproduction steps, HTTP request, HTTP response, payload, remediation, references.
"""
from enum import Enum
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field
import hashlib


class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Confidence(str, Enum):
    VERY_LOW = "Very Low"
    LOW = "Low"
    POSSIBLE = "Possible"
    TENTATIVE = "Tentative"
    MEDIUM = "Medium"
    LIKELY = "Likely"
    HIGH = "High"
    VERY_HIGH = "Very High"
    PROBABLE = "Probable"
    CERTAIN = "Certain"


class VerificationStatus(str, Enum):
    """Verification outcome for a finding."""
    VERIFIED = "Verified"
    NOT_ACTIVELY_VERIFIED = "Not Actively Verified"
    FAILED = "Failed"


class DetectionMethod(str, Enum):
    """How the finding was detected."""
    PASSIVE = "Passive"
    ACTIVE = "Active"


class Evidence(BaseModel):
    """Rich evidence collected to prove a finding."""
    type: str = Field(..., description="Type of evidence (e.g., 'sqli_error', 'xss_reflection', 'timing_differential')")
    description: str = Field(..., description="Explanation of what the evidence shows")
    data: Any = Field(..., description="The actual evidence data")
    matched_value: Optional[str] = Field(None, description="The specific value matched (masked if sensitive)")
    detection_rule: Optional[str] = Field(None, description="The rule or regex that triggered the finding")
    detection_method: Optional[str] = Field(None, description="How it was detected (e.g. 'Passive Regex', 'Active Fuzzing')")
    reason: Optional[str] = Field(None, description="Reason why the plugin triggered")
    raw_request: Optional[str] = Field(None, description="Full raw HTTP request as string")
    raw_response: Optional[str] = Field(None, description="Full raw HTTP response as string (truncated to 10KB)")
    request_headers: Optional[Dict[str, str]] = Field(None, description="HTTP request headers")
    response_headers: Optional[Dict[str, str]] = Field(None, description="HTTP response headers")
    cookies: Optional[Dict[str, str]] = Field(None, description="Relevant cookies")
    dom_snapshot: Optional[str] = Field(None, description="DOM snapshot at time of detection (truncated)")
    screenshot_path: Optional[str] = Field(None, description="Path to screenshot file if captured")
    timing_ms: Optional[float] = Field(None, description="Response time in milliseconds")
    baseline_timing_ms: Optional[float] = Field(None, description="Baseline response time for comparison")
    diff: Optional[str] = Field(None, description="Diff between baseline and fuzzed response")
    response_hash: Optional[str] = Field(None, description="SHA-256 hash of response body")
    reproduction_steps: Optional[List[str]] = Field(None, description="Ordered curl-equivalent commands to reproduce")


class Finding(BaseModel):
    """A security vulnerability or misconfiguration finding with full enterprise metadata."""
    plugin_id: str
    title: str
    description: str
    severity: Severity
    original_severity: Optional[Severity] = Field(None, description="Severity before contextual adjustment (audit trail)")
    confidence: Confidence
    evidence: List[Evidence] = Field(default_factory=list)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    endpoint: str = Field(..., description="The URL or resource where the finding was discovered")
    affected_endpoints: List[str] = Field(default_factory=list, description="All endpoints represented by an aggregated finding")

    # Verification & Detection
    detection_method: DetectionMethod = Field(default=DetectionMethod.PASSIVE, description="How this was discovered")
    verification_status: VerificationStatus = Field(default=VerificationStatus.NOT_ACTIVELY_VERIFIED)
    verification_details: Optional[str] = Field(None, description="Explanation of verification outcome")
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Numeric confidence 0.0 to 1.0")
    endpoint_class: Optional[str] = Field(default="Main Application", description="Functional classification of endpoint (e.g. Auth, Admin, Feed, API)")
    asset_category: Optional[str] = Field(default="First-party", description="Asset ownership category (e.g. First-party, CDN, Analytics, Payment)")

    # Explainability
    why_detected: Optional[str] = Field(None, description="Why the scanner flagged this finding")
    how_verified: Optional[str] = Field(None, description="How the finding was verified (active/passive)")
    severity_reason: Optional[str] = Field(None, description="Why this severity level was assigned")
    false_positive_reasons: List[str] = Field(default_factory=list, description="Possible reasons this could be a false positive")

    # Attack details
    attack_payload: Optional[str] = Field(None, description="The payload that triggered the vulnerability")
    affected_parameter: Optional[str] = Field(None, description="The parameter/field that is vulnerable")
    http_request: Optional[str] = Field(None, description="Full HTTP request that triggered the finding")
    http_response: Optional[str] = Field(None, description="HTTP response snippet showing the vulnerability")

    # Reproduction
    reproduction_steps: List[str] = Field(default_factory=list, description="Steps to reproduce the finding")

    # Standards mappings
    owasp_category: Optional[str] = Field(None, description="OWASP Top 10 category (e.g., 'A03:2021-Injection')")
    cwe_id: Optional[str] = Field(None, description="CWE ID (e.g., 'CWE-89')")
    capec_id: Optional[str] = Field(None, description="CAPEC ID (e.g., 'CAPEC-66')")
    cvss_vector: Optional[str] = Field(None, description="CVSS v3.1 vector string")
    cvss_score: Optional[float] = Field(None, description="CVSS v3.1 base score")
    epss_score: Optional[float] = Field(None, description="EPSS probability (None if unavailable)")
    kev_status: Optional[bool] = Field(None, description="Whether in CISA KEV catalog (None if unknown)")
    priority_score: Optional[float] = Field(None, description="Calculated priority score (0-10)")

    # Impact
    business_impact: Optional[str] = Field(None, description="Business impact description")
    technical_impact: Optional[str] = Field(None, description="Technical impact description")
    risk_explanation: Optional[str] = Field(None, description="Explanation of how risk was calculated")

    def compute_dedup_hash(self) -> str:
        """Compute a deduplication hash based on plugin, endpoint, parameter, and title."""
        hash_input = f"{self.plugin_id}:{self.endpoint}:{self.affected_parameter or ''}:{self.title}"
        return hashlib.sha256(hash_input.encode()).hexdigest()
