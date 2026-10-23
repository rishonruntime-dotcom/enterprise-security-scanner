"""
Enterprise Risk Engine.

Orchestrates full dynamic risk assessment using weighted risk intelligence:
- Vulnerability severity (CVSS-based): 35%
- Exploitability (EPSS + KEV + active success): 25%
- Environment/Attack Surface: 20%
- Security Maturity (risk reduction): 10%
- Business Impact: 10%

Uses RiskIntelligenceCollector to gather comprehensive intelligence from
scan results, then WeightedRiskEngine to compute differentiated scores.
"""
from typing import Optional, Union, Dict, Any, List
from ..correlation.models import EnrichedFinding
from .models import AssetCriticality, ExposureLevel, RiskScore
from .intelligence_collector import RiskIntelligenceCollector
from .weighted_engine import WeightedRiskEngine


class RiskEngine:
    """Coordinates full dynamic risk assessment for a finding using weighted intelligence."""

    def __init__(
        self,
        default_criticality: Union[AssetCriticality, str] = AssetCriticality.MEDIUM,
        default_exposure: Union[ExposureLevel, str] = ExposureLevel.INTERNET_FACING,
        target_context: Optional[Dict[str, Any]] = None,
    ):
        if isinstance(default_criticality, str):
            norm = default_criticality.lower().strip()
            if norm == "low":
                self.default_criticality = AssetCriticality.LOW
            elif norm in ("medium", "normal"):
                self.default_criticality = AssetCriticality.MEDIUM
            elif norm == "high":
                self.default_criticality = AssetCriticality.HIGH
            elif norm in ("missioncritical", "mission_critical"):
                self.default_criticality = AssetCriticality.MISSION_CRITICAL
            else:
                self.default_criticality = AssetCriticality.MEDIUM
        else:
            self.default_criticality = default_criticality

        if isinstance(default_exposure, str):
            norm = default_exposure.lower().strip()
            if norm == "internal":
                self.default_exposure = ExposureLevel.INTERNAL
            elif norm == "external":
                self.default_exposure = ExposureLevel.EXTERNAL
            elif norm in ("internetfacing", "internet_facing"):
                self.default_exposure = ExposureLevel.INTERNET_FACING
            else:
                self.default_exposure = ExposureLevel.INTERNET_FACING
        else:
            self.default_exposure = default_exposure

        self.target_context = target_context or {}
        self.collector = RiskIntelligenceCollector()
        self.weighted_engine = WeightedRiskEngine(
            default_criticality=self.default_criticality.value,
            default_exposure=self.default_exposure.value,
        )

    def add_finding(self, finding: Any) -> None:
        """Add a finding to the intelligence collector."""
        self.collector.add_finding(finding)

    def add_technology(self, tech: Dict[str, Any]) -> None:
        """Add a detected technology."""
        self.collector.add_technology(tech)

    def add_header(self, name: str, value: str) -> None:
        """Add a response header."""
        self.collector.add_header(name, value)

    def set_csp_policy(self, policy: Optional[str]) -> None:
        """Set CSP policy."""
        self.collector.set_csp_policy(policy)

    def add_endpoint(self, endpoint: Dict[str, Any]) -> None:
        """Add a discovered endpoint."""
        self.collector.add_endpoint(endpoint)

    def set_scan_metadata(self, metadata: Dict[str, Any]) -> None:
        """Set scan-level metadata."""
        self.collector.set_scan_metadata(metadata)

    def assess(
        self,
        finding: EnrichedFinding,
        asset_criticality: Optional[AssetCriticality] = None,
        exposure: Optional[ExposureLevel] = None,
        target_context: Optional[Dict[str, Any]] = None,
    ) -> RiskScore:
        """
        Assess risk for a finding using weighted risk intelligence.
        
        Args:
            finding: The enriched finding
            asset_criticality: Optional asset criticality override
            exposure: Optional exposure level override
            target_context: Optional additional context
        """
        # Add finding to collector for intelligence gathering
        self.collector.add_finding(finding)
        
        # Merge context
        ctx = {**self.target_context, **(target_context or {})}
        
        # Collect risk intelligence
        risk_intel = self.collector.collect(target_context=ctx)
        
        # Override with finding-specific intelligence if available
        if hasattr(finding, "intelligence") and finding.intelligence:
            risk_intel.vulnerability_intelligence = finding.intelligence
        
        # Assess using weighted engine
        return self.weighted_engine.assess(
            finding=finding,
            risk_intelligence=risk_intel,
            asset_criticality=asset_criticality,
            exposure=exposure,
        )

    def assess_batch(
        self,
        findings: list[EnrichedFinding],
        asset_criticality: Optional[AssetCriticality] = None,
        exposure: Optional[ExposureLevel] = None,
        target_context: Optional[Dict[str, Any]] = None,
    ) -> list[RiskScore]:
        """Assess risk for multiple findings."""
        # Collect all findings first
        for finding in findings:
            self.add_finding(finding)
        
        return [
            self.assess(f, asset_criticality, exposure, target_context)
            for f in findings
        ]
