from typing import Optional, Dict, Any, List
from .pipeline import PipelineStep
from .models import EnrichedFinding
from ..risk.engine import RiskEngine
from ..risk.models import AssetCriticality, ExposureLevel
from ..risk.intelligence_collector import RiskIntelligenceCollector
from ..interfaces.repositories import AbstractScanRepository


class RiskCalculationStep(PipelineStep):
    """Calculates full dynamic risk for an enriched finding using weighted risk intelligence."""

    def __init__(
        self,
        risk_engine: RiskEngine,
        scan_repo: Optional[AbstractScanRepository] = None,
        target_context: Optional[Dict[str, Any]] = None,
    ):
        self.risk_engine = risk_engine
        self.scan_repo = scan_repo
        self.target_context = target_context or {}
        self.collector = RiskIntelligenceCollector()

    async def process(
        self,
        finding: EnrichedFinding,
        scan_id: Optional[str] = None,
    ) -> Optional[EnrichedFinding]:
        if not finding:
            return None

        criticality = None
        exposure = None
        scan_metadata = {}

        if scan_id and self.scan_repo:
            scan = None
            if hasattr(self.scan_repo, 'get_by_id'):
                scan = await self.scan_repo.get_by_id(scan_id)
            elif hasattr(self.scan_repo, 'get'):
                scan = await self.scan_repo.get(scan_id)
                
            if scan:
                if scan.asset_criticality:
                    try:
                        criticality = AssetCriticality(scan.asset_criticality)
                    except ValueError:
                        norm = scan.asset_criticality.lower().strip()
                        if norm in ("normal", "medium"):
                            criticality = AssetCriticality.MEDIUM
                if scan.exposure:
                    try:
                        exposure = ExposureLevel(scan.exposure)
                    except ValueError:
                        pass
                
                scan_metadata = {
                    "asset_criticality": getattr(scan, "asset_criticality", "Medium"),
                    "exposure": getattr(scan, "exposure", "InternetFacing"),
                    "data_sensitivity": getattr(scan, "data_sensitivity", "Medium"),
                    "compliance_requirements": getattr(scan, "compliance_requirements", []),
                    "user_base_size": getattr(scan, "user_base_size", "Medium"),
                    "revenue_impact": getattr(scan, "revenue_impact", "Medium"),
                }

        # Collect intelligence from findings
        self._collect_intelligence(finding)
        
        # Collect from scan metadata
        if scan_metadata:
            self.risk_engine.set_scan_metadata(scan_metadata)

        # Calculate risk score
        ctx = {**self.target_context, **scan_metadata}
        risk_score = self.risk_engine.assess(
            finding,
            asset_criticality=criticality,
            exposure=exposure,
            target_context=ctx,
        )
        
        finding.risk = risk_score
        finding.evidence_score = risk_score.evidence_quality_score
        
        # Also store component scores on finding for reporting
        finding.vulnerability_score = risk_score.vulnerability_score
        finding.exploitability_score = risk_score.exploitability_score
        finding.attack_surface_score = risk_score.attack_surface_score
        finding.mitigation_score = risk_score.mitigation_score
        finding.maturity_score = risk_score.maturity_score
        finding.business_impact_score = risk_score.business_impact_score

        return finding

    def _collect_intelligence(self, finding: EnrichedFinding) -> None:
        """Collect intelligence from a finding."""
        self.risk_engine.add_finding(finding)
        
        # Collect technologies if available
        if hasattr(finding, "technologies"):
            for tech in (finding.technologies or []):
                self.risk_engine.add_technology(tech)
        
        # Collect headers from evidence
        if finding.evidence:
            for ev in finding.evidence:
                if ev.response_headers:
                    for k, v in ev.response_headers.items():
                        self.risk_engine.add_header(k, v)
                if ev.request_headers:
                    for k, v in ev.request_headers.items():
                        self.risk_engine.add_header(k, v)
                if ev.cookies:
                    for k, v in ev.cookies.items():
                        self.risk_engine.add_header("set-cookie", f"{k}={v}")
        
        # Collect endpoints
        if hasattr(finding, "affected_endpoints"):
            for ep in (finding.affected_endpoints or [finding.endpoint]):
                if isinstance(ep, str):
                    self.risk_engine.add_endpoint({"path": ep, "endpoint": ep})
                elif isinstance(ep, dict):
                    self.risk_engine.add_endpoint(ep)

