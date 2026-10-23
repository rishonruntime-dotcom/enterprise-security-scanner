"""
Dynamic Confidence Pipeline Step.

Applies the DynamicConfidenceEngine as the authoritative source for finding
confidence.  Runs after verification and all other enrichment steps, but
before false-positive reduction and dynamic severity.
"""
from typing import Optional
from .pipeline import PipelineStep
from .models import EnrichedFinding
from ..models.finding import Confidence
from .confidence import DynamicConfidenceEngine, ConfidenceComponents


class DynamicConfidenceStep(PipelineStep):
    """Recalculates confidence using the multi-factor DynamicConfidenceEngine."""

    def __init__(self, default_criticality: str = "Medium", default_exposure: str = "InternetFacing"):
        self.engine = DynamicConfidenceEngine()

    async def process(
        self,
        finding: EnrichedFinding,
        scan_id: Optional[str] = None,
    ) -> Optional[EnrichedFinding]:
        if not finding:
            return None

        scan_context: dict[str, object] = {}
        if scan_id:
            scan_context = self._load_scan_context(scan_id)

        confidence_enum, confidence_score, components = self.engine.calculate(finding, scan_context)

        finding.confidence = confidence_enum
        finding.confidence_score = confidence_score
        finding.severity_reason = self._build_severity_reason(finding, components)

        return finding

    @staticmethod
    def _build_severity_reason(finding: EnrichedFinding, components: ConfidenceComponents) -> str:
        parts = []
        if components.evidence_component >= 0.7:
            parts.append("strong evidence base")
        elif components.evidence_component >= 0.4:
            parts.append("moderate evidence base")
        else:
            parts.append("limited evidence base")

        if components.verification_component >= 0.9:
            parts.append("verified")
        elif components.verification_component >= 0.6:
            parts.append("partially verified")
        else:
            parts.append("unverified")

        if components.endpoint_component >= 0.8:
            parts.append("observed across multiple endpoints")

        if components.framework_component >= 0.7:
            parts.append("known framework detected")

        if components.mitigation_component < 0.7:
            parts.append("existing mitigations reduce exploitability")

        return f"Confidence based on: {', '.join(parts)}."

    @staticmethod
    def _load_scan_context(scan_id: Optional[str]) -> dict[str, object]:
        context: dict[str, object] = {}
        if not scan_id:
            return context

        try:
            from ..database.session import get_session_factory
            from ..repositories.scan_repository import ScanRepository
            factory = get_session_factory()
            if not factory:
                return context
            with factory() as session:
                repo = ScanRepository(session)
                scan = repo.get_by_id(scan_id)
                if scan:
                    if getattr(scan, "asset_criticality", None):
                        context["asset_criticality"] = scan.asset_criticality
                    if getattr(scan, "exposure", None):
                        context["exposure"] = scan.exposure
        except Exception:
            pass

        return context
