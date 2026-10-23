"""
Business Priority Engine Pipeline Step.

Calculates final priority score (0-10) independently based on asset criticality,
internet exposure, KEV catalog, EPSS probability, and evidence quality.
"""
from typing import Optional
from .pipeline import PipelineStep
from .models import EnrichedFinding
from ..risk.calculators import PriorityCalculator
from ..risk.models import AssetCriticality, ExposureLevel


class BusinessPriorityStep(PipelineStep):
    """Calculates independent business priority score for enriched findings."""

    async def process(self, finding: EnrichedFinding, scan_id: Optional[str] = None) -> Optional[EnrichedFinding]:
        if not finding or not finding.risk:
            return finding

        risk_score = finding.risk

        # Pull all verified inputs from the risk model
        cvss = risk_score.cvss
        epss = risk_score.epss
        is_kev = risk_score.is_kev
        criticality = risk_score.asset_criticality
        exposure = risk_score.exposure
        evidence_quality = risk_score.evidence_quality_score

        # Calculate priority independently
        priority, explanation = PriorityCalculator.calculate(
            cvss=cvss,
            epss=epss,
            is_kev=is_kev,
            asset_criticality=criticality,
            exposure=exposure,
            evidence_quality=evidence_quality,
        )

        # Update finding priority
        finding.risk.final_priority = priority
        finding.risk.risk_explanation = explanation
        finding.risk_explanation = explanation
        finding.priority_score = priority

        return finding
