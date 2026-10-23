"""
CVSS Engine Pipeline Step.

Dynamically calculates CVSS v3.1 vector and score based on verified characteristics.
"""
from typing import Optional
from .pipeline import PipelineStep
from .models import EnrichedFinding
from ..models.finding import Severity
from ..risk.calculators import CVSSCalculator


class CVSSCalculationStep(PipelineStep):
    """Calculates dynamic CVSS vector and base score for verified findings."""

    async def process(self, finding: EnrichedFinding, scan_id: Optional[str] = None) -> Optional[EnrichedFinding]:
        if not finding:
            return None

        # Dynamically calculate CVSS using characteristics
        cvss_score = CVSSCalculator.calculate_for_finding(finding)
        
        # Attach to finding intelligence or risk structure if needed
        if finding.intelligence:
            finding.intelligence.cvss_vector = cvss_score.vector
        
        finding.cvss_score = cvss_score.base_score
        
        # NOTE: Severity is no longer set here.  The DynamicSeverityStep
        # runs after all other pipeline steps and is the single source of
        # truth for final qualitative severity.
        return finding
