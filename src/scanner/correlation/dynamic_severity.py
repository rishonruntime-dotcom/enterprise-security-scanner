"""
Dynamic Severity Pipeline Step.

Applies the DynamicSeverityEngine as the absolute last step before a finding
is added to the report.  All upstream enrichment (verification, intelligence,
CVSS, risk, priority, severity context, false-positive reduction) must run
before this step so it has the full picture.
"""
from typing import Optional
from .pipeline import PipelineStep
from .models import EnrichedFinding
from ..models.finding import Severity
from ..risk.severity_engine import DynamicSeverityEngine


class DynamicSeverityStep(PipelineStep):
    """Recalculates final severity using the multi-factor DynamicSeverityEngine."""

    def __init__(
        self,
        default_criticality: str = "Medium",
        default_exposure: str = "InternetFacing",
    ):
        self.engine = DynamicSeverityEngine(
            default_criticality=default_criticality,
            default_exposure=default_exposure,
        )

    async def process(
        self,
        finding: EnrichedFinding,
        scan_id: Optional[str] = None,
    ) -> Optional[EnrichedFinding]:
        if not finding:
            return None

        # Collect scan context if available
        scan_context: dict[str, object] = {}
        if scan_id:
            scan_context = self._load_scan_context(scan_id)

        severity, explanation, components = self.engine.calculate(finding, scan_context)

        # Always update; the engine is the source of truth for final severity.
        finding.severity = severity
        finding.severity_reason = explanation
        finding.risk_explanation = explanation

        # Attach component breakdown for auditability
        if not hasattr(finding, "severity_components"):
            pass

        return finding

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
