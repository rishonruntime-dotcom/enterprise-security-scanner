"""Contextual severity calibration for otherwise valid findings."""
from typing import Any, Mapping, Optional

from ..models.finding import DetectionMethod, Severity
from ..risk.calculators import CVSSCalculator
from ..risk.engine import RiskEngine
from ..risk.models import AssetCriticality, ExposureLevel
from .models import EnrichedFinding


_SEVERITY_ORDER = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
_LOW_VALUE_ENDPOINTS = {"Static Assets", "Media", "Feed"}


class ContextualSeverityStep:
    """Calibrate severity without manufacturing risk from weak evidence."""

    def __init__(self, risk_engine: Optional[RiskEngine] = None):
        self.risk_engine = risk_engine

    async def process(
        self,
        finding: EnrichedFinding,
        scan_id: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> EnrichedFinding:
        context = context or {}
        is_passive = finding.detection_method == DetectionMethod.PASSIVE or finding.plugin_id.startswith("PASS-")
        endpoint_class = finding.endpoint_class or "Main Application"
        calibrated = finding.severity
        reason = None

        # Multi-factor objective calibration:
        # Evaluate exploitability, asset criticality, evidence quality, and compensating controls.
        if is_passive and endpoint_class in _LOW_VALUE_ENDPOINTS:
            calibrated = Severity.INFO
            reason = f"Generic passive finding on a {endpoint_class.lower()} endpoint."
        elif is_passive and self._is_material_csp_finding(finding):
            criticality = self._criticality(context.get("asset_criticality"))
            # Only escalate material CSP flaws when asset criticality is high AND the policy is unmitigated
            if criticality in {AssetCriticality.HIGH, AssetCriticality.MISSION_CRITICAL} and finding.severity in {Severity.MEDIUM, Severity.HIGH}:
                calibrated = Severity.HIGH
                reason = f"Material unmitigated CSP weakness on a {criticality.value} business asset."
            elif finding.severity == Severity.LOW:
                # Do not force Low severity CSP findings (e.g. good protection with minor legacy fallbacks) to High/CVSS 8.9
                calibrated = Severity.LOW
                reason = f"CSP policy provides good protection with minor legacy fallbacks on a {criticality.value} asset."

        if calibrated != finding.severity:
            finding.severity = calibrated
            cvss = CVSSCalculator.calculate_base(calibrated)
            finding.cvss_score = cvss.base_score
            if finding.intelligence:
                finding.intelligence.cvss_vector = cvss.vector
            if reason:
                finding.risk_explanation = reason
                finding.severity_reason = reason

            if self.risk_engine:
                exposure = self._exposure(context.get("exposure"))
                finding.risk = self.risk_engine.assess(
                    finding,
                    asset_criticality=self._criticality(context.get("asset_criticality")),
                    exposure=exposure,
                )
                finding.priority_score = finding.risk.final_priority
                finding.evidence_score = finding.risk.evidence_quality_score
                if reason:
                    finding.risk.risk_explanation = f"{reason} {finding.risk.risk_explanation}".strip()
        return finding

    @staticmethod
    def _is_material_csp_finding(finding: EnrichedFinding) -> bool:
        title = finding.title.lower()
        if finding.severity == Severity.INFO or any(word in title for word in ("notice", "mitigated", "backward-compatible", "good protection", "strong protection")):
            return False
        return finding.plugin_id.startswith("PASS-001-CSP-") or "content-security-policy" in title or "csp " in title

    @staticmethod
    def _criticality(value: Any) -> AssetCriticality:
        try:
            return AssetCriticality(value) if value else AssetCriticality.MEDIUM
        except ValueError:
            normalized = str(value).lower().replace("_", "").replace(" ", "")
            return AssetCriticality.MISSION_CRITICAL if normalized == "missioncritical" else AssetCriticality.HIGH if normalized == "high" else AssetCriticality.LOW if normalized == "low" else AssetCriticality.MEDIUM

    @staticmethod
    def _exposure(value: Any) -> Optional[ExposureLevel]:
        try:
            return ExposureLevel(value) if value else None
        except ValueError:
            return None
