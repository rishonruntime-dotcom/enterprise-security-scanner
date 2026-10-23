"""
Dynamic Severity Engine.

Calculates final severity by combining:
  - CVSS base score
  - Context (endpoint class, asset category)
  - Mitigations (existing protections)
  - Verification status and confidence
  - Asset criticality and exposure
  - Exploitability (EPSS, KEV)
  - Business impact

Replaces static CVSS→severity mapping with a multi-factor weighted model.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

import structlog

from ..models.finding import Severity, Confidence, DetectionMethod, VerificationStatus
from ..correlation.models import EnrichedFinding
from ..risk.models import AssetCriticality, ExposureLevel
from ..risk.calculators import BusinessRiskCalculator, PriorityCalculator
from ..risk.intelligence import EPSSAnalyzer, KEVAnalyzer

logger = structlog.get_logger(__name__)


# ── Weights & Multipliers ─────────────────────────────────────────────────────

_WEIGHT_CVSS = 0.30
_WEIGHT_CONTEXT = 0.15
_WEIGHT_ASSET = 0.15
_WEIGHT_EXPLOITABILITY = 0.15
_WEIGHT_VERIFICATION = 0.15
_WEIGHT_BUSINESS = 0.10

_ENDPOINT_CLASS_MULTIPLIER = {
    "Authentication": 1.30,
    "Admin": 1.35,
    "Payment": 1.35,
    "API": 1.15,
    "GraphQL": 1.20,
    "Upload": 1.20,
    "Main Application": 1.00,
    "Third Party": 0.75,
    "Download": 0.85,
    "Embed": 0.70,
    "Static Assets": 0.50,
    "Media": 0.55,
    "Feed": 0.60,
}

_ASSET_CATEGORY_MULTIPLIER = {
    "First-party": 1.15,
    "CDN": 0.85,
    "Payment": 1.25,
    "OAuth": 1.20,
    "Analytics": 0.80,
    "Embedded Widgets": 0.75,
    "Third Party": 0.70,
}

_CRITICALITY_MULTIPLIER = {
    AssetCriticality.LOW: 0.75,
    AssetCriticality.MEDIUM: 1.00,
    AssetCriticality.HIGH: 1.15,
    AssetCriticality.MISSION_CRITICAL: 1.30,
}

_EXPOSURE_MULTIPLIER = {
    ExposureLevel.INTERNAL: 0.80,
    ExposureLevel.EXTERNAL: 1.00,
    ExposureLevel.INTERNET_FACING: 1.10,
}

_VERIFICATION_BOOST = {
    VerificationStatus.VERIFIED: 1.25,
    VerificationStatus.NOT_ACTIVELY_VERIFIED: 1.00,
    VerificationStatus.FAILED: 0.80,
}

_CONFIDENCE_BOOST = {
    Confidence.CERTAIN: 1.15,
    Confidence.HIGH: 1.10,
    Confidence.MEDIUM: 1.00,
    Confidence.LOW: 0.85,
}

_SEVERITY_THRESHOLDS = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
    (0.0, Severity.INFO),
]


@dataclass
class SeverityComponents:
    """Breakdown of the dynamic severity calculation for auditability."""
    cvss_component: float = 0.0
    context_component: float = 0.0
    asset_component: float = 0.0
    exploitability_component: float = 0.0
    verification_component: float = 0.0
    business_component: float = 0.0
    mitigation_dampener: float = 1.0
    raw_score: float = 0.0
    final_score: float = 0.0


class DynamicSeverityEngine:
    """Enterprise dynamic severity calculator.

    Produces a final severity (Info/Low/Medium/High/Critical) by blending:
      - CVSS v3.1 base score
      - Endpoint / asset context
      - Asset criticality and exposure
      - Exploitability (EPSS + KEV)
      - Verification status and confidence
      - Business impact
      - Mitigation dampening

    The engine is deterministic and auditable: every factor is exposed via
    ``SeverityComponents`` for reporting and override workflows.
    """

    def __init__(
        self,
        default_criticality: AssetCriticality = AssetCriticality.MEDIUM,
        default_exposure: ExposureLevel = ExposureLevel.INTERNET_FACING,
    ):
        self.default_criticality = default_criticality
        self.default_exposure = default_exposure

    def calculate(
        self,
        finding: EnrichedFinding,
        scan_context: Optional[dict[str, Any]] = None,
    ) -> tuple[Severity, str, SeverityComponents]:
        """Return (final_severity, explanation, components)."""
        ctx = scan_context or {}
        components = self._build_components(finding, ctx)
        final_score, dampener = self._apply_dampening(components.raw_score, finding)
        components.mitigation_dampener = round(dampener, 2)
        components.final_score = round(final_score, 2)
        severity = self._score_to_severity(final_score)
        explanation = self._build_explanation(components, severity)
        return severity, explanation, components

    # ── Public helpers ────────────────────────────────────────────────────────

    @staticmethod
    def score_to_severity(score: float) -> Severity:
        for threshold, sev in _SEVERITY_THRESHOLDS:
            if score >= threshold:
                return sev
        return Severity.INFO

    # ── Internal pipeline ─────────────────────────────────────────────────────

    def _build_components(self, finding: EnrichedFinding, ctx: dict[str, Any]) -> SeverityComponents:
        cvss = self._cvss_component(finding)
        context = self._context_component(finding, cvss)
        asset = self._asset_component(finding, ctx)
        exploit = self._exploitability_component(finding)
        verify = self._verification_component(finding)
        business = self._business_component(finding, ctx)

        raw = (
            _WEIGHT_CVSS * cvss
            + _WEIGHT_CONTEXT * context
            + _WEIGHT_ASSET * asset
            + _WEIGHT_EXPLOITABILITY * exploit
            + _WEIGHT_VERIFICATION * verify
            + _WEIGHT_BUSINESS * business
        )

        return SeverityComponents(
            cvss_component=round(cvss, 2),
            context_component=round(context, 2),
            asset_component=round(asset, 2),
            exploitability_component=round(exploit, 2),
            verification_component=round(verify, 2),
            business_component=round(business, 2),
            raw_score=round(raw, 2),
            final_score=round(raw, 2),
        )

    def _cvss_component(self, finding: EnrichedFinding) -> float:
        cvss_score = getattr(finding, "cvss_score", None)
        if cvss_score is not None:
            return min(float(cvss_score), 10.0)
        return self._severity_to_score(finding.severity)

    def _context_component(self, finding: EnrichedFinding, cvss: float) -> float:
        ep_class = finding.endpoint_class or "Main Application"
        ep_mult = _ENDPOINT_CLASS_MULTIPLIER.get(ep_class, 1.0)
        asset_cat = getattr(finding, "asset_category", "First-party") or "First-party"
        asset_mult = _ASSET_CATEGORY_MULTIPLIER.get(asset_cat, 1.0)
        return cvss * ep_mult * asset_mult

    def _asset_component(self, finding: EnrichedFinding, ctx: dict[str, Any]) -> float:
        criticality = ctx.get("asset_criticality") or getattr(finding, "asset_criticality", None)
        exposure = ctx.get("exposure") or getattr(finding, "exposure", None)

        crit_enum = self._to_asset_criticality(criticality)
        exp_enum = self._to_exposure_level(exposure)

        crit_mult = _CRITICALITY_MULTIPLIER.get(crit_enum, 1.0)
        exp_mult = _EXPOSURE_MULTIPLIER.get(exp_enum, 1.0)
        return 10.0 * crit_mult * exp_mult

    def _exploitability_component(self, finding: EnrichedFinding) -> float:
        cwe_id = finding.intelligence.cwe_id if finding.intelligence else None
        epss = EPSSAnalyzer.analyze(cwe_id=cwe_id)
        is_kev = KEVAnalyzer.is_kev(cwe_id=cwe_id)

        epss_prob = epss.probability if (epss and epss.probability is not None) else 0.0
        epss_boost = epss_prob * 3.0
        kev_boost = 2.0 if is_kev else 0.0
        return min(epss_boost + kev_boost, 10.0)

    def _verification_component(self, finding: EnrichedFinding) -> float:
        verify_status = getattr(finding, "verification_status", VerificationStatus.NOT_ACTIVELY_VERIFIED)
        confidence = getattr(finding, "confidence", Confidence.MEDIUM)

        verify_mult = _VERIFICATION_BOOST.get(verify_status, 1.0)
        conf_mult = _CONFIDENCE_BOOST.get(confidence, 1.0)
        return 10.0 * verify_mult * conf_mult

    def _business_component(self, finding: EnrichedFinding, ctx: dict[str, Any]) -> float:
        criticality = ctx.get("asset_criticality") or getattr(finding, "asset_criticality", None)
        exposure = ctx.get("exposure") or getattr(finding, "exposure", None)
        cwe_id = finding.intelligence.cwe_id if finding.intelligence else None

        crit_enum = self._to_asset_criticality(criticality)
        exp_enum = self._to_exposure_level(exposure)

        risk = BusinessRiskCalculator.calculate(cwe_id, crit_enum, exp_enum)
        return risk.overall_business_risk

    def _apply_dampening(self, raw: float, finding: EnrichedFinding) -> tuple[float, float]:
        dampener = 1.0

        # Mitigation: browser protections present
        evidence = finding.evidence or []
        raw_response = ""
        for ev in evidence:
            raw_response = getattr(ev, "raw_response", "") or ""
            if raw_response:
                break
        raw_lower = raw_response.lower()

        has_csp = "content-security-policy" in raw_lower
        has_nonce_or_hash = "'nonce-" in raw_lower or "'sha" in raw_lower
        has_strict_dynamic = "strict-dynamic" in raw_lower
        has_trusted_types = "trusted-types" in raw_lower and "require-trusted-types-for" in raw_lower
        has_hsts = "strict-transport-security" in raw_lower
        has_xfo = "x-frame-options" in raw_lower
        has_xcto = "x-content-type-options" in raw_lower

        # Strong mitigation bundle: multiple protections present
        strong_mitigation_count = sum([
            has_csp,
            has_nonce_or_hash,
            has_strict_dynamic,
            has_trusted_types,
            has_hsts,
            has_xfo,
            has_xcto,
        ])

        # Dampen based on mitigation strength
        if strong_mitigation_count >= 5:
            dampener *= 0.50
        elif strong_mitigation_count >= 3:
            dampener *= 0.60
        elif strong_mitigation_count >= 1:
            dampener *= 0.75

        # Individual header dampening (additive with bundle)
        if has_csp:
            dampener *= 0.85
        if has_xfo:
            dampener *= 0.90
        if has_hsts:
            dampener *= 0.93
        if has_xcto:
            dampener *= 0.93

        # Strong mitigation: CSP with nonces or strict-dynamic
        if has_nonce_or_hash or has_strict_dynamic:
            dampener *= 0.75

        # Trusted Types enforcement
        if has_trusted_types:
            dampener *= 0.70

        # Mitigation: false positive reduction already downgraded
        fp_reasons = getattr(finding, "false_positive_reasons", []) or []
        if fp_reasons:
            dampener *= 0.85

        # Mitigation: low-value endpoint
        ep_class = finding.endpoint_class or "Main Application"
        if ep_class in {"Static Assets", "Media", "Feed"}:
            dampener *= 0.60

        # Mitigation: third-party assets get more dampening
        asset_cat = getattr(finding, "asset_category", "First-party") or "First-party"
        if asset_cat in {"Third Party", "CDN", "Analytics", "Embedded Widgets"}:
            dampener *= 0.75

        # Configuration findings with strong mitigations should not be High
        # If the finding is a configuration issue (PASS- prefix) and has strong mitigations,
        # cap the severity at Medium maximum
        if finding.plugin_id.startswith("PASS-") and strong_mitigation_count >= 3:
            if raw * dampener >= 7.0:
                dampener = 7.0 / max(raw, 0.1)

        return max(0.0, min(10.0, raw * dampener)), dampener

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _score_to_severity(score: float) -> Severity:
        for threshold, sev in _SEVERITY_THRESHOLDS:
            if score >= threshold:
                return sev
        return Severity.INFO

    @staticmethod
    def _severity_to_score(severity: Severity) -> float:
        mapping = {
            Severity.INFO: 0.0,
            Severity.LOW: 3.9,
            Severity.MEDIUM: 6.5,
            Severity.HIGH: 8.9,
            Severity.CRITICAL: 9.8,
        }
        return mapping.get(severity, 5.0)

    @staticmethod
    def _to_asset_criticality(value: Any) -> AssetCriticality:
        if isinstance(value, AssetCriticality):
            return value
        if not value:
            return AssetCriticality.MEDIUM
        try:
            return AssetCriticality(value)
        except ValueError:
            norm = str(value).lower().replace("_", "").replace(" ", "")
            if norm == "low":
                return AssetCriticality.LOW
            if norm in ("high",):
                return AssetCriticality.HIGH
            if norm in ("missioncritical", "mission_critical"):
                return AssetCriticality.MISSION_CRITICAL
            return AssetCriticality.MEDIUM

    @staticmethod
    def _to_exposure_level(value: Any) -> ExposureLevel:
        if isinstance(value, ExposureLevel):
            return value
        if not value:
            return ExposureLevel.INTERNET_FACING
        try:
            return ExposureLevel(value)
        except ValueError:
            norm = str(value).lower().replace("_", " ").strip()
            if norm == "internal":
                return ExposureLevel.INTERNAL
            if norm == "external":
                return ExposureLevel.EXTERNAL
            return ExposureLevel.INTERNET_FACING

    @staticmethod
    def _build_explanation(components: SeverityComponents, severity: Severity) -> str:
        return (
            f"Dynamic severity={severity.value} (final={components.final_score:.1f}). "
            f"CVSS={components.cvss_component:.1f}, context={components.context_component:.1f}, "
            f"asset={components.asset_component:.1f}, exploit={components.exploitability_component:.1f}, "
            f"verify={components.verification_component:.1f}, business={components.business_component:.1f}, "
            f"dampener={components.mitigation_dampener:.2f}"
        )
