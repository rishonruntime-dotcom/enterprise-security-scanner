"""
Confidence calculation modules.

Contains:
- ConfidenceCalculator: legacy multi-signal confidence calculator
- DynamicConfidenceEngine: new multi-factor dynamic confidence engine
- ConfidenceComponents: breakdown of dynamic confidence calculation
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

import structlog

from ..models.finding import Confidence, DetectionMethod, VerificationStatus
from .models import EnrichedFinding

logger = structlog.get_logger(__name__)


# ── Legacy Confidence Calculator ─────────────────────────────────────────────


class ConfidenceCalculator:
    """Multi-Signal Dynamic Confidence Scoring Engine."""

    @staticmethod
    def calculate(
        detection_method: Union[DetectionMethod, str],
        is_verified: bool,
        verification_status: Union[VerificationStatus, str],
        evidence_list: List[Any],
        merge_count: int = 1,
        endpoint_count: int = 1,
        has_extracted_proof: bool = False
    ) -> Tuple[Confidence, float]:
        """
        Calculates confidence score (0.0 to 1.0) and Enum (HIGH, MEDIUM, LOW) based on multi-signal evidence:
        1. Verification status (Verified active test +0.45, Passive +0.25, Unconfirmed +0.15)
        2. Extracted Proof / Evidence Quality (+0.25 for extracted regex/payload match, +0.15 for raw HTTP headers/body)
        3. Repeat Observations (+0.20 for merge_count/endpoints >= 3, +0.10 for >= 2, +0.05 for 1)
        """
        score = 0.0

        v_stat = str(verification_status).upper()
        d_meth = str(detection_method).upper()

        # Signal 1: Verification & Detection Method
        if is_verified or "VERIFIED" in v_stat:
            score += 0.45
        elif "PASSIVE" in d_meth or "NOT_ACTIVELY_VERIFIED" in v_stat:
            score += 0.25
        else:
            score += 0.15

        # Signal 2: Evidence Quality & Proof Extraction
        if has_extracted_proof:
            score += 0.25
        elif evidence_list and len(evidence_list) > 0:
            score += 0.15

        has_http_payload = any(
            getattr(ev, "raw_request", None) or getattr(ev, "raw_response", None) or getattr(ev, "data", None)
            for ev in evidence_list
        ) if evidence_list else False
        
        if has_http_payload:
            score += 0.15

        # Signal 3: Repeat Multi-Endpoint Signal Count
        if merge_count >= 3 or endpoint_count >= 3:
            score += 0.20
        elif merge_count >= 2 or endpoint_count >= 2:
            score += 0.10
        else:
            score += 0.05

        final_score = min(1.0, round(score, 2))

        if final_score >= 0.75:
            return Confidence.HIGH, final_score
        elif final_score >= 0.45:
            return Confidence.MEDIUM, final_score
        else:
            return Confidence.LOW, final_score


# ── Dynamic Confidence Engine ─────────────────────────────────────────────────

# Knowledge Bases
_FRAMEWORK_PATH_SIGNATURES: Dict[str, List[str]] = {
    "django": ["/static/", "/admin/", "/api/"],
    "rails": ["/assets/", "/rails/", "/admin/"],
    "express": ["/static/", "/public/", "/api/"],
    "spring": ["/static/", "/public/", "/api/"],
    "aspnet": ["/lib/", "/css/", "/js/", "/api/"],
    "laravel": ["/storage/", "/public/", "/api/"],
}

_PLUGIN_RELIABILITY: Dict[str, float] = {
    "ACT-XSS-001": 0.95,
    "ACT-SQLI-001": 0.92,
    "ACT-TRAV-001": 0.90,
    "ACT-SSRF-001": 0.88,
    "ACT-CMDI-001": 0.85,
    "ACT-XXE-001": 0.87,
    "ACT-SSTI-001": 0.83,
    "ACT-REDIR-001": 0.85,
    "PASS-001": 0.75,
    "PASS-001-CSP-": 0.80,
    "PASS-002": 0.85,
    "PASS-003": 0.70,
    "PASS-004": 0.78,
    "PASS-005": 0.90,
    "PASS-006": 0.80,
}

_RULE_CERTAINTY: Dict[str, float] = {
    "ACT-XSS-001": 0.95,
    "ACT-SQLI-001": 0.90,
    "ACT-TRAV-001": 0.92,
    "ACT-SSRF-001": 0.88,
    "ACT-CMDI-001": 0.85,
    "ACT-XXE-001": 0.90,
    "ACT-SSTI-001": 0.82,
    "ACT-REDIR-001": 0.85,
    "PASS-001": 0.60,
    "PASS-001-CSP-": 0.70,
    "PASS-002": 0.75,
    "PASS-003": 0.50,
    "PASS-004": 0.65,
    "PASS-005": 0.90,
    "PASS-006": 0.70,
}


@dataclass
class ConfidenceComponents:
    """Breakdown of the dynamic confidence calculation for auditability."""
    evidence_component: float = 0.0
    verification_component: float = 0.0
    endpoint_component: float = 0.0
    framework_component: float = 0.0
    technology_component: float = 0.0
    historical_component: float = 0.0
    mitigation_component: float = 0.0
    rule_certainty_component: float = 0.0
    raw_score: float = 0.0
    final_score: float = 0.0


class DynamicConfidenceEngine:
    """Enterprise dynamic confidence calculator.

    Produces a confidence score (0.0-1.0) and qualitative enum
    (Low/Medium/High/Certain) by blending multiple signals:

    - Evidence richness and source count
    - Verification status and method
    - Multi-endpoint observation
    - Framework/platform detection
    - Technology fingerprint confidence
    - Historical plugin reliability
    - Mitigation presence
    - Rule/certainty of detection

    The engine is deterministic and auditable: every factor is exposed via
    ``ConfidenceComponents`` for reporting and override workflows.
    """

    def __init__(self):
        pass

    def calculate(
        self,
        finding: EnrichedFinding,
        scan_context: Optional[dict[str, Any]] = None,
    ) -> Tuple[Confidence, float, ConfidenceComponents]:
        """Return (confidence_enum, confidence_score, components)."""
        ctx = scan_context or {}
        components = self._build_components(finding, ctx)
        final_score = max(0.0, min(1.0, components.raw_score))
        components.final_score = round(final_score, 2)
        confidence_enum = self._score_to_confidence(final_score)
        explanation = self._build_explanation(components, confidence_enum)
        logger.debug(
            "Dynamic confidence calculated",
            plugin_id=finding.plugin_id,
            endpoint=finding.endpoint,
            score=final_score,
            confidence=confidence_enum.value,
            explanation=explanation,
        )
        return confidence_enum, final_score, components

    # ── Component Calculations ────────────────────────────────────────────────

    def _build_components(self, finding: EnrichedFinding, ctx: dict[str, Any]) -> ConfidenceComponents:
        evidence = self._evidence_component(finding)
        verification = self._verification_component(finding)
        endpoint = self._endpoint_component(finding)
        framework = self._framework_component(finding)
        technology = self._technology_component(finding, ctx)
        historical = self._historical_component(finding)
        mitigation = self._mitigation_component(finding)
        rule = self._rule_certainty_component(finding)

        raw = (
            0.20 * evidence
            + 0.20 * verification
            + 0.15 * endpoint
            + 0.05 * framework
            + 0.10 * technology
            + 0.10 * historical
            + 0.10 * mitigation
            + 0.10 * rule
        )

        return ConfidenceComponents(
            evidence_component=round(evidence, 2),
            verification_component=round(verification, 2),
            endpoint_component=round(endpoint, 2),
            framework_component=round(framework, 2),
            technology_component=round(technology, 2),
            historical_component=round(historical, 2),
            mitigation_component=round(mitigation, 2),
            rule_certainty_component=round(rule, 2),
            raw_score=round(raw, 2),
            final_score=round(raw, 2),
        )

    def _evidence_component(self, finding: EnrichedFinding) -> float:
        """Evidence richness and source count (max 1.0)."""
        evidence_list = finding.evidence or []
        count = len(evidence_list)
        if count == 0:
            return 0.0

        # Base score for having evidence
        score = min(count * 0.25, 0.50)

        # Quality bonuses from first evidence item
        if evidence_list:
            ev = evidence_list[0]
            if getattr(ev, "raw_request", None):
                score += 0.15
            if getattr(ev, "raw_response", None):
                score += 0.15
            if getattr(ev, "diff", None):
                score += 0.10
            if getattr(ev, "reproduction_steps", None):
                score += 0.10
            if getattr(ev, "timing_ms", None) is not None and getattr(ev, "baseline_timing_ms", None) is not None:
                score += 0.10
            if getattr(ev, "dom_snapshot", None):
                score += 0.05
            if getattr(ev, "screenshot_path", None):
                score += 0.05

        return min(score, 1.0)

    def _verification_component(self, finding: EnrichedFinding) -> float:
        """Verification status and method (max 1.0)."""
        v_status = getattr(finding, "verification_status", VerificationStatus.NOT_ACTIVELY_VERIFIED)
        is_verified = getattr(finding, "is_verified", False)
        d_method = getattr(finding, "detection_method", DetectionMethod.PASSIVE)

        if v_status == VerificationStatus.VERIFIED or is_verified:
            return 1.0
        if v_status == VerificationStatus.FAILED:
            return 0.3
        if d_method == DetectionMethod.ACTIVE:
            return 0.55
        return 0.4

    def _endpoint_component(self, finding: EnrichedFinding) -> float:
        """Multi-endpoint observation signal (max 1.0)."""
        merge_count = getattr(finding, "merge_count", 1)
        affected = getattr(finding, "affected_endpoints", []) or [finding.endpoint]
        endpoint_count = len(affected) if affected else 1

        if merge_count >= 5 or endpoint_count >= 5:
            return 1.0
        if merge_count >= 3 or endpoint_count >= 3:
            return 0.8
        if merge_count >= 2 or endpoint_count >= 2:
            return 0.6
        return 0.4

    def _framework_component(self, finding: EnrichedFinding) -> float:
        """Known framework/platform detection (max 1.0)."""
        endpoint = finding.endpoint or ""
        path = urllib.parse.urlparse(endpoint).path.lower()

        for framework, signatures in _FRAMEWORK_PATH_SIGNATURES.items():
            if any(sig in path for sig in signatures):
                return 0.9

        # Check for framework headers in raw response
        evidence = finding.evidence or []
        raw_response = ""
        for ev in evidence:
            raw_response = getattr(ev, "raw_response", "") or ""
            if raw_response:
                break
        raw_lower = raw_response.lower()

        framework_headers = {
            "django": ["x-frame-options", "x-content-type-options"],
            "rails": ["x-frame-options", "x-xss-protection"],
            "express": ["x-powered-by"],
            "spring": ["x-frame-options", "x-xss-protection"],
            "aspnet": ["x-aspnet-version", "x-powered-by"],
            "laravel": ["x-frame-options"],
        }
        for framework, headers in framework_headers.items():
            if any(h in raw_lower for h in headers):
                return 0.7

        return 0.2

    def _technology_component(self, finding: EnrichedFinding, ctx: dict[str, Any]) -> float:
        """Technology fingerprint confidence (max 1.0)."""
        tech_confidence = ctx.get("technology_confidence")
        if tech_confidence is not None:
            try:
                return max(0.0, min(1.0, float(tech_confidence)))
            except (TypeError, ValueError):
                pass

        # Check if finding intelligence includes technology references
        intel = getattr(finding, "intelligence", None)
        if intel and intel.description:
            tech_keywords = ["wordpress", "drupal", "joomla", "react", "angular", "vue", "django", "rails", "spring", "aspnet", "laravel"]
            desc_lower = intel.description.lower()
            if any(kw in desc_lower for kw in tech_keywords):
                return 0.7

        return 0.3

    def _historical_component(self, finding: EnrichedFinding) -> float:
        """Plugin/detection method historical reliability (max 1.0)."""
        plugin_id = finding.plugin_id or ""
        base_reliability = 0.5

        # Exact match
        if plugin_id in _PLUGIN_RELIABILITY:
            base_reliability = _PLUGIN_RELIABILITY[plugin_id]
        else:
            # Prefix match for CSP variants
            for prefix, reliability in _PLUGIN_RELIABILITY.items():
                if plugin_id.startswith(prefix):
                    base_reliability = reliability
                    break

        # Detection method adjustment
        d_method = getattr(finding, "detection_method", DetectionMethod.PASSIVE)
        if d_method == DetectionMethod.ACTIVE:
            base_reliability = min(1.0, base_reliability + 0.05)
        else:
            base_reliability = max(0.0, base_reliability - 0.05)

        return base_reliability

    def _mitigation_component(self, finding: EnrichedFinding) -> float:
        """Existing security controls reduce confidence in exploitability (max 1.0)."""
        evidence = finding.evidence or []
        raw_response = ""
        for ev in evidence:
            raw_response = getattr(ev, "raw_response", "") or ""
            if raw_response:
                break
        raw_lower = raw_response.lower()

        # Mitigations present reduce confidence that the finding is exploitable
        mitigation_count = 0
        if "content-security-policy" in raw_lower:
            mitigation_count += 1
        if "x-frame-options" in raw_lower:
            mitigation_count += 1
        if "strict-transport-security" in raw_lower:
            mitigation_count += 1
        if "x-content-type-options" in raw_lower:
            mitigation_count += 1
        if "permissions-policy" in raw_lower:
            mitigation_count += 1
        if "referrer-policy" in raw_lower:
            mitigation_count += 1

        # More mitigations = lower confidence in exploitability
        return max(0.2, 1.0 - mitigation_count * 0.12)

    def _rule_certainty_component(self, finding: EnrichedFinding) -> float:
        """How certain the detection rule is (max 1.0)."""
        plugin_id = finding.plugin_id or ""
        base_certainty = 0.5

        # Exact match
        if plugin_id in _RULE_CERTAINTY:
            base_certainty = _RULE_CERTAINTY[plugin_id]
        else:
            # Prefix match for CSP variants
            for prefix, certainty in _RULE_CERTAINTY.items():
                if plugin_id.startswith(prefix):
                    base_certainty = certainty
                    break

        # Adjust based on evidence specificity
        evidence = finding.evidence or []
        if evidence:
            ev = evidence[0]
            matched_value = getattr(ev, "matched_value", None)
            detection_rule = getattr(ev, "detection_rule", None)
            if matched_value and detection_rule:
                base_certainty = min(1.0, base_certainty + 0.10)
            elif matched_value or detection_rule:
                base_certainty = min(1.0, base_certainty + 0.05)

        return base_certainty

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _score_to_confidence(score: float) -> Confidence:
        if score >= 0.95:
            return Confidence.CERTAIN
        elif score >= 0.82:
            return Confidence.VERY_HIGH
        elif score >= 0.68:
            return Confidence.HIGH
        elif score >= 0.52:
            return Confidence.LIKELY
        elif score >= 0.38:
            return Confidence.MEDIUM
        elif score >= 0.22:
            return Confidence.TENTATIVE
        else:
            return Confidence.LOW

    @staticmethod
    def _build_explanation(components: ConfidenceComponents, confidence: Confidence) -> str:
        return (
            f"Dynamic confidence={confidence.value} (score={components.final_score:.2f}). "
            f"evidence={components.evidence_component:.2f}, verification={components.verification_component:.2f}, "
            f"endpoints={components.endpoint_component:.2f}, framework={components.framework_component:.2f}, "
            f"technology={components.technology_component:.2f}, historical={components.historical_component:.2f}, "
            f"mitigation={components.mitigation_component:.2f}, rule={components.rule_certainty_component:.2f}"
        )
