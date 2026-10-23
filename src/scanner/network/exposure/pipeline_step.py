"""
Network Exposure Pipeline Step.

Converts ExposedServiceFinding objects into standardized Finding objects
that can flow through the existing correlation pipeline.
"""
from typing import Any, Optional
import structlog

from ...models.finding import Finding, Evidence, Severity, Confidence, VerificationStatus, DetectionMethod
from .models import ExposedServiceFinding


logger = structlog.get_logger(__name__)


class NetworkExposureStep:
    """Pipeline step that converts network exposure findings to standard findings."""

    async def process(self, item: Any, scan_id: Optional[str] = None) -> Optional[Finding]:
        if isinstance(item, ExposedServiceFinding):
            return self._convert_to_finding(item)
        return item

    def _convert_to_finding(self, exposure: ExposedServiceFinding) -> Finding:
        """Convert ExposedServiceFinding to Finding."""
        evidence = Evidence(
            type="network_exposure",
            description=f"Service {exposure.service} exposed on port {exposure.port}",
            data={
                "port": exposure.port,
                "service": exposure.service,
                "product": exposure.product,
                "version": exposure.version,
                "endpoint": exposure.endpoint,
                "risk_score": exposure.risk_score,
                "is_expected": exposure.is_expected,
                "is_authenticated": exposure.is_authenticated,
                "is_internet_facing": exposure.is_internet_facing,
            },
            detection_method="Active",
            reason=exposure.why_detected,
        )

        severity = Severity.INFO
        if exposure.severity.value == "Critical":
            severity = Severity.CRITICAL
        elif exposure.severity.value == "High":
            severity = Severity.HIGH
        elif exposure.severity.value == "Medium":
            severity = Severity.MEDIUM
        elif exposure.severity.value == "Low":
            severity = Severity.LOW

        confidence = Confidence.LOW
        if exposure.confidence >= 0.95:
            confidence = Confidence.CERTAIN
        elif exposure.confidence >= 0.80:
            confidence = Confidence.HIGH
        elif exposure.confidence >= 0.50:
            confidence = Confidence.MEDIUM

        return Finding(
            plugin_id=exposure.plugin_id,
            title=exposure.title,
            description=exposure.description,
            severity=severity,
            confidence=confidence,
            confidence_score=exposure.confidence,
            endpoint=exposure.endpoint,
            evidence=[evidence],
            verification_status=VerificationStatus.VERIFIED,
            detection_method=DetectionMethod.ACTIVE,
            remediation=exposure.remediation,
            references=exposure.references,
            cwe_id=exposure.cwe_id,
            owasp_category=exposure.owasp_category,
            capec_id=exposure.capec_id,
            why_detected=exposure.why_detected,
            how_verified=exposure.how_verified,
            severity_reason=exposure.severity_reason,
            false_positive_reasons=exposure.false_positive_reasons,
            cvss_score=exposure.risk_score * 3.5,
            priority_score=exposure.risk_score,
            business_impact=f"Network exposure: {exposure.service} on port {exposure.port} increases attack surface.",
            technical_impact=f"Exposed {exposure.service} service may provide unauthorized access to data or system resources.",
            risk_explanation=f"Risk score {exposure.risk_score:.1f}/10 based on service type, authentication status, and exposure.",
        )
