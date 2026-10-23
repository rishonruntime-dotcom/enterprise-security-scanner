import pytest
from scanner.models.finding import Severity, Confidence, DetectionMethod
from scanner.correlation.models import EnrichedFinding, VulnerabilityIntelligence
from scanner.risk.calculators import CVSSCalculator
from scanner.reporting.manager import ReportManager
from scanner.reporting.models import ScanSummary


def test_cvss_invariants_for_all_severities():
    """Verify that recalibrate_and_validate enforces all 4 enterprise CVSS invariants."""
    for sev in [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]:
        finding = EnrichedFinding(
            plugin_id="PASS-003",
            title=f"Sample {sev.value} finding",
            description="Test finding description",
            severity=sev,
            confidence=Confidence.HIGH,
            endpoint="https://example.test/",
            detection_method=DetectionMethod.PASSIVE,
            intelligence=VulnerabilityIntelligence(),
        )

        calibrated = CVSSCalculator.recalibrate_and_validate(finding)

        # Invariant 1: Vector string must be valid and non-empty for score > 0
        vector = calibrated.cvss_vector or calibrated.intelligence.cvss_vector
        assert vector is not None
        assert vector != ""
        assert vector != "N/A"
        assert vector.startswith("CVSS:3.1/")

        # Invariant 2: Vector-derived score must match finding cvss_score
        calculated_from_vec = CVSSCalculator.calculate_from_vector(vector)
        assert calculated_from_vec.base_score == calibrated.cvss_score

        # Invariant 3: Qualitative severity must agree with CVSS score range
        expected_sev = CVSSCalculator.severity_from_score(calibrated.cvss_score)
        assert calibrated.severity == expected_sev

        # Invariant 4: Severity reason must NOT be generic placeholder
        reason = calibrated.severity_reason or calibrated.risk_explanation
        assert reason is not None
        assert "confidence based on" not in reason.lower()
        assert len(reason) > 10


def test_low_severity_banner_disclosure_has_low_cvss_score_and_valid_vector():
    """Server Version Banner Disclosed (LOW) must have CVSS score in LOW range (0.1-3.9) and valid vector."""
    banner_finding = EnrichedFinding(
        plugin_id="PASS-003",
        title="Server Version Banner Disclosed",
        description="Apache/2.4.41 disclosed in response header",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        endpoint="https://example.test/",
        detection_method=DetectionMethod.PASSIVE,
        intelligence=VulnerabilityIntelligence(),
    )

    calibrated = CVSSCalculator.recalibrate_and_validate(banner_finding)

    assert calibrated.severity == Severity.LOW
    assert 0.1 <= calibrated.cvss_score <= 3.9
    assert calibrated.cvss_vector.startswith("CVSS:3.1/")
    assert "confidence based on" not in calibrated.severity_reason.lower()


def test_email_disclosure_has_low_cvss_score_and_valid_vector():
    """Email Address Disclosed (LOW) must have CVSS score in LOW range (0.1-3.9) and valid vector."""
    email_finding = EnrichedFinding(
        plugin_id="PASS-003",
        title="Email Address(es) Disclosed in Source Code",
        description="user@example.test found in page comment",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        endpoint="https://example.test/contact",
        detection_method=DetectionMethod.PASSIVE,
        intelligence=VulnerabilityIntelligence(),
    )

    calibrated = CVSSCalculator.recalibrate_and_validate(email_finding)

    assert calibrated.severity == Severity.LOW
    assert 0.1 <= calibrated.cvss_score <= 3.9
    assert calibrated.cvss_vector.startswith("CVSS:3.1/")
    assert "confidence based on" not in calibrated.severity_reason.lower()


def test_report_manager_enforces_cvss_invariants_on_all_report_findings():
    """ReportManager must run recalibrate_and_validate on all report findings."""
    f1 = EnrichedFinding(
        plugin_id="PASS-003",
        title="Server Version Banner Disclosed",
        description="Banner disclosure",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        endpoint="https://example.test/",
        cvss_score=5.0,  # Contradictory score passed intentionally
        cvss_vector="N/A",  # Invalid vector passed intentionally
        severity_reason="Confidence based on header pattern",  # Bad reason string passed intentionally
        intelligence=VulnerabilityIntelligence(),
    )

    manager = ReportManager(exporters={}, output_dir="/tmp")
    intelligence = manager._compute_intelligence(
        findings=[f1],
        target_urls=["https://example.test"],
        summary=ScanSummary(total_findings=1, low_count=1),
        stats={},
        scan_obj=None,
    )

    # Re-check finding f1 after ReportManager processing
    assert f1.cvss_score <= 3.9  # Recalibrated to LOW range!
    assert f1.cvss_vector != "N/A"
    assert f1.cvss_vector.startswith("CVSS:3.1/")
    assert "confidence based on" not in f1.severity_reason.lower()
