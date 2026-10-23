import pytest
from scanner.models.finding import Severity, Confidence, DetectionMethod
from scanner.correlation.models import EnrichedFinding, VulnerabilityIntelligence
from scanner.reporting.manager import ReportManager
from scanner.reporting.models import ScanSummary


def test_standalone_mitigation_weaknesses_are_rejected_from_attack_chains():
    """
    Rejection Invariant: Mitigation weakness != vulnerability.
    Standalone passive missing headers or insecure cookie flags WITHOUT an executable vulnerability primitive (e.g. XSS) MUST NOT form an attack chain.
    """
    header_finding = EnrichedFinding(
        plugin_id="PASS-001-CSP-MISSING",
        title="Missing Content-Security-Policy Header",
        description="No CSP header returned by server",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        endpoint="https://example.test/",
        detection_method=DetectionMethod.PASSIVE,
    )
    cookie_finding = EnrichedFinding(
        plugin_id="PASS-002",
        title="Insecure Session Cookie Flags",
        description="Session cookie missing HttpOnly flag",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        endpoint="https://example.test/",
        detection_method=DetectionMethod.PASSIVE,
    )

    manager = ReportManager(exporters={}, output_dir="/tmp")
    chains = manager._synthesize_attack_chains(
        findings=[header_finding, cookie_finding],
        stats={},
    )

    # Must be 0 chains generated because no executable vulnerability primitive (like XSS) exists!
    assert len(chains) == 0


def test_coexistence_without_causality_is_rejected():
    """
    Rejection Invariant: co-existence != causality.
    Unrelated findings co-existing on the same domain without a technical prerequisite dependency MUST NOT generate a chain.
    """
    info_finding = EnrichedFinding(
        plugin_id="PASS-003",
        title="Server Version Banner Disclosed",
        description="Apache version disclosed",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        endpoint="https://example.test/",
        detection_method=DetectionMethod.PASSIVE,
    )
    cookie_finding = EnrichedFinding(
        plugin_id="PASS-002",
        title="Insecure Cookie Security Configuration",
        description="Insecure cookie flags",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        endpoint="https://example.test/",
        detection_method=DetectionMethod.PASSIVE,
    )

    manager = ReportManager(exporters={}, output_dir="/tmp")
    chains = manager._synthesize_attack_chains(
        findings=[info_finding, cookie_finding],
        stats={},
    )

    assert len(chains) == 0


def test_valid_causal_attack_chain_includes_explicit_edge_mechanisms():
    """
    Valid Chain Edge Invariant:
    When a verified executable vulnerability primitive (Reflected XSS) is present alongside a missing CSP header and an insecure session cookie,
    the resulting attack chain MUST contain structured causal edges detailing:
    Source Finding -> Causal Relationship -> Technical Mechanism -> Destination Finding.
    """
    header_finding = EnrichedFinding(
        plugin_id="PASS-001-CSP-MISSING",
        title="Missing Content-Security-Policy Header",
        description="No CSP header returned by server",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        endpoint="https://example.test/search",
        detection_method=DetectionMethod.PASSIVE,
    )
    xss_finding = EnrichedFinding(
        plugin_id="ACT-XSS-001",
        title="Reflected Cross-Site Scripting (XSS)",
        description="Reflected script injection in q parameter",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        endpoint="https://example.test/search?q=",
        is_verified=True,
        detection_method=DetectionMethod.ACTIVE,
        intelligence=VulnerabilityIntelligence(cwe_id="CWE-79"),
    )
    cookie_finding = EnrichedFinding(
        plugin_id="PASS-002",
        title="Insecure Cookie Security Configuration",
        description="Session cookie missing HttpOnly flag",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        endpoint="https://example.test/search",
        detection_method=DetectionMethod.PASSIVE,
    )

    manager = ReportManager(exporters={}, output_dir="/tmp")
    chains = manager._synthesize_attack_chains(
        findings=[header_finding, xss_finding, cookie_finding],
        stats={},
    )

    assert len(chains) == 1
    chain = chains[0]
    assert chain["chain_id"] == "CHAIN-001"
    assert "causal_edges" in chain
    assert len(chain["causal_edges"]) >= 2

    # Assert edge 1 structure
    edge1 = chain["causal_edges"][0]
    assert "source_finding" in edge1
    assert "causal_relationship" in edge1
    assert "technical_mechanism" in edge1
    assert "destination_finding" in edge1
    assert edge1["source_finding"]["plugin_id"] == "PASS-001-CSP-MISSING"
    assert edge1["destination_finding"]["plugin_id"] == "ACT-XSS-001"
    assert len(edge1["causal_relationship"]) > 5
    assert len(edge1["technical_mechanism"]) > 10

    # Assert edge 2 structure
    edge2 = chain["causal_edges"][1]
    assert edge2["source_finding"]["plugin_id"] == "ACT-XSS-001"
    assert "document.cookie" in edge2["technical_mechanism"].lower()
