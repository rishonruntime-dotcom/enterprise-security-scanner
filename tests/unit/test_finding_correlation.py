import asyncio

from scanner.correlation.pipeline import FindingPipeline
from scanner.correlation.correlator import FindingCorrelator
from scanner.correlation.models import EnrichedFinding, VulnerabilityIntelligence
from scanner.models.finding import Confidence, Evidence, Severity, VerificationStatus


def _finding(**overrides) -> EnrichedFinding:
    defaults = {
        "plugin_id": "TEST-001",
        "title": "Test finding",
        "description": "Test",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "endpoint": "https://scanner.test/search?q=test",
        "evidence": [Evidence(type="test", description="test evidence", data={})],
    }
    defaults.update(overrides)
    return EnrichedFinding(**defaults)


def test_verified_xss_and_material_csp_weakness_become_one_correlated_finding():
    xss = _finding(
        plugin_id="ACT-XSS-001",
        title="Verified reflected XSS",
        severity=Severity.HIGH,
        is_verified=True,
        verification_status=VerificationStatus.VERIFIED,
        intelligence=VulnerabilityIntelligence(cwe_id="CWE-79"),
    )
    csp = _finding(
        plugin_id="PASS-001-CSP-SCRIPT-INLINE",
        title="CSP Directive Misconfiguration: Unrestricted 'script-src' Allows 'unsafe-inline'",
        endpoint="https://scanner.test/",
    )
    unrelated = _finding(plugin_id="PASS-002", title="Insecure Cookie Configuration: sid")

    results = asyncio.run(FindingPipeline().process([xss, csp, unrelated], scan_id="scan-correlation"))

    assert len(results) == 2
    correlated = next(finding for finding in results if finding.plugin_id == FindingCorrelator.RULE_ID)
    assert correlated.severity == Severity.HIGH
    assert correlated.is_verified is True
    assert correlated.merge_count == 2
    assert correlated.evidence[0].data["correlation_rule"] == FindingCorrelator.RULE_ID
    assert len(correlated.evidence[0].data["supporting_findings"]) == 2
    assert any(finding.plugin_id == "PASS-002" for finding in results)


def test_unverified_xss_or_mitigated_csp_does_not_create_correlation():
    unverified_xss = _finding(plugin_id="ACT-XSS-001", title="Potential XSS")
    mitigated_csp = _finding(
        plugin_id="PASS-001-CSP-SCRIPT-INLINE",
        title="CSP Notice: 'script-src' Contains Backward-Compatible 'unsafe-inline'",
        severity=Severity.INFO,
    )

    results = FindingCorrelator().correlate([unverified_xss, mitigated_csp])

    assert results == [unverified_xss, mitigated_csp]


def test_missing_browser_security_headers_collapse_into_one_correlated_finding():
    hsts = _finding(
        plugin_id="PASS-001",
        title="Missing Strict-Transport-Security (HSTS) Header",
        severity=Severity.LOW,
        endpoint="https://scanner.test/",
        evidence=[Evidence(type="missing_header", description="HSTS missing", data={"missing_header": "strict-transport-security"})],
    )
    xfo = _finding(
        plugin_id="PASS-001",
        title="Missing Anti-Clickjacking Headers",
        severity=Severity.LOW,
        endpoint="https://scanner.test/",
        evidence=[Evidence(type="missing_header", description="XFO missing", data={"missing_header": "x-frame-options"})],
    )
    csp = _finding(
        plugin_id="PASS-006",
        title="Missing Content-Security-Policy Header",
        severity=Severity.LOW,
        endpoint="https://scanner.test/",
        evidence=[Evidence(type="missing_csp", description="CSP missing", data={"header": "content-security-policy"})],
    )
    unrelated = _finding(
        plugin_id="PASS-002",
        title="Insecure Cookie Configuration: sid",
        endpoint="https://scanner.test/",
    )

    results = FindingCorrelator().correlate([hsts, xfo, csp, unrelated])

    assert len(results) == 2
    correlated = next(f for f in results if f.plugin_id == FindingCorrelator.BROWSER_SECURITY_RULE_ID)
    assert correlated.title == "Weak Browser Security Configuration"
    assert correlated.confidence == Confidence.HIGH
    assert correlated.merge_count == 3
    assert correlated.evidence[0].data["correlation_rule"] == FindingCorrelator.BROWSER_SECURITY_RULE_ID
    assert len(correlated.evidence[0].data["supporting_findings"]) == 3
    assert any(f.plugin_id == "PASS-002" for f in results)


def test_single_missing_header_is_not_correlated():
    hsts = _finding(
        plugin_id="PASS-001",
        title="Missing Strict-Transport-Security (HSTS) Header",
        severity=Severity.LOW,
        endpoint="https://scanner.test/",
    )

    results = FindingCorrelator().correlate([hsts])

    assert results == [hsts]


def test_attack_chain_collapses_xss_csp_and_session_cookie_into_one():
    xss = _finding(
        plugin_id="ACT-XSS-001",
        title="Verified reflected XSS",
        severity=Severity.HIGH,
        endpoint="https://scanner.test/search",
        is_verified=True,
        verification_status=VerificationStatus.VERIFIED,
        intelligence=VulnerabilityIntelligence(cwe_id="CWE-79"),
    )
    missing_csp = _finding(
        plugin_id="PASS-006",
        title="Missing Content-Security-Policy Header",
        severity=Severity.LOW,
        endpoint="https://scanner.test/",
    )
    session_cookie = _finding(
        plugin_id="PASS-002",
        title="Cookie Security Configuration: sessionid",
        severity=Severity.HIGH,
        endpoint="https://scanner.test/",
        evidence=[Evidence(
            type="cookie_security_context",
            description="Insecure session cookie",
            data={
                "detection_evidence": {
                    "observation": {"cookie_type": "session", "missing_attributes": ["Secure", "HttpOnly"]}
                }
            },
        )],
    )

    results = FindingCorrelator().correlate([xss, missing_csp, session_cookie])

    assert len(results) == 1
    attack_chain = results[0]
    assert attack_chain.plugin_id == FindingCorrelator.ATTACK_CHAIN_RULE_ID
    assert attack_chain.title == "Session Theft via XSS enabled by Weak Content Security Policy"
    assert attack_chain.severity == Severity.CRITICAL
    assert attack_chain.is_verified is True
    assert attack_chain.merge_count == 3
    assert attack_chain.evidence[0].data["correlation_rule"] == FindingCorrelator.ATTACK_CHAIN_RULE_ID
    assert "chain" in attack_chain.evidence[0].data
    assert len(attack_chain.evidence[0].data["supporting_findings"]) == 3


def test_attack_chain_does_not_trigger_without_session_cookie():
    xss = _finding(
        plugin_id="ACT-XSS-001",
        title="Verified reflected XSS",
        severity=Severity.HIGH,
        endpoint="https://scanner.test/search",
        is_verified=True,
        verification_status=VerificationStatus.VERIFIED,
        intelligence=VulnerabilityIntelligence(cwe_id="CWE-79"),
    )
    missing_csp = _finding(
        plugin_id="PASS-006",
        title="Missing Content-Security-Policy Header",
        severity=Severity.LOW,
        endpoint="https://scanner.test/",
    )

    results = FindingCorrelator().correlate([xss, missing_csp])

    assert len(results) == 1
    assert results[0].plugin_id == FindingCorrelator.RULE_ID
