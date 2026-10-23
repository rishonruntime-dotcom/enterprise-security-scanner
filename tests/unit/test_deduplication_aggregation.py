import asyncio

from scanner.correlation.pipeline import FindingPipeline
from scanner.correlation.models import EnrichedFinding
from scanner.models.finding import Confidence, Evidence, Severity


def _finding(plugin_id: str, title: str, endpoint: str) -> EnrichedFinding:
    return EnrichedFinding(
        plugin_id=plugin_id,
        title=title,
        description="Security header is absent.",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        endpoint=endpoint,
        evidence=[Evidence(type="missing_header", description="HSTS is absent", data={"missing_header": "HSTS"})],
    )


def test_passive_findings_are_aggregated_with_an_affected_endpoint_inventory():
    findings = [
        _finding("PASS-001", "Missing Strict-Transport-Security (HSTS) Header", "https://example.test/"),
        _finding("PASS-001", "Missing Strict-Transport-Security (HSTS) Header", "https://example.test/account"),
        _finding("PASS-001", "Missing Strict-Transport-Security (HSTS) Header", "https://example.test/search?q=test"),
    ]

    results = asyncio.run(FindingPipeline().process(findings, scan_id="scan-dedup"))

    assert len(results) == 1
    aggregated = results[0]
    assert aggregated.merge_count == 3
    assert aggregated.affected_endpoints == [
        "https://example.test/",
        "https://example.test/account",
        "https://example.test/search?q=test",
    ]
    assert aggregated.evidence[0].data["affected_endpoint_count"] == 3


def test_active_findings_remain_distinct_per_endpoint():
    findings = [
        _finding("ACT-XSS-001", "Potential XSS in 'q'", "https://example.test/search?q=test"),
        _finding("ACT-XSS-001", "Potential XSS in 'q'", "https://example.test/products?q=test"),
    ]

    results = asyncio.run(FindingPipeline().process(findings, scan_id="scan-active"))

    assert len(results) == 2
