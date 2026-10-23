import asyncio

from scanner.correlation.pipeline import FindingPipeline
from scanner.correlation.severity_context import ContextualSeverityStep
from scanner.correlation.models import EnrichedFinding
from scanner.models.finding import Confidence, DetectionMethod, Evidence, Severity
from scanner.risk.engine import RiskEngine


def _finding(**overrides) -> EnrichedFinding:
    values = {
        "plugin_id": "PASS-001-CSP-SCRIPT-INLINE",
        "title": "CSP Directive Misconfiguration: Unrestricted 'script-src' Allows 'unsafe-inline'",
        "description": "Weak CSP.",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "confidence_score": 0.8,
        "endpoint": "https://example.test/",
        "endpoint_class": "Main Application",
        "detection_method": DetectionMethod.PASSIVE,
        "evidence": [Evidence(type="csp_directive", description="unsafe-inline", data={})],
    }
    values.update(overrides)
    return EnrichedFinding(**values)


def test_mission_critical_asset_elevates_material_csp_weakness_and_recalculates_risk():
    finding = _finding()
    pipeline = FindingPipeline(severity_context_step=ContextualSeverityStep(RiskEngine()))

    result = asyncio.run(pipeline.process([finding], severity_context={"asset_criticality": "MissionCritical"}))

    assert result[0].severity == Severity.HIGH
    assert result[0].risk is not None
    assert result[0].risk.cvss.base_score == 8.8


def test_generic_passive_finding_on_static_asset_is_informational():
    finding = _finding(endpoint="https://example.test/assets/app.js", endpoint_class="Static Assets")
    pipeline = FindingPipeline(severity_context_step=ContextualSeverityStep(RiskEngine()))

    result = asyncio.run(pipeline.process([finding], severity_context={"asset_criticality": "MissionCritical"}))

    assert result[0].severity == Severity.INFO
    assert result[0].risk.cvss.base_score == 0.0


def test_active_findings_are_not_downgraded_for_static_endpoint_context():
    finding = _finding(
        plugin_id="ACT-XSS-001",
        title="Verified reflected XSS",
        severity=Severity.HIGH,
        endpoint_class="Static Assets",
        detection_method=DetectionMethod.ACTIVE,
    )

    result = asyncio.run(FindingPipeline(severity_context_step=ContextualSeverityStep()).process([finding]))

    assert result[0].severity == Severity.HIGH
