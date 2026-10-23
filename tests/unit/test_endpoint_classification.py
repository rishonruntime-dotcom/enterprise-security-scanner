import asyncio
from datetime import datetime
from pathlib import Path

import pytest

from scanner.classification.classifier import EndpointClassifier
from scanner.classification.models import EndpointClass
from scanner.correlation.pipeline import FindingPipeline
from scanner.correlation.verification import EvidenceVerificationStep
from scanner.crawler.models import Endpoint
from scanner.models.finding import Confidence, Evidence, Severity
from scanner.passive.models import PassiveObservation
from scanner.api.routes.findings import FindingResponse
from scanner.correlation.models import EnrichedFinding
from scanner.reporting.exporters import MarkdownExporter
from scanner.reporting.models import Report


def test_discovered_endpoint_is_classified_with_input_context():
    endpoint = Endpoint(
        method="POST",
        url="https://example.test/account/signin",
        parameters={"username": "", "password": ""},
    )

    assert endpoint.endpoint_class == EndpointClass.AUTHENTICATION.value
    assert endpoint.classification_confidence >= 0.9
    assert endpoint.classification_reason == "authentication route or credential form"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.test/api/v1/orders", EndpointClass.API),
        ("https://example.test/assets/app.js", EndpointClass.STATIC_ASSETS),
        ("https://example.test/media/banner.webp", EndpointClass.MEDIA),
        ("https://example.test/download/export.csv", EndpointClass.DOWNLOAD),
        ("https://example.test/catalog", EndpointClass.MAIN_APP),
    ],
)
def test_classifier_uses_path_segments_and_extensions(url, expected):
    classification = EndpointClassifier.classify_endpoint(url)

    assert classification.endpoint_class == expected


def test_endpoint_class_is_stored_on_pipeline_finding_and_only_generic_passive_is_downgraded():
    passive = PassiveObservation(
        plugin_id="PASS-HEADER-001",
        observation_type="missing_header",
        title="Missing security header",
        description="Header was not present.",
        severity=Severity.MEDIUM,
        endpoint="https://example.test/assets/app.js",
        evidence=[Evidence(type="header", description="header absent", data={})],
    )
    result = asyncio.run(FindingPipeline(steps=[EvidenceVerificationStep()]).process(passive))

    assert result is not None
    assert result.endpoint_class == EndpointClass.STATIC_ASSETS.value
    assert result.severity == Severity.LOW

    # Endpoint class must not reduce an actively verified/exploitable issue.
    assert EndpointClassifier.adjust_severity(
        Severity.MEDIUM,
        EndpointClass.STATIC_ASSETS,
        plugin_id="ACT-XSS-001",
        is_passive=False,
    ) == Severity.MEDIUM

    # original_severity should preserve the pre-adjustment severity
    assert result.original_severity == Severity.MEDIUM


def test_endpoint_class_is_available_in_api_and_markdown_report():
    import tempfile
    finding = EnrichedFinding(
        plugin_id="ACT-API-001",
        title="API finding",
        description="Test finding",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        endpoint="https://example.test/api/v1/users",
        endpoint_class=EndpointClass.API.value,
    )
    api_finding = FindingResponse.model_validate({
        "id": "finding-1",
        "scan_id": "scan-1",
        "plugin_id": finding.plugin_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "endpoint": finding.endpoint,
        "endpoint_class": finding.endpoint_class,
        "cwe_id": None,
        "cvss_score": None,
        "priority_score": None,
        "is_verified": False,
        "created_at": datetime.now(),
    })
    assert api_finding.endpoint_class == EndpointClass.API.value

    template_dir = Path(__file__).parents[2] / "src" / "scanner" / "reporting" / "templates"
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = asyncio.run(MarkdownExporter(str(template_dir)).export(Report(findings=[finding]), tmp_dir))
        assert "**Endpoint Class:** API" in Path(output_path).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.test/api/v1/orders", EndpointClass.API),
        ("https://example.test/assets/app.js", EndpointClass.STATIC_ASSETS),
        ("https://example.test/media/banner.webp", EndpointClass.MEDIA),
        ("https://example.test/download/export.csv", EndpointClass.DOWNLOAD),
        ("https://example.test/catalog", EndpointClass.MAIN_APP),
        ("https://example.test/checkout/payment", EndpointClass.CHECKOUT),
        ("https://example.test/upload/document", EndpointClass.UPLOAD),
        ("https://example.test/admin/users", EndpointClass.ADMIN),
        ("https://example.test/sysadmin/control-panel", EndpointClass.ADMIN_PORTAL),
        ("https://example.test/stripe/payment-gateway", EndpointClass.PAYMENT_GATEWAY),
        ("https://example.test/sso/oidc/identity", EndpointClass.IDENTITY),
        ("https://example.test/customer-data/pii/vault", EndpointClass.CUSTOMER_DATA),
    ],
)
def test_classifier_detects_all_endpoint_classes(url, expected):
    classification = EndpointClassifier.classify_endpoint(url)
    assert classification.endpoint_class == expected


@pytest.mark.parametrize(
    ("endpoint_class", "severity", "expected"),
    [
        (EndpointClass.AUTHENTICATION, Severity.LOW, Severity.MEDIUM),
        (EndpointClass.AUTHENTICATION, Severity.MEDIUM, Severity.HIGH),
        (EndpointClass.AUTHENTICATION, Severity.HIGH, Severity.CRITICAL),
        (EndpointClass.AUTHENTICATION, Severity.CRITICAL, Severity.CRITICAL),
        (EndpointClass.AUTHENTICATION, Severity.INFO, Severity.INFO),
        (EndpointClass.ADMIN, Severity.LOW, Severity.MEDIUM),
        (EndpointClass.ADMIN, Severity.MEDIUM, Severity.HIGH),
        (EndpointClass.ADMIN, Severity.HIGH, Severity.CRITICAL),
        (EndpointClass.PAYMENT, Severity.LOW, Severity.MEDIUM),
        (EndpointClass.PAYMENT, Severity.MEDIUM, Severity.HIGH),
        (EndpointClass.PAYMENT, Severity.HIGH, Severity.CRITICAL),
        (EndpointClass.API, Severity.MEDIUM, Severity.HIGH),
        (EndpointClass.API, Severity.LOW, Severity.LOW),
        (EndpointClass.UPLOAD, Severity.LOW, Severity.MEDIUM),
        (EndpointClass.UPLOAD, Severity.MEDIUM, Severity.HIGH),
        (EndpointClass.UPLOAD, Severity.HIGH, Severity.HIGH),
        (EndpointClass.MAIN_APP, Severity.MEDIUM, Severity.MEDIUM),
        (EndpointClass.MAIN_APP, Severity.LOW, Severity.LOW),
    ],
)
def test_adjust_severity_by_asset_criticality(endpoint_class, severity, expected):
    assert EndpointClassifier.adjust_severity(severity, endpoint_class) == expected


def test_auth_endpoint_escalates_passive_finding():
    """A passively detected missing HSTS on a login page is escalated relative to static assets."""
    login_result = EndpointClassifier.adjust_severity(
        Severity.LOW, EndpointClass.AUTHENTICATION,
        plugin_id="PASS-001", is_passive=True,
    )
    static_result = EndpointClassifier.adjust_severity(
        Severity.LOW, EndpointClass.STATIC_ASSETS,
        plugin_id="PASS-001", is_passive=True,
    )
    assert login_result == Severity.MEDIUM
    assert static_result == Severity.INFO
    assert login_result.value != static_result.value
