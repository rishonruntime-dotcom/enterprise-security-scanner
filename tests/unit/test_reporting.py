import json
import os
import tempfile
import pytest

from scanner.models.finding import Severity, Confidence
from scanner.correlation.models import EnrichedFinding, VulnerabilityIntelligence
from scanner.reporting.models import Report, ReportMetadata, ScanSummary, ReportIntelligence, AssetCriticalitySummary, DiscoveryQualityMetrics
from scanner.reporting.exporters import JSONExporter, SARIFExporter, MarkdownExporter, HTMLExporter
from scanner.reporting.manager import ReportManager

@pytest.mark.asyncio
async def test_json_exporter():
    f1 = EnrichedFinding(
        plugin_id="TEST-01", title="Test JSON", description="Desc", severity=Severity.HIGH, confidence=Confidence.HIGH, endpoint="https://example.com",
        intelligence=VulnerabilityIntelligence(cwe_id="CWE-79")
    )
    
    report = Report(
        metadata=ReportMetadata(target_urls=["https://example.com"]),
        summary=ScanSummary(total_findings=1, high_count=1),
        findings=[f1]
    )
    
    exporter = JSONExporter()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = await exporter.export(report, tmpdir)
        
        assert os.path.exists(path)
        with open(path, "r") as f:
            data = json.load(f)
            
        assert data["summary"]["total_findings"] == 1
        assert data["findings"][0]["title"] == "Test JSON"

@pytest.mark.asyncio
async def test_sarif_exporter():
    f1 = EnrichedFinding(
        plugin_id="TEST-01", title="Test SARIF", description="Desc", severity=Severity.HIGH, confidence=Confidence.HIGH, endpoint="https://example.com",
        intelligence=VulnerabilityIntelligence(cwe_id="CWE-79")
    )
    
    report = Report(
        metadata=ReportMetadata(target_urls=["https://example.com"]),
        summary=ScanSummary(total_findings=1, high_count=1),
        findings=[f1]
    )
    
    exporter = SARIFExporter()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = await exporter.export(report, tmpdir)
        
        assert os.path.exists(path)
        with open(path, "r") as f:
            data = json.load(f)
            
        assert data["version"] == "2.1.0"
        runs = data["runs"]
        assert len(runs) == 1
        results = runs[0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "TEST-01"
        assert results[0]["level"] == "error"

@pytest.mark.asyncio
async def test_report_intelligence_computed():
    f1 = EnrichedFinding(
        plugin_id="TEST-01", title="Critical Issue", description="Desc", severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        endpoint="https://example.com/admin", endpoint_class="Admin",
        intelligence=VulnerabilityIntelligence(cwe_id="CWE-79"), is_verified=True
    )
    f2 = EnrichedFinding(
        plugin_id="TEST-02", title="Medium Issue", description="Desc", severity=Severity.MEDIUM, confidence=Confidence.LOW,
        endpoint="https://example.com/api", endpoint_class="API",
        intelligence=VulnerabilityIntelligence(cwe_id="CWE-89")
    )

    manager = ReportManager(exporters={}, output_dir="/tmp")
    intelligence = manager._compute_intelligence(
        findings=[f1, f2],
        target_urls=["https://example.com"],
        summary=ScanSummary(total_findings=2, critical_count=1, high_count=0, medium_count=1, low_count=0, info_count=0,
                           confidence_high_count=1, confidence_medium_count=0, confidence_low_count=1,
                           verified_count=1, unverified_count=1),
        stats={"technologies": []},
        scan_obj=None
    )

    assert intelligence.overall_security_score >= 0.0
    assert intelligence.overall_security_score <= 100.0
    assert len(intelligence.executive_recommendations) > 0
    assert len(intelligence.most_critical_assets) > 0
    assert len(intelligence.findings_by_asset) == 2
    assert len(intelligence.findings_by_technology) >= 1
    assert intelligence.confidence_distribution["High"] == 1
    assert intelligence.confidence_distribution["Low"] == 1
    assert intelligence.verified_vs_unverified["verified"] == 1
    assert intelligence.verified_vs_unverified["unverified"] == 1

@pytest.mark.asyncio
async def test_json_exporter_includes_intelligence():
    f1 = EnrichedFinding(
        plugin_id="TEST-01", title="Test", description="Desc", severity=Severity.HIGH, confidence=Confidence.HIGH,
        endpoint="https://example.com", intelligence=VulnerabilityIntelligence(cwe_id="CWE-79")
    )
    
    report = Report(
        metadata=ReportMetadata(target_urls=["https://example.com"]),
        summary=ScanSummary(total_findings=1, high_count=1, false_positive_probability=15.0),
        findings=[f1],
        intelligence=ReportIntelligence(
            overall_security_score=75.5,
            executive_recommendations=["Fix critical issues"],
            confidence_distribution={"High": 1, "Medium": 0, "Low": 0},
            verified_vs_unverified={"verified": 0, "unverified": 1}
        )
    )
    
    exporter = JSONExporter()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = await exporter.export(report, tmpdir)
        with open(path, "r") as f:
            data = json.load(f)
        
        assert "intelligence" in data
        assert data["intelligence"]["overall_security_score"] == 75.5
        assert "executive_recommendations" in data["intelligence"]
        assert data["summary"]["false_positive_probability"] == 15.0

@pytest.mark.asyncio
async def test_markdown_exporter_renders_intelligence():
    template_dir = os.path.join(os.path.dirname(__file__), "..", "..", "src", "scanner", "reporting", "templates")
    exporter = MarkdownExporter(template_dir=template_dir)
    
    f1 = EnrichedFinding(
        plugin_id="TEST-01", title="Test", description="Desc", severity=Severity.HIGH, confidence=Confidence.HIGH,
        endpoint="https://example.com", intelligence=VulnerabilityIntelligence(cwe_id="CWE-79")
    )
    
    report = Report(
        metadata=ReportMetadata(target_urls=["https://example.com"]),
        summary=ScanSummary(total_findings=1, high_count=1, false_positive_probability=10.0),
        findings=[f1],
        intelligence=ReportIntelligence(
            overall_security_score=85.0,
            attack_surface_summary={"total_endpoints": 10, "total_forms": 2, "total_parameters": 25, "total_pages": 5, "browser_routes": 3, "targets": 1},
            most_critical_assets=[AssetCriticalitySummary(target_url="https://example.com/admin", finding_count=1, critical_count=1, high_count=0, risk_score=9.0)],
            executive_recommendations=["Recommendation 1", "Recommendation 2"],
            findings_by_asset=[],
            findings_by_technology=[],
            confidence_distribution={"High": 1, "Medium": 0, "Low": 0},
            verified_vs_unverified={"verified": 0, "unverified": 1}
        )
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        path = await exporter.export(report, tmpdir)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        
        assert "Overall Security Score" in content
        assert "85.0" in content
        assert "Attack Surface Summary" in content
        assert "Most Critical Assets" in content
        assert "Executive Recommendations" in content
        assert "Recommendation 1" in content
        assert "Confidence Distribution" in content
        assert "Verified vs Unverified" in content
        assert "False Positive Probability" in content

@pytest.mark.asyncio
async def test_html_exporter_renders_intelligence():
    template_dir = os.path.join(os.path.dirname(__file__), "..", "..", "src", "scanner", "reporting", "templates")
    exporter = HTMLExporter(template_dir=template_dir)
    
    f1 = EnrichedFinding(
        plugin_id="TEST-01", title="Test", description="Desc", severity=Severity.HIGH, confidence=Confidence.HIGH,
        endpoint="https://example.com", intelligence=VulnerabilityIntelligence(cwe_id="CWE-79")
    )
    
    report = Report(
        metadata=ReportMetadata(target_urls=["https://example.com"]),
        summary=ScanSummary(total_findings=1, high_count=1, false_positive_probability=10.0),
        findings=[f1],
        intelligence=ReportIntelligence(
            overall_security_score=85.0,
            attack_surface_summary={"total_endpoints": 10, "total_forms": 2, "total_parameters": 25, "total_pages": 5, "browser_routes": 3, "targets": 1},
            most_critical_assets=[AssetCriticalitySummary(target_url="https://example.com/admin", finding_count=1, critical_count=1, high_count=0, risk_score=9.0)],
            executive_recommendations=["Recommendation 1"],
            findings_by_asset=[],
            findings_by_technology=[],
            confidence_distribution={"High": 1, "Medium": 0, "Low": 0},
            verified_vs_unverified={"verified": 0, "unverified": 1}
        )
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        path = await exporter.export(report, tmpdir)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        
        assert "Report Intelligence Overview" in content
        assert "85.0" in content
        assert "Attack Surface Summary" in content
        assert "Most Critical Assets" in content
        assert "Executive Recommendations" in content
        assert "Recommendation 1" in content
        assert "Confidence" in content
        assert "Verified" in content
        assert "False Positive Probability" in content

class TestAssetClassifier:
    """Test asset classification logic."""

    def test_first_party_same_domain(self):
        from scanner.classification.classifier import AssetClassifier
        result = AssetClassifier.classify("https://example.com/admin", primary_domain="example.com")
        assert result.asset_category.value == "First-party"

    def test_cdn_domain(self):
        from scanner.classification.classifier import AssetClassifier
        result = AssetClassifier.classify("https://cdn.jsdelivr.net/npm/lib")
        assert result.asset_category.value == "CDN"

    def test_analytics_domain(self):
        from scanner.classification.classifier import AssetClassifier
        result = AssetClassifier.classify("https://analytics.google.com/collect")
        assert result.asset_category.value == "Analytics"

    def test_oauth_domain(self):
        from scanner.classification.classifier import AssetClassifier
        result = AssetClassifier.classify("https://accounts.google.com/o/oauth2/v2/auth")
        assert result.asset_category.value == "OAuth"

    def test_payment_domain(self):
        from scanner.classification.classifier import AssetClassifier
        result = AssetClassifier.classify("https://js.stripe.com/v3/")
        assert result.asset_category.value == "Payment"

    def test_embedded_widget_path(self):
        from scanner.classification.classifier import AssetClassifier
        result = AssetClassifier.classify("https://example.com/embed/chat-widget")
        assert result.asset_category.value == "Embedded Widgets"

    def test_third_party_external(self):
        from scanner.classification.classifier import AssetClassifier
        result = AssetClassifier.classify("https://external-site.com/page", primary_domain="example.com")
        assert result.asset_category.value == "Third-party"

    def test_first_party_subdomain(self):
        from scanner.classification.classifier import AssetClassifier
        result = AssetClassifier.classify("https://app.example.com/dashboard", primary_domain="example.com")
        assert result.asset_category.value == "First-party"

@pytest.mark.asyncio
async def test_report_intelligence_includes_asset_category():
    f1 = EnrichedFinding(
        plugin_id="TEST-01", title="CDN Issue", description="Desc", severity=Severity.HIGH, confidence=Confidence.HIGH,
        endpoint="https://cdn.jsdelivr.net/npm/lib", asset_category="CDN"
    )
    f2 = EnrichedFinding(
        plugin_id="TEST-02", title="First-party Issue", description="Desc", severity=Severity.MEDIUM, confidence=Confidence.LOW,
        endpoint="https://example.com/api", asset_category="First-party"
    )

    manager = ReportManager(exporters={}, output_dir="/tmp")
    intelligence = manager._compute_intelligence(
        findings=[f1, f2],
        target_urls=["https://example.com"],
        summary=ScanSummary(total_findings=2, critical_count=0, high_count=1, medium_count=1, low_count=0, info_count=0),
        stats={"technologies": []},
        scan_obj=None
    )

    assert len(intelligence.findings_by_asset_category) == 2
    cats = {cat.asset_category: cat.findings for cat in intelligence.findings_by_asset_category}
    assert "CDN" in cats
    assert "First-party" in cats
    assert len(cats["CDN"]) == 1
    assert len(cats["First-party"]) == 1

@pytest.mark.asyncio
async def test_markdown_exporter_renders_asset_category():
    template_dir = os.path.join(os.path.dirname(__file__), "..", "..", "src", "scanner", "reporting", "templates")
    exporter = MarkdownExporter(template_dir=template_dir)
    
    f1 = EnrichedFinding(
        plugin_id="TEST-01", title="Test", description="Desc", severity=Severity.HIGH, confidence=Confidence.HIGH,
        endpoint="https://cdn.jsdelivr.net/lib", asset_category="CDN",
        intelligence=VulnerabilityIntelligence(cwe_id="CWE-79")
    )
    
    report = Report(
        metadata=ReportMetadata(target_urls=["https://example.com"]),
        summary=ScanSummary(total_findings=1, high_count=1),
        findings=[f1],
        intelligence=ReportIntelligence(
            findings_by_asset_category=[{"asset_category": "CDN", "findings": [{"severity": "High"}]}]
        )
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        path = await exporter.export(report, tmpdir)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        
        assert "Asset Category:** CDN" in content
        assert "Findings by Asset Category" in content

@pytest.mark.asyncio
async def test_html_exporter_renders_asset_category():
    template_dir = os.path.join(os.path.dirname(__file__), "..", "..", "src", "scanner", "reporting", "templates")
    exporter = HTMLExporter(template_dir=template_dir)
    
    f1 = EnrichedFinding(
        plugin_id="TEST-01", title="Test", description="Desc", severity=Severity.HIGH, confidence=Confidence.HIGH,
        endpoint="https://cdn.jsdelivr.net/lib", asset_category="CDN",
        intelligence=VulnerabilityIntelligence(cwe_id="CWE-79")
    )
    
    report = Report(
        metadata=ReportMetadata(target_urls=["https://example.com"]),
        summary=ScanSummary(total_findings=1, high_count=1),
        findings=[f1],
        intelligence=ReportIntelligence(
            findings_by_asset_category=[{"asset_category": "CDN", "findings": [{"severity": "High"}]}]
        )
    )
    
    with tempfile.TemporaryDirectory() as tmpdir:
        path = await exporter.export(report, tmpdir)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        
        assert "Asset Category:</strong>" in content
        assert "CDN" in content
        assert "Findings by Asset Category" in content

class TestTechnologyDeduplication:
    """Test technology deduplication in reports."""

    def test_deduplicate_technologies_merges_duplicates(self):
        manager = ReportManager(exporters={}, output_dir="/tmp")
        techs = [
            {"name": "React", "category": "JavaScript Framework", "version": "18.0.0", "confidence": 95},
            {"name": "React", "category": "JavaScript Framework", "version": "18.0.0", "confidence": 90},
            {"name": "React", "category": "JavaScript Framework", "version": "17.0.0", "confidence": 85},
        ]
        result = manager._deduplicate_technologies(techs)
        assert len(result) == 1
        assert result[0]["name"] == "React"
        assert result[0]["confidence"] == 95
        assert result[0]["version"] == "18.0.0"
        assert result[0]["detected_on_endpoints"] == 3

    def test_deduplicate_technologies_preserves_unique(self):
        manager = ReportManager(exporters={}, output_dir="/tmp")
        techs = [
            {"name": "React", "category": "JavaScript Framework", "confidence": 95},
            {"name": "Angular", "category": "JavaScript Framework", "confidence": 90},
        ]
        result = manager._deduplicate_technologies(techs)
        assert len(result) == 2
        names = {t["name"] for t in result}
        assert names == {"React", "Angular"}

    def test_deduplicate_technologies_upgrades_category(self):
        manager = ReportManager(exporters={}, output_dir="/tmp")
        techs = [
            {"name": "React", "category": "General", "confidence": 90},
            {"name": "React", "category": "JavaScript Framework", "confidence": 95},
        ]
        result = manager._deduplicate_technologies(techs)
        assert result[0]["category"] == "JavaScript Framework"

    def test_deduplicate_technologies_empty_input(self):
        manager = ReportManager(exporters={}, output_dir="/tmp")
        result = manager._deduplicate_technologies([])
        assert result == []

    def test_deduplicate_technologies_dict_and_object_mix(self):
        manager = ReportManager(exporters={}, output_dir="/tmp")
        techs = [
            {"name": "React", "category": "JavaScript Framework", "confidence": 90},
            type("Tech", (), {"name": "React", "category": "JavaScript Framework", "version": "18.0.0", "confidence": 95})(),
        ]
        result = manager._deduplicate_technologies(techs)
        assert len(result) == 1
        assert result[0]["name"] == "React"
        assert result[0]["confidence"] == 95

    @pytest.mark.asyncio
    async def test_generate_report_deduplicates_technologies(self):
        manager = ReportManager(exporters={"json": JSONExporter()}, output_dir="/tmp")
        
        techs = [
            {"name": "React", "category": "JavaScript Framework", "version": "18.0.0", "confidence": 95},
            {"name": "React", "category": "JavaScript Framework", "version": "18.0.0", "confidence": 90},
            {"name": "Nginx", "category": "Web Server", "version": "1.20.0", "confidence": 100},
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_paths = await manager.generate_report(
                findings=[],
                formats=["json"],
                target_urls=["https://example.com"],
                technologies=techs,
                stats={},
                scan_obj=None
            )
            path = output_paths["json"]
            with open(path, "r") as f:
                data = json.load(f)
            
            assert len(data["technologies"]) == 2
            tech_names = {t["name"] for t in data["technologies"]}
            assert tech_names == {"React", "Nginx"}
            react = next(t for t in data["technologies"] if t["name"] == "React")
            assert react["detected_on_endpoints"] == 2

    @pytest.mark.asyncio
    async def test_generate_report_attack_surface_uses_deduped_tech_count(self):
        manager = ReportManager(exporters={"json": JSONExporter()}, output_dir="/tmp")
        
        techs = [
            {"name": "React", "category": "JavaScript Framework", "confidence": 95},
            {"name": "React", "category": "JavaScript Framework", "confidence": 90},
            {"name": "React", "category": "JavaScript Framework", "confidence": 85},
        ]
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_paths = await manager.generate_report(
                findings=[],
                formats=["json"],
                target_urls=["https://example.com"],
                technologies=techs,
                stats={},
                scan_obj=None
            )
            path = output_paths["json"]
            with open(path, "r") as f:
                data = json.load(f)
            
            assert data["intelligence"]["attack_surface_summary"]["technologies"] == 1
    """Test explainability fields on findings and report rendering."""

    @pytest.mark.asyncio
    async def test_markdown_exporter_renders_explainability(self):
        template_dir = os.path.join(os.path.dirname(__file__), "..", "..", "src", "scanner", "reporting", "templates")
        exporter = MarkdownExporter(template_dir=template_dir)
        
        f1 = EnrichedFinding(
            plugin_id="TEST-01", title="SQL Injection", description="Desc", severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            endpoint="https://example.com/search", intelligence=VulnerabilityIntelligence(cwe_id="CWE-89"),
            why_detected="Error-based SQLi pattern matched in response.",
            how_verified="Active verification: error-based technique with retry stability checks.",
            severity_reason="Critical severity because SQL injection enables complete database compromise.",
            false_positive_reasons=["Application may return custom error pages.", "Cached response may have been served."]
        )
        
        report = Report(
            metadata=ReportMetadata(target_urls=["https://example.com"]),
            summary=ScanSummary(total_findings=1, critical_count=1),
            findings=[f1]
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = await exporter.export(report, tmpdir)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            
            assert "Scanner Explainability" in content
            assert "Why Detected" in content
            assert "How Verified" in content
            assert "Why Severity Assigned" in content
            assert "Possible False-Positive Reasons" in content
            assert "complete database compromise" in content

    @pytest.mark.asyncio
    async def test_html_exporter_renders_explainability(self):
        template_dir = os.path.join(os.path.dirname(__file__), "..", "..", "src", "scanner", "reporting", "templates")
        exporter = HTMLExporter(template_dir=template_dir)
        
        f1 = EnrichedFinding(
            plugin_id="TEST-01", title="SQL Injection", description="Desc", severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            endpoint="https://example.com/search", intelligence=VulnerabilityIntelligence(cwe_id="CWE-89"),
            why_detected="Error-based SQLi pattern matched in response.",
            how_verified="Active verification: error-based technique with retry stability checks.",
            severity_reason="Critical severity because SQL injection enables complete database compromise.",
            false_positive_reasons=["Application may return custom error pages.", "Cached response may have been served."]
        )
        
        report = Report(
            metadata=ReportMetadata(target_urls=["https://example.com"]),
            summary=ScanSummary(total_findings=1, critical_count=1),
            findings=[f1]
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = await exporter.export(report, tmpdir)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            
            assert "Scanner Explainability" in content
            assert "Why Detected" in content
            assert "How Verified" in content
            assert "Why Severity Assigned" in content
            assert "Possible False-Positive Reasons" in content
            assert "complete database compromise" in content

    def test_finding_model_has_explainability_fields(self):
        from scanner.models.finding import Finding
        f = Finding(
            plugin_id="TEST", title="Test", description="Desc", severity=Severity.HIGH, confidence=Confidence.HIGH,
            endpoint="https://example.com",
            why_detected="Reason",
            how_verified="Active",
            severity_reason="High because...",
            false_positive_reasons=["Reason 1"]
        )
        assert f.why_detected == "Reason"
        assert f.how_verified == "Active"
        assert f.severity_reason == "High because..."
        assert f.false_positive_reasons == ["Reason 1"]

class TestDiscoveryQualityMetrics:
    """Test discovery quality metrics computation and rendering."""

    @pytest.mark.asyncio
    async def test_discovery_quality_computed(self):
        from scanner.reporting.models import DiscoveryQualityMetrics
        f1 = EnrichedFinding(
            plugin_id="TEST-01", title="API Issue", description="Desc", severity=Severity.HIGH, confidence=Confidence.HIGH,
            endpoint="https://example.com/api/v1/users", endpoint_class="API", asset_category="First-party",
            intelligence=VulnerabilityIntelligence(cwe_id="CWE-89")
        )
        f2 = EnrichedFinding(
            plugin_id="TEST-02", title="Auth Issue", description="Desc", severity=Severity.MEDIUM, confidence=Confidence.LOW,
            endpoint="https://example.com/login", endpoint_class="Authentication", asset_category="First-party",
            intelligence=VulnerabilityIntelligence(cwe_id="CWE-79")
        )

        manager = ReportManager(exporters={}, output_dir="/tmp")
        intelligence = manager._compute_intelligence(
            findings=[f1, f2],
            target_urls=["https://example.com"],
            summary=ScanSummary(total_findings=2, endpoints_discovered=10, forms_discovered=2),
            stats={
                "javascript_files_analyzed": 3,
                "assets_skipped": 5,
                "third_party_assets": 2,
                "spa_routes": ["/app"],
                "openapi_specs": ["/openapi.json"],
                "manifest_urls": ["/manifest.json"],
            },
            scan_obj=None
        )

        assert intelligence.discovery_quality is not None
        assert intelligence.discovery_quality.apis_discovered == 1
        assert intelligence.discovery_quality.auth_endpoints == 1
        assert intelligence.discovery_quality.javascript_files_analyzed == 3
        assert intelligence.discovery_quality.assets_skipped == 5
        assert intelligence.discovery_quality.third_party_assets == 2
        assert intelligence.discovery_quality.hidden_endpoints == 3

    @pytest.mark.asyncio
    async def test_markdown_exporter_renders_discovery_quality(self):
        template_dir = os.path.join(os.path.dirname(__file__), "..", "..", "src", "scanner", "reporting", "templates")
        exporter = MarkdownExporter(template_dir=template_dir)
        
        f1 = EnrichedFinding(
            plugin_id="TEST-01", title="Test", description="Desc", severity=Severity.HIGH, confidence=Confidence.HIGH,
            endpoint="https://example.com/api", endpoint_class="API",
            intelligence=VulnerabilityIntelligence(cwe_id="CWE-79")
        )
        
        report = Report(
            metadata=ReportMetadata(target_urls=["https://example.com"]),
            summary=ScanSummary(total_findings=1, high_count=1, endpoints_discovered=10, forms_discovered=2),
            findings=[f1],
            intelligence=ReportIntelligence(
                discovery_quality=DiscoveryQualityMetrics(
                    crawl_coverage_percent=85.5,
                    forms_discovered=2,
                    apis_discovered=1,
                    javascript_files_analyzed=3,
                    hidden_endpoints=3,
                    assets_skipped=5,
                    third_party_assets=2,
                    total_assets=10,
                    endpoint_types={"API": 1, "Main Application": 5}
                )
            )
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = await exporter.export(report, tmpdir)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            
            assert "Discovery Quality Metrics" in content
            assert "85.5%" in content
            assert "APIs Discovered" in content
            assert "Hidden Endpoints" in content
            assert "Third-Party Assets" in content

    @pytest.mark.asyncio
    async def test_html_exporter_renders_discovery_quality(self):
        template_dir = os.path.join(os.path.dirname(__file__), "..", "..", "src", "scanner", "reporting", "templates")
        exporter = HTMLExporter(template_dir=template_dir)
        
        f1 = EnrichedFinding(
            plugin_id="TEST-01", title="Test", description="Desc", severity=Severity.HIGH, confidence=Confidence.HIGH,
            endpoint="https://example.com/api", endpoint_class="API",
            intelligence=VulnerabilityIntelligence(cwe_id="CWE-79")
        )
        
        report = Report(
            metadata=ReportMetadata(target_urls=["https://example.com"]),
            summary=ScanSummary(total_findings=1, high_count=1, endpoints_discovered=10, forms_discovered=2),
            findings=[f1],
            intelligence=ReportIntelligence(
                discovery_quality=DiscoveryQualityMetrics(
                    crawl_coverage_percent=85.5,
                    forms_discovered=2,
                    apis_discovered=1,
                    javascript_files_analyzed=3,
                    hidden_endpoints=3,
                    assets_skipped=5,
                    third_party_assets=2,
                    total_assets=10,
                    endpoint_types={"API": 1, "Main Application": 5}
                )
            )
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = await exporter.export(report, tmpdir)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            
            assert "Discovery Quality Metrics" in content
            assert "85.5%" in content
            assert "APIs Discovered" in content
            assert "Hidden Endpoints" in content
            assert "Third-Party Assets" in content

class TestSecurityScoreCalculation:
    """Tests for the comprehensive security score algorithm."""

    @staticmethod
    def _make_finding(severity, endpoint="https://example.com", raw_response="", is_verified=False):
        from scanner.models.finding import Finding, Evidence, DetectionMethod, VerificationStatus
        evidence = [Evidence(type="test", description="test", data={}, raw_response=raw_response)] if raw_response else []
        finding = Finding(
            plugin_id="TEST-001",
            title="Test Finding",
            description="Test",
            severity=severity,
            confidence=Confidence.HIGH,
            endpoint=endpoint,
            evidence=evidence,
            detection_method=DetectionMethod.PASSIVE,
            verification_status=VerificationStatus.VERIFIED if is_verified else VerificationStatus.NOT_ACTIVELY_VERIFIED,
        )
        return EnrichedFinding(**finding.model_dump())

    def test_score_bounded_zero_to_hundred(self):
        manager = ReportManager(exporters={}, output_dir="/tmp")
        score = manager._compute_intelligence(
            findings=[],
            target_urls=[],
            summary=ScanSummary(total_findings=0, critical_count=0, high_count=0, medium_count=0, low_count=0, info_count=0),
            stats={},
            scan_obj=None,
        ).overall_security_score
        assert 0.0 <= score <= 100.0

    def test_secure_site_scores_high(self):
        manager = ReportManager(exporters={}, output_dir="/tmp")
        raw_response = (
            "HTTP/1.1 200 OK\r\n"
            "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n"
            "Content-Security-Policy: default-src 'self'\r\n"
            "X-Frame-Options: DENY\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "Referrer-Policy: strict-origin-when-cross-origin\r\n"
            "Permissions-Policy: geolocation=()\r\n"
            "X-XSS-Protection: 1; mode=block\r\n"
            "\r\n"
        )
        findings = [
            self._make_finding(Severity.LOW, raw_response=raw_response, is_verified=True)
            for _ in range(3)
        ]
        summary = ScanSummary(
            total_findings=3,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=3,
            info_count=0,
            confidence_high_count=3,
            confidence_medium_count=0,
            confidence_low_count=0,
            verified_count=3,
            unverified_count=0,
            false_positive_probability=5.0,
        )
        score = manager._compute_intelligence(
            findings=findings,
            target_urls=["https://example.com"],
            summary=summary,
            stats={"technologies": [{"name": "cloudflare", "category": "CDN"}]},
            scan_obj=None,
        ).overall_security_score
        assert score >= 80.0

    def test_vulnerable_site_scores_low(self):
        manager = ReportManager(exporters={}, output_dir="/tmp")
        findings = [
            self._make_finding(Severity.CRITICAL),
            self._make_finding(Severity.CRITICAL),
            self._make_finding(Severity.HIGH),
            self._make_finding(Severity.HIGH),
            self._make_finding(Severity.HIGH),
            self._make_finding(Severity.MEDIUM),
        ]
        summary = ScanSummary(
            total_findings=6,
            critical_count=2,
            high_count=3,
            medium_count=1,
            low_count=0,
            info_count=0,
            confidence_high_count=0,
            confidence_medium_count=2,
            confidence_low_count=4,
            verified_count=0,
            unverified_count=6,
            false_positive_probability=50.0,
        )
        score = manager._compute_intelligence(
            findings=findings,
            target_urls=["http://vulnerable.example.com"],
            summary=summary,
            stats={"technologies": []},
            scan_obj=None,
        ).overall_security_score
        assert score <= 60.0

    def test_compromised_site_scores_very_low(self):
        manager = ReportManager(exporters={}, output_dir="/tmp")
        findings = [
            self._make_finding(Severity.CRITICAL) for _ in range(5)
        ] + [
            self._make_finding(Severity.HIGH) for _ in range(3)
        ]
        summary = ScanSummary(
            total_findings=8,
            critical_count=5,
            high_count=3,
            medium_count=0,
            low_count=0,
            info_count=0,
            confidence_high_count=0,
            confidence_medium_count=0,
            confidence_low_count=8,
            verified_count=0,
            unverified_count=8,
            false_positive_probability=60.0,
        )
        score = manager._compute_intelligence(
            findings=findings,
            target_urls=["http://compromised.example.com"],
            summary=summary,
            stats={"technologies": []},
            scan_obj=None,
        ).overall_security_score
        assert score < 30.0

    def test_development_site_scores_mid_range(self):
        manager = ReportManager(exporters={}, output_dir="/tmp")
        raw_response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Security-Policy: default-src 'self'\r\n"
            "X-Frame-Options: DENY\r\n"
            "\r\n"
        )
        findings = [
            self._make_finding(Severity.HIGH, raw_response=raw_response),
            self._make_finding(Severity.MEDIUM, raw_response=raw_response),
            self._make_finding(Severity.MEDIUM, raw_response=raw_response),
            self._make_finding(Severity.LOW, raw_response=raw_response),
        ]
        summary = ScanSummary(
            total_findings=4,
            critical_count=0,
            high_count=1,
            medium_count=2,
            low_count=1,
            info_count=0,
            confidence_high_count=1,
            confidence_medium_count=2,
            confidence_low_count=1,
            verified_count=2,
            unverified_count=2,
            false_positive_probability=30.0,
        )
        score = manager._compute_intelligence(
            findings=findings,
            target_urls=["https://dev.example.com"],
            summary=summary,
            stats={"technologies": [{"name": "django", "category": "Framework"}]},
            scan_obj=None,
        ).overall_security_score
        assert 60.0 <= score <= 85.0

    def test_missing_headers_reduces_score(self):
        manager = ReportManager(exporters={}, output_dir="/tmp")
        findings_secure = [self._make_finding(Severity.LOW, raw_response="HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\n\r\n")]
        findings_insecure = [self._make_finding(Severity.LOW, raw_response="HTTP/1.1 200 OK\r\n\r\n")]

        summary = ScanSummary(
            total_findings=1,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=1,
            info_count=0,
            confidence_high_count=1,
            confidence_medium_count=0,
            confidence_low_count=0,
            verified_count=1,
            unverified_count=0,
            false_positive_probability=0.0,
        )

        score_secure = manager._compute_intelligence(
            findings=findings_secure,
            target_urls=["https://example.com"],
            summary=summary,
            stats={"technologies": []},
            scan_obj=None,
        ).overall_security_score

        score_insecure = manager._compute_intelligence(
            findings=findings_insecure,
            target_urls=["https://example.com"],
            summary=summary,
            stats={"technologies": []},
            scan_obj=None,
        ).overall_security_score

        assert score_secure > score_insecure

    def test_verified_findings_boost_score(self):
        manager = ReportManager(exporters={}, output_dir="/tmp")
        findings_unverified = [
            self._make_finding(Severity.MEDIUM, is_verified=False) for _ in range(3)
        ]
        findings_verified = [
            self._make_finding(Severity.MEDIUM, is_verified=True) for _ in range(3)
        ]

        summary_unverified = ScanSummary(
            total_findings=3,
            critical_count=0,
            high_count=0,
            medium_count=3,
            low_count=0,
            info_count=0,
            confidence_high_count=0,
            confidence_medium_count=3,
            confidence_low_count=0,
            verified_count=0,
            unverified_count=3,
            false_positive_probability=40.0,
        )
        summary_verified = ScanSummary(
            total_findings=3,
            critical_count=0,
            high_count=0,
            medium_count=3,
            low_count=0,
            info_count=0,
            confidence_high_count=3,
            confidence_medium_count=0,
            confidence_low_count=0,
            verified_count=3,
            unverified_count=0,
            false_positive_probability=5.0,
        )

        score_unverified = manager._compute_intelligence(
            findings=findings_unverified,
            target_urls=["https://example.com"],
            summary=summary_unverified,
            stats={"technologies": []},
            scan_obj=None,
        ).overall_security_score

        score_verified = manager._compute_intelligence(
            findings=findings_verified,
            target_urls=["https://example.com"],
            summary=summary_verified,
            stats={"technologies": []},
            scan_obj=None,
        ).overall_security_score

        assert score_verified > score_unverified
