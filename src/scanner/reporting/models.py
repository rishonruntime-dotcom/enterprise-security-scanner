from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from ..correlation.models import EnrichedFinding

class ScanSummary(BaseModel):
    """Aggregate statistics for a scan."""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    scan_duration_seconds: float = 0.0
    pages_discovered: int = 0
    endpoints_discovered: int = 0
    forms_discovered: int = 0
    parameters_discovered: int = 0
    browser_routes_discovered: int = 0
    http_requests_sent: int = 0
    payloads_executed: int = 0
    verification_requests: int = 0
    confidence_high_count: int = 0
    confidence_medium_count: int = 0
    confidence_low_count: int = 0
    verified_count: int = 0
    unverified_count: int = 0
    false_positive_probability: float = 0.0
    network_open_ports: int = 0
    network_services_detected: int = 0
    network_risky_services: int = 0

class DiscoveryQualityMetrics(BaseModel):
    """Granular discovery quality metrics for a scan."""
    crawl_coverage_percent: float = 0.0
    endpoint_types: Dict[str, int] = Field(default_factory=dict)
    hidden_endpoints: int = 0
    forms_discovered: int = 0
    apis_discovered: int = 0
    javascript_files_analyzed: int = 0
    assets_skipped: int = 0
    third_party_assets: int = 0
    total_assets: int = 0
    first_party_endpoints: int = 0
    third_party_endpoints: int = 0
    cdn_endpoints: int = 0
    api_endpoints: int = 0
    auth_endpoints: int = 0
    admin_endpoints: int = 0
    network_exposure: Dict[str, Any] = Field(default_factory=dict)

class AssetCriticalitySummary(BaseModel):
    """Summary for a critical asset."""
    target_url: str
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    risk_score: float = 0.0

class FindingsByAsset(BaseModel):
    """Findings grouped by asset."""
    asset_url: str
    findings: List[Dict[str, Any]] = Field(default_factory=list)

class FindingsByTechnology(BaseModel):
    """Findings grouped by technology."""
    technology_name: str
    technology_category: str = ""
    findings: List[Dict[str, Any]] = Field(default_factory=list)

class FindingsByAssetCategory(BaseModel):
    """Findings grouped by asset ownership/integration category."""
    asset_category: str
    findings: List[Dict[str, Any]] = Field(default_factory=list)

class ReportIntelligence(BaseModel):
    """Advanced intelligence sections for executive reporting."""
    overall_security_score: float = 0.0
    score_breakdown: Dict[str, Any] = Field(default_factory=dict)
    risk_trend: List[Dict[str, Any]] = Field(default_factory=list)
    attack_surface_summary: Dict[str, Any] = Field(default_factory=dict)
    most_critical_assets: List[AssetCriticalitySummary] = Field(default_factory=list)
    executive_recommendations: List[str] = Field(default_factory=list)
    findings_by_asset: List[FindingsByAsset] = Field(default_factory=list)
    findings_by_asset_category: List[FindingsByAssetCategory] = Field(default_factory=list)
    findings_by_technology: List[FindingsByTechnology] = Field(default_factory=list)
    confidence_distribution: Dict[str, int] = Field(default_factory=dict)
    verified_vs_unverified: Dict[str, int] = Field(default_factory=dict)
    discovery_quality: DiscoveryQualityMetrics = Field(default_factory=DiscoveryQualityMetrics)
    network_exposure: Optional[Dict[str, Any]] = Field(default=None)
    grouped_findings: List[Dict[str, Any]] = Field(default_factory=list)
    fp_engine_decisions: Dict[str, Any] = Field(default_factory=dict)
    attack_chains: List[Dict[str, Any]] = Field(default_factory=list)

class ReportMetadata(BaseModel):
    """Metadata surrounding the generated report."""
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    scanner_version: str = "2.4.0-enterprise"
    target_urls: List[str] = Field(default_factory=list)

class Report(BaseModel):
    """The master report object aggregating all scanner output."""
    metadata: ReportMetadata = Field(default_factory=ReportMetadata)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: List[EnrichedFinding] = Field(default_factory=list)
    technologies: List[Any] = Field(default_factory=list)
    intelligence: ReportIntelligence = Field(default_factory=ReportIntelligence)
