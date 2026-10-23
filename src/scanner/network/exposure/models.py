"""
Network Exposure Models & Architecture.

Defines comprehensive, enterprise-grade data structures for network exposure analysis,
service classification, fingerprinting, TLS/HTTP/WAF/CDN assessment, and exposure risk modeling.
"""
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"


class TransportProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class ServiceRisk(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ServiceCategory(str, Enum):
    WEB = "Web"
    DATABASE = "Database"
    REMOTE_ADMIN = "Remote Administration"
    FILE_SHARING = "File Sharing"
    MESSAGING = "Messaging"
    EMAIL = "Email"
    DNS = "DNS"
    MONITORING = "Monitoring"
    DEVOPS = "DevOps"
    KUBERNETES = "Kubernetes"
    CONTAINER = "Container"
    VPN = "VPN"
    IOT = "IoT"
    PRINTING = "Printing"
    INFRASTRUCTURE = "Infrastructure"
    UNKNOWN = "Unknown"


class TLSInformation(BaseModel):
    """Rich TLS security posture information for a network service."""
    tls_supported: bool = False
    supported_versions: List[str] = Field(default_factory=list)
    negotiated_version: Optional[str] = None
    certificate_issuer: Optional[str] = None
    expiration_date: Optional[str] = None
    self_signed: bool = False
    weak_cipher_suites: List[str] = Field(default_factory=list)
    forward_secrecy: bool = True
    hsts_enabled: bool = False
    alpn_protocols: List[str] = Field(default_factory=list)
    supports_http2: bool = False
    supports_http3: bool = False


class HTTPInformation(BaseModel):
    """HTTP protocol and header details for a web-based service."""
    http_versions: List[str] = Field(default_factory=list)
    server_software: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    has_csp: bool = False
    has_hsts: bool = False
    has_xfo: bool = False


class CDNInformation(BaseModel):
    """Content Delivery Network (CDN) detection info."""
    detected: bool = False
    provider_name: Optional[str] = None
    pop_location: Optional[str] = None
    matched_headers: List[str] = Field(default_factory=list)


class ReverseProxyInformation(BaseModel):
    """Reverse Proxy fingerprinting info."""
    detected: bool = False
    proxy_type: Optional[str] = None
    version: Optional[str] = None
    matched_signatures: List[str] = Field(default_factory=list)


class WAFInformation(BaseModel):
    """Web Application Firewall (WAF) detection info."""
    detected: bool = False
    waf_name: Optional[str] = None
    vendor: Optional[str] = None
    matched_rules: List[str] = Field(default_factory=list)


class ServiceVersionInformation(BaseModel):
    """Detailed product and version metadata for a service."""
    product: Optional[str] = None
    version: Optional[str] = None
    vendor: Optional[str] = None
    cpe: Optional[str] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class DetectedService(BaseModel):
    """Detailed fingerprint of a service running on an open port."""
    port: int
    protocol: TransportProtocol = TransportProtocol.TCP
    service_name: str
    category: ServiceCategory = ServiceCategory.UNKNOWN
    version_info: Optional[ServiceVersionInformation] = None
    banner: Optional[str] = None
    tls_info: Optional[TLSInformation] = None
    http_info: Optional[HTTPInformation] = None
    cdn_info: Optional[CDNInformation] = None
    proxy_info: Optional[ReverseProxyInformation] = None
    waf_info: Optional[WAFInformation] = None
    os_fingerprint: Optional[str] = None
    risk_level: ServiceRisk = ServiceRisk.INFO
    is_expected: bool = False
    requires_auth: bool = True
    raw_response: Optional[str] = None


class OpenPort(BaseModel):
    """Model representing an open network port."""
    port: int
    state: PortState = PortState.OPEN
    protocol: TransportProtocol = TransportProtocol.TCP
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    tls_support: Optional[bool] = None
    tls_version: Optional[str] = None
    http_version: Optional[str] = None
    server_software: Optional[str] = None
    reverse_proxy: Optional[str] = None
    cdn: Optional[str] = None
    extra_info: Dict[str, Any] = Field(default_factory=dict)
    checks: List[str] = Field(default_factory=list, description="Safe checks performed on this port")
    detected_service: Optional[DetectedService] = None


# PortInfo is maintained as a direct alias/subclass for 100% backward compatibility
class PortInfo(OpenPort):
    """Backward-compatible PortInfo model."""
    pass


class ServiceFingerprint(BaseModel):
    """Fingerprinted service details."""
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    protocol: str = "tcp"
    cpe: Optional[str] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    source: Optional[str] = None


class ExposureSummary(BaseModel):
    """Target-level exposure summary and risk posture metrics."""
    target_host: str
    total_ports_scanned: int = 0
    open_ports_count: int = 0
    filtered_ports_count: int = 0
    closed_ports_count: int = 0
    category_counts: Dict[str, int] = Field(default_factory=dict)
    expected_services_count: int = 0
    risky_services_count: int = 0
    overall_exposure_risk: ServiceRisk = ServiceRisk.INFO
    cdn_detected: bool = False
    waf_detected: bool = False
    reverse_proxy_detected: bool = False
    summary_notes: List[str] = Field(default_factory=list)


class NetworkExposureResult(BaseModel):
    """Results from network exposure analysis."""
    target_host: str
    open_ports: List[PortInfo] = Field(default_factory=list)
    filtered_ports: List[int] = Field(default_factory=list)
    closed_ports: List[int] = Field(default_factory=list)
    services: List[ServiceFingerprint] = Field(default_factory=list)
    exposure_summary: Optional[ExposureSummary] = None
    scan_duration_seconds: float = 0.0
    ports_scanned: int = 0


class ExposedServiceFinding(BaseModel):
    """A finding generated from an exposed service."""
    plugin_id: str
    title: str
    description: str
    severity: ServiceRisk
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    port: int
    service: str
    product: Optional[str] = None
    version: Optional[str] = None
    endpoint: str
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    capec_id: Optional[str] = None
    why_detected: Optional[str] = None
    how_verified: Optional[str] = None
    severity_reason: Optional[str] = None
    false_positive_reasons: List[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    is_expected: bool = Field(default=False)
    is_authenticated: bool = Field(default=False)
    is_internet_facing: bool = Field(default=True)
    anonymous_access: bool = Field(default=False)
    default_creds_detected: bool = Field(default=False)
    misconfiguration_detected: bool = Field(default=False)
    check_details: List[str] = Field(default_factory=list)


class NetworkExposureSection(BaseModel):
    """Dedicated report section for network exposure."""
    target_host: str
    total_ports_scanned: int = 0
    open_ports_count: int = 0
    filtered_ports_count: int = 0
    closed_ports_count: int = 0
    open_ports: List[Dict[str, Any]] = Field(default_factory=list)
    services_summary: List[Dict[str, Any]] = Field(default_factory=list)
    exposure_summary: Optional[Dict[str, Any]] = None
    risky_services_count: int = 0
    scan_duration_seconds: float = 0.0
