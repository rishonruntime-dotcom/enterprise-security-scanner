"""
Enterprise Risk Intelligence Collector.

Gathers comprehensive intelligence from scan results, technologies,
security headers, CSP configurations, and target metadata to build
a complete RiskIntelligence profile for weighted risk scoring.
"""
from typing import Any, Dict, List, Optional
import structlog

from .intelligence_models import (
    RiskIntelligence,
    ExploitIntelligence,
    MitigationIntelligence,
    EnvironmentIntelligence,
    SecurityMaturityIntelligence,
    BusinessIntelligence,
    CSPQuality,
    HSTSStatus,
    TrustedTypesStatus,
    SecurityMaturityLevel,
)

logger = structlog.get_logger(__name__)


class RiskIntelligenceCollector:
    """Collects and aggregates risk intelligence from scan results."""

    def __init__(self):
        self.findings: List[Any] = []
        self.technologies: List[Dict[str, Any]] = []
        self.headers: Dict[str, str] = {}
        self.csp_policy: Optional[str] = None
        self.trusted_types_policy: Optional[str] = None
        self.endpoints: List[Dict[str, Any]] = []
        self.scan_metadata: Dict[str, Any] = {}
        self.maturity_signals: Dict[str, Any] = {}

    def add_finding(self, finding: Any) -> None:
        """Add a finding to the intelligence profile."""
        self.findings.append(finding)

    def add_technology(self, tech: Dict[str, Any]) -> None:
        """Add a detected technology."""
        self.technologies.append(tech)

    def add_header(self, name: str, value: str) -> None:
        """Add a response header."""
        self.headers[name.lower()] = value

    def set_csp_policy(self, policy: Optional[str]) -> None:
        """Set CSP policy."""
        self.csp_policy = policy

    def set_trusted_types_policy(self, policy: Optional[str]) -> None:
        """Set Trusted Types policy."""
        self.trusted_types_policy = policy

    def add_endpoint(self, endpoint: Dict[str, Any]) -> None:
        """Add a discovered endpoint."""
        self.endpoints.append(endpoint)

    def set_scan_metadata(self, metadata: Dict[str, Any]) -> None:
        """Set scan-level metadata."""
        self.scan_metadata = metadata

    def add_maturity_signal(self, signal: Dict[str, Any]) -> None:
        """Add a security maturity signal."""
        self.maturity_signals.update(signal)

    def collect(self, target_context: Optional[Dict[str, Any]] = None) -> RiskIntelligence:
        """
        Collect all intelligence and return a comprehensive RiskIntelligence profile.
        
        Args:
            target_context: Optional context dict with keys:
                - asset_criticality: str
                - exposure: str
                - data_sensitivity: str
                - compliance_requirements: List[str]
                - user_base_size: str
                - revenue_impact: str
        """
        target_context = target_context or {}
        
        # Collect exploit intelligence from findings
        exploit_intel = self._collect_exploit_intelligence()
        
        # Collect mitigation intelligence from headers/CSP
        mitigation_intel = self._collect_mitigation_intelligence()
        
        # Collect environment intelligence
        env_intel = self._collect_environment_intelligence(target_context)
        
        # Collect security maturity intelligence
        maturity_intel = self._collect_security_maturity_intelligence()
        
        # Collect business intelligence
        business_intel = self._collect_business_intelligence(target_context)
        
        return RiskIntelligence(
            exploit_intelligence=exploit_intel,
            mitigation_intelligence=mitigation_intel,
            environment_intelligence=env_intel,
            security_maturity_intelligence=maturity_intel,
            business_intelligence=business_intel,
        )

    def _collect_exploit_intelligence(self) -> ExploitIntelligence:
        """Collect exploit intelligence from findings."""
        # Aggregate EPSS and KEV across findings
        max_epss = 0.0
        max_epss_pct = 0.0
        is_any_kev = None
        any_active_success = False
        max_maturity = "Unknown"
        cwe_for_fallback = None
        
        maturity_rank = {"High": 4, "Functional": 3, "ProofOfConcept": 2, "Unknown": 1}
        
        for finding in self.findings:
            # EPSS
            epss = getattr(finding, "epss_score", None)
            if epss is not None and epss > max_epss:
                max_epss = epss
            epss_pct = getattr(finding, "epss_percentile", None)
            if epss_pct is not None and epss_pct > max_epss_pct:
                max_epss_pct = epss_pct
            
            # KEV
            kev = getattr(finding, "kev_status", None)
            if kev is True:
                is_any_kev = True
            elif kev is None and is_any_kev is None:
                is_any_kev = None
            
            # Active exploit success
            if getattr(finding, "verification_status", None) == "Verified":
                any_active_success = True
            
            # Exploit maturity
            maturity = getattr(finding, "exploit_maturity", None) or "Unknown"
            if maturity_rank.get(maturity, 0) > maturity_rank.get(max_maturity, 0):
                max_maturity = maturity
            
            # Collect CWE for fallback
            finding_cwe = getattr(finding, "cwe_id", None)
            if not finding_cwe and hasattr(finding, "intelligence") and finding.intelligence:
                finding_cwe = getattr(finding.intelligence, "cwe_id", None)
            if finding_cwe and not cwe_for_fallback:
                cwe_for_fallback = finding_cwe
        
        # Fallback to CWE-based EPSS if no finding-level EPSS data
        if max_epss == 0.0 and cwe_for_fallback:
            from .intelligence import EPSSAnalyzer
            epss_score = EPSSAnalyzer.analyze(cwe_id=cwe_for_fallback)
            if epss_score.probability:
                max_epss = epss_score.probability
            if epss_score.percentile:
                max_epss_pct = epss_score.percentile
        
        # Fallback to CWE-based KEV if no finding-level KEV data
        if is_any_kev is None and cwe_for_fallback:
            from .intelligence import KEVAnalyzer
            is_any_kev = KEVAnalyzer.is_kev(cwe_id=cwe_for_fallback)
        
        return ExploitIntelligence(
            epss_probability=max_epss if max_epss > 0 else None,
            epss_percentile=max_epss_pct if max_epss_pct > 0 else None,
            is_kev=is_any_kev,
            active_exploit_success=any_active_success,
            exploit_maturity=max_maturity,
        )

    def _collect_mitigation_intelligence(self) -> MitigationIntelligence:
        """Collect mitigation intelligence from headers and configurations."""
        headers_lower = {k.lower(): v.lower() for k, v in self.headers.items()}
        
        # CSP analysis
        csp_header = headers_lower.get("content-security-policy", "")
        csp_quality = self._assess_csp_quality(csp_header)
        csp_strict_dynamic = "strict-dynamic" in csp_header
        csp_nonce = "'nonce-" in csp_header or "'sha" in csp_header
        
        # HSTS analysis
        hsts_header = headers_lower.get("strict-transport-security", "")
        hsts_status = self._assess_hsts_status(hsts_header)
        hsts_max_age = self._parse_hsts_max_age(hsts_header)
        hsts_include_subdomains = "includesubdomains" in hsts_header
        
        # Trusted Types
        tt_header = headers_lower.get("content-security-policy", "")
        tt_status = self._assess_trusted_types(tt_header)
        
        # Other security headers
        xfo = "x-frame-options" in headers_lower
        xcto = "x-content-type-options" in headers_lower
        referrer = "referrer-policy" in headers_lower
        permissions = "permissions-policy" in headers_lower or "feature-policy" in headers_lower
        
        mitigation = MitigationIntelligence(
            csp_quality=csp_quality,
            csp_strict_dynamic=csp_strict_dynamic,
            csp_nonce=csp_nonce,
            hsts_status=hsts_status,
            hsts_max_age=hsts_max_age,
            hsts_include_subdomains=hsts_include_subdomains,
            trusted_types=tt_status,
            x_frame_options=xfo,
            x_content_type_options=xcto,
            referrer_policy=referrer,
            permissions_policy=permissions,
        )
        mitigation.calculate_score()
        return mitigation

    def _assess_csp_quality(self, csp_header: str) -> CSPQuality:
        """Assess CSP quality based on policy strength.

        Evaluates both weaknesses and protections.
        A modern CSP with strong mitigations should not be downgraded
        because of isolated weak directives.
        """
        if not csp_header:
            return CSPQuality.ABSENT

        csp_lower = csp_header.lower()

        weak_patterns = ["'unsafe-inline'", "'unsafe-eval'", "*", "http://"]
        strong_directives = ["default-src 'self'", "script-src 'none'", "object-src 'none'"]

        weak_count = sum(1 for p in weak_patterns if p in csp_lower)
        strong_count = sum(1 for d in strong_directives if d in csp_lower)

        has_modern_mitigations = (
            "strict-dynamic" in csp_lower or
            "'nonce-" in csp_lower or
            "'sha256-" in csp_lower or
            "'sha384-" in csp_lower or
            "'sha512-" in csp_lower or
            ("trusted-types" in csp_lower and "require-trusted-types-for" in csp_lower)
        )

        has_nonce_or_hash = "'nonce-" in csp_lower or "'sha" in csp_lower
        has_strict_dynamic = "strict-dynamic" in csp_lower
        has_object_none = "object-src 'none'" in csp_lower or "object-src 'self'" in csp_lower
        has_trusted_types_enforced = "trusted-types" in csp_lower and "require-trusted-types-for" in csp_lower
        has_report_uri = "report-uri" in csp_lower or "report-to" in csp_lower

        strong_mitigation_count = sum([
            has_nonce_or_hash,
            has_strict_dynamic,
            has_object_none,
            has_trusted_types_enforced,
            has_report_uri,
        ])

        # If strong mitigations are present, downgrade weak patterns less aggressively
        if has_modern_mitigations:
            if weak_count >= 3 and strong_mitigation_count >= 3:
                return CSPQuality.MODERATE
            elif weak_count >= 2 and strong_mitigation_count >= 2:
                return CSPQuality.MODERATE
            elif weak_count >= 1 and strong_mitigation_count >= 1:
                return CSPQuality.MODERATE
            else:
                return CSPQuality.STRONG

        # No modern mitigations - evaluate based on weak/strong patterns
        if weak_count >= 3 and not has_modern_mitigations:
            return CSPQuality.WEAK
        elif weak_count >= 1 or strong_count == 0:
            return CSPQuality.WEAK
        else:
            return CSPQuality.STRONG

    def _assess_hsts_status(self, hsts_header: str) -> HSTSStatus:
        """Assess HSTS status."""
        if not hsts_header:
            return HSTSStatus.ABSENT
        if "preload" in hsts_header.lower():
            return HSTSStatus.PRELOAD
        return HSTSStatus.PRESENT

    def _parse_hsts_max_age(self, hsts_header: str) -> Optional[int]:
        """Parse HSTS max-age value."""
        if not hsts_header:
            return None
        import re
        match = re.search(r"max-age=(\d+)", hsts_header, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

    def _assess_trusted_types(self, csp_header: str) -> TrustedTypesStatus:
        """Assess Trusted Types status from CSP."""
        if not csp_header:
            return TrustedTypesStatus.ABSENT
        csp_lower = csp_header.lower()
        has_tt_policy = "trusted-types" in csp_lower
        has_rttf = "require-trusted-types-for" in csp_lower
        
        if has_rttf:
            if "script" in csp_lower.split("require-trusted-types-for")[1].split(";")[0]:
                return TrustedTypesStatus.ENFORCED
            return TrustedTypesStatus.REPORT_ONLY
        elif has_tt_policy:
            return TrustedTypesStatus.REPORT_ONLY
        return TrustedTypesStatus.ABSENT

    def _collect_environment_intelligence(self, target_context: Dict[str, Any]) -> EnvironmentIntelligence:
        """Collect environment and attack surface intelligence."""
        # Count endpoints by type
        endpoint_count = len(self.endpoints)
        parameterized = sum(1 for e in self.endpoints if e.get("parameters"))
        api_endpoints = sum(1 for e in self.endpoints if e.get("class") == "API")
        admin_endpoints = sum(1 for e in self.endpoints if "admin" in e.get("path", "").lower())
        authenticated = sum(1 for e in self.endpoints if e.get("requires_auth"))
        
        # Count technologies
        tech_names = set(t.get("name", "") for t in self.technologies if t.get("name"))
        framework_keywords = ["react", "angular", "vue", "django", "flask", "laravel", "express", "spring", "nextjs", "nuxtjs"]
        framework_count = sum(1 for t in self.technologies 
                            if any(fw in t.get("name", "").lower() for fw in framework_keywords))
        
        return EnvironmentIntelligence(
            asset_criticality=target_context.get("asset_criticality", "Medium"),
            exposure=target_context.get("exposure", "InternetFacing"),
            endpoint_count=endpoint_count,
            parameterized_endpoints=parameterized,
            api_endpoints=api_endpoints,
            admin_endpoints=admin_endpoints,
            authenticated_endpoints=authenticated,
            technology_count=len(tech_names),
            framework_count=framework_count,
        )

    def _collect_security_maturity_intelligence(self) -> SecurityMaturityIntelligence:
        """Collect security maturity intelligence."""
        # Count security headers
        security_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "x-xss-protection",
        ]
        headers_lower = {k.lower() for k in self.headers.keys()}
        present_count = sum(1 for h in security_headers if h in headers_lower)
        
        # Cookie security score
        cookie_score = 0.0
        cookie_headers = [v for k, v in self.headers.items() if k.lower() == "set-cookie"]
        if cookie_headers:
            secure_count = sum(1 for c in cookie_headers if "secure" in c.lower())
            httponly_count = sum(1 for c in cookie_headers if "httponly" in c.lower())
            samesite_count = sum(1 for c in cookie_headers if "samesite" in c.lower())
            cookie_score = (secure_count + httponly_count + samesite_count) / (len(cookie_headers) * 3)
        
        # TLS score (basic check)
        tls_score = 0.5  # Default moderate
        if self.headers.get("strict-transport-security"):
            tls_score = 0.8
        
        return SecurityMaturityIntelligence(
            security_headers_present=present_count,
            security_headers_total=len(security_headers),
            cookie_security_score=cookie_score,
            tls_configuration_score=tls_score,
        )

    def _collect_business_intelligence(self, target_context: Dict[str, Any]) -> BusinessIntelligence:
        """Collect business context intelligence."""
        return BusinessIntelligence(
            data_sensitivity=target_context.get("data_sensitivity", "Medium"),
            compliance_requirements=target_context.get("compliance_requirements", []),
            user_base_size=target_context.get("user_base_size", "Medium"),
            revenue_impact=target_context.get("revenue_impact", "Medium"),
        )
