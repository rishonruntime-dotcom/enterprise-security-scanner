"""False Positive Reduction Engine for enterprise vulnerability scanner.

Evaluates every finding through a reasoning chain before it reaches the report:
  1. CDN / hosting-provider exception
  2. Reverse-proxy / load-balancer exception
  3. Framework / platform exception
  4. Browser-native protection exception
  5. Known secure-configuration exception
  6. Final severity calibration

Designed as the LAST pipeline step so all upstream enrichment
(verification, intelligence, CVSS, risk, severity context) is already applied.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog

from ..models.finding import Finding, Severity, Confidence, DetectionMethod
from .models import EnrichedFinding
from ..classification.classifier import AssetClassifier

logger = structlog.get_logger(__name__)


# ── Domain / Pattern Knowledge Bases ─────────────────────────────────────────

_CDN_HOSTING_INDICATORS: Set[str] = {
    "cloudflare.com", "cloudfront.net", "fastly.net", "akamai.net",
    "akamaihd.net", "cdn.jsdelivr.net", "unpkg.com", "cdn.cloudflare.net",
    "b-cdn.net", "bunny.net", "keycdn.com", "stackpathdns.com",
    "netdna-cdn.com", "cdn77.org", "cdnify.com", "incapdns.net",
    "imperva.com", "sucuri.net", "azureedge.net", "azure.com",
    "googleusercontent.com", "googlehosted.com",
    "cloudflare.net", "fastly.io", "akamaiedge.net",
    "edgesuite.net", "llnwd.net", "optimum.net", "s3.amazonaws.com",
    "cloudfront.com", "cdn.prod.fastly.net",
}

_REVERSE_PROXY_INDICATORS: Set[str] = {
    "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host",
    "x-real-ip", "x-request-start", "x-request-id", "x-correlation-id",
    "x-route", "x-server", "x-served-by", "x-cache", "x-cache-status",
    "cf-ray", "cf-request-id", "x-haproxy-server", "x-varnish",
    "via", "x-cdn", "x-edge-location", "x-amz-cf-id",
    "x-nginx", "x-powered-by", "server", "x-amz-cf-id",
    "x-sucuri-id", "x-imperva-request-id", "x-original-url",
}

_FRAMEWORK_HEADERS: Dict[str, Set[str]] = {
    "django": {"x-frame-options", "x-content-type-options", "referrer-policy"},
    "rails": {"x-frame-options", "x-content-type-options", "x-xss-protection", "referrer-policy"},
    "express": {"x-frame-options", "x-content-type-options", "referrer-policy"},
    "spring": {"x-frame-options", "x-content-type-options", "x-xss-protection", "referrer-policy"},
    "aspnet": {"x-frame-options", "x-content-type-options", "x-xss-protection", "referrer-policy"},
    "laravel": {"x-frame-options", "x-content-type-options", "referrer-policy"},
    "wordpress": {"x-frame-options", "x-content-type-options", "referrer-policy", "x-xss-protection"},
    "drupal": {"x-frame-options", "x-content-type-options", "referrer-policy", "x-xss-protection"},
    "nextjs": {"x-frame-options", "x-content-type-options", "referrer-policy"},
    "nuxtjs": {"x-frame-options", "x-content-type-options", "referrer-policy"},
}

_FRAMEWORK_PATH_SIGNATURES: Dict[str, Set[str]] = {
    "django": {"/static/", "/admin/", "/api/"},
    "rails": {"/assets/", "/rails/", "/admin/"},
    "express": {"/static/", "/public/", "/api/"},
    "spring": {"/static/", "/public/", "/api/"},
    "aspnet": {"/lib/", "/css/", "/js/", "/api/"},
    "laravel": {"/storage/", "/public/", "/api/"},
    "wordpress": {"/wp-content/", "/wp-includes/", "/wp-admin/", "/wp-json/"},
    "drupal": {"/sites/", "/modules/", "/themes/", "/node/"},
    "nextjs": {"/_next/", "/api/"},
    "nuxtjs": {"/_nuxt/", "/api/"},
    "react": {"/static/js/", "/static/css/"},
    "angular": {"/main.", "/polyfills.", "/runtime.", "/styles."},
    "vue": {"/js/app.", "/js/chunk."},
}

# Headers that browsers enforce natively, reducing scanner-flagged risk
_BROWSER_NATIVE_PROTECTIONS: Dict[str, Set[str]] = {
    "samesite_cookies": {"samesite=lax", "samesite=strict"},
    "secure_cookies": {"secure"},
    "http_only_cookies": {"httponly"},
}

# Known secure configurations that should not be flagged as weaknesses
_SECURE_CONFIG_PATTERNS: Dict[str, Set[str]] = {
    "hsts_preload": {"includesubdomains", "preload"},
    "csp_strong": {"strict-dynamic", "'unsafe-inline'"},
    "csp_reporting": {"report-uri", "report-to"},
    "permissions_policy": {"permissions-policy"},
    "referrer_policy": {"referrer-policy"},
}


# General security mitigations that reduce exploitability
_MITIGATION_HEADERS: Set[str] = {
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
    "permissions-policy",
    "referrer-policy",
    "x-xss-protection",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
}


class FPRReason(Enum):
    """Reasons a finding was adjusted or kept."""
    CDN_EXCEPTION = "cdn_exception"
    REVERSE_PROXY_EXCEPTION = "reverse_proxy_exception"
    FRAMEWORK_EXCEPTION = "framework_exception"
    BROWSER_PROTECTION = "browser_protection"
    MITIGATIONS_PRESENT = "mitigations_present"
    SECURE_CONFIGURATION = "secure_configuration"
    LOW_VALUE_ENDPOINT = "low_value_endpoint"
    LEGITIMATE_BASELINE = "legitimate_baseline"
    NO_EXCEPTION = "no_exception"


@dataclass
class FPRResult:
    """Result of false-positive reduction reasoning."""
    finding: EnrichedFinding
    action: str  # "keep", "downgrade", "drop"
    original_severity: Severity
    final_severity: Severity
    reason: FPRReason
    reasoning_chain: List[str] = field(default_factory=list)
    confidence_adjustment: float = 0.0
    dropped: bool = False


class FalsePositiveReductionEngine:
    """Enterprise false-positive reduction engine.

    Applies a multi-layer reasoning chain to every finding before it reaches
    the report.  Each layer can:
      - keep the finding unchanged
      - downgrade severity
      - drop the finding entirely
    """

    def __init__(self, http_manager: Any = None):
        self.http_manager = http_manager

    def reduce(self, finding: EnrichedFinding) -> FPRResult:
        """Run the full false-positive reduction chain on a single finding."""
        original_severity = finding.severity
        reasoning_chain: List[str] = []
        current_severity = original_severity
        action = "keep"
        confidence_adjustment = 0.0
        dropped = False
        final_reason = FPRReason.NO_EXCEPTION

        # Layer 1: CDN / Hosting Provider Exception
        cdn_result = self._check_cdn_exception(finding)
        if cdn_result:
            reasoning_chain.append(cdn_result["reason"])
            current_severity = cdn_result.get("severity", current_severity)
            action = cdn_result.get("action", action)
            confidence_adjustment = cdn_result.get("confidence_adjustment", confidence_adjustment)
            final_reason = FPRReason.CDN_EXCEPTION
            if cdn_result.get("drop", False):
                dropped = True
                return FPRResult(
                    finding=finding,
                    action=action,
                    original_severity=original_severity,
                    final_severity=current_severity,
                    reason=FPRReason.CDN_EXCEPTION,
                    reasoning_chain=reasoning_chain,
                    confidence_adjustment=confidence_adjustment,
                    dropped=True,
                )

        # Layer 2: Reverse Proxy / Load Balancer Exception
        proxy_result = self._check_reverse_proxy_exception(finding)
        if proxy_result:
            reasoning_chain.append(proxy_result["reason"])
            current_severity = proxy_result.get("severity", current_severity)
            action = proxy_result.get("action", action)
            confidence_adjustment = proxy_result.get("confidence_adjustment", confidence_adjustment)
            final_reason = FPRReason.REVERSE_PROXY_EXCEPTION
            if proxy_result.get("drop", False):
                dropped = True
                return FPRResult(
                    finding=finding,
                    action=action,
                    original_severity=original_severity,
                    final_severity=current_severity,
                    reason=FPRReason.REVERSE_PROXY_EXCEPTION,
                    reasoning_chain=reasoning_chain,
                    confidence_adjustment=confidence_adjustment,
                    dropped=True,
                )

        # Layer 3: Framework / Platform Exception
        framework_result = self._check_framework_exception(finding)
        if framework_result:
            reasoning_chain.append(framework_result["reason"])
            current_severity = framework_result.get("severity", current_severity)
            action = framework_result.get("action", action)
            confidence_adjustment = framework_result.get("confidence_adjustment", confidence_adjustment)
            final_reason = FPRReason.FRAMEWORK_EXCEPTION
            if framework_result.get("drop", False):
                dropped = True
                return FPRResult(
                    finding=finding,
                    action=action,
                    original_severity=original_severity,
                    final_severity=current_severity,
                    reason=FPRReason.FRAMEWORK_EXCEPTION,
                    reasoning_chain=reasoning_chain,
                    confidence_adjustment=confidence_adjustment,
                    dropped=True,
                )

        # Layer 4: Browser Native Protection Exception
        browser_result = self._check_browser_protection(finding)
        if browser_result:
            reasoning_chain.append(browser_result["reason"])
            current_severity = browser_result.get("severity", current_severity)
            action = browser_result.get("action", action)
            confidence_adjustment = browser_result.get("confidence_adjustment", confidence_adjustment)
            final_reason = FPRReason.BROWSER_PROTECTION
            if browser_result.get("drop", False):
                dropped = True
                return FPRResult(
                    finding=finding,
                    action=action,
                    original_severity=original_severity,
                    final_severity=current_severity,
                    reason=FPRReason.BROWSER_PROTECTION,
                    reasoning_chain=reasoning_chain,
                    confidence_adjustment=confidence_adjustment,
                    dropped=True,
                )

        # Layer 5: Security Mitigations Present
        mitigation_result = self._check_mitigations_present(finding)
        if mitigation_result:
            reasoning_chain.append(mitigation_result["reason"])
            current_severity = mitigation_result.get("severity", current_severity)
            action = mitigation_result.get("action", action)
            confidence_adjustment = max(confidence_adjustment, mitigation_result.get("confidence_adjustment", 0.0))
            final_reason = FPRReason.MITIGATIONS_PRESENT
            if mitigation_result.get("drop", False):
                dropped = True
                return FPRResult(
                    finding=finding,
                    action=action,
                    original_severity=original_severity,
                    final_severity=current_severity,
                    reason=FPRReason.MITIGATIONS_PRESENT,
                    reasoning_chain=reasoning_chain,
                    confidence_adjustment=confidence_adjustment,
                    dropped=True,
                )

        # Layer 6: Known Secure Configuration Exception
        secure_config_result = self._check_secure_configuration(finding)
        if secure_config_result:
            reasoning_chain.append(secure_config_result["reason"])
            current_severity = secure_config_result.get("severity", current_severity)
            action = secure_config_result.get("action", action)
            confidence_adjustment = max(confidence_adjustment, secure_config_result.get("confidence_adjustment", 0.0))
            final_reason = FPRReason.SECURE_CONFIGURATION
            if secure_config_result.get("drop", False):
                dropped = True
                return FPRResult(
                    finding=finding,
                    action=action,
                    original_severity=original_severity,
                    final_severity=current_severity,
                    reason=FPRReason.SECURE_CONFIGURATION,
                    reasoning_chain=reasoning_chain,
                    confidence_adjustment=confidence_adjustment,
                    dropped=True,
                )

        # Layer 6: Low-value endpoint calibration
        low_value_result = self._check_low_value_endpoint(finding)
        if low_value_result:
            reasoning_chain.append(low_value_result["reason"])
            current_severity = low_value_result.get("severity", current_severity)
            action = low_value_result.get("action", action)
            confidence_adjustment = low_value_result.get("confidence_adjustment", confidence_adjustment)
            final_reason = FPRReason.LOW_VALUE_ENDPOINT

        if not reasoning_chain:
            reasoning_chain.append("No false-positive exceptions detected. Finding retained at original severity.")

        return FPRResult(
            finding=finding,
            action=action,
            original_severity=original_severity,
            final_severity=current_severity,
            reason=final_reason,
            reasoning_chain=reasoning_chain,
            confidence_adjustment=confidence_adjustment,
            dropped=dropped,
        )

    # ── Layer 1: CDN / Hosting Provider ─────────────────────────────────────

    def _check_cdn_exception(self, finding: EnrichedFinding) -> Optional[Dict[str, Any]]:
        """CDN-hosted assets often have security managed by the provider."""
        asset_cat = getattr(finding, "asset_category", "First-party")
        if asset_cat != "CDN":
            return None

        # Generic header findings on CDN are often false positives
        # because CDNs terminate TLS and add their own headers
        if finding.plugin_id.startswith("PASS-"):
            title_lower = finding.title.lower()
            if any(kw in title_lower for kw in ["missing hsts", "missing x-frame-options", "missing x-content-type-options"]):
                return {
                    "action": "downgrade",
                    "severity": Severity.INFO,
                    "reason": "CDN-managed endpoint: security headers are typically enforced at the origin or by the CDN provider.",
                    "confidence_adjustment": 0.1,
                    "drop": False,
                }

        return None

    # ── Layer 2: Reverse Proxy / Load Balancer ───────────────────────────────

    def _check_reverse_proxy_exception(self, finding: EnrichedFinding) -> Optional[Dict[str, Any]]:
        """Reverse proxies may strip or override security headers."""
        evidence = finding.evidence or []
        raw_response = ""
        for ev in evidence:
            raw_response = getattr(ev, "raw_response", "") or ""
            if raw_response:
                break

        raw_response_lower = raw_response.lower()
        proxy_headers_found = [h for h in _REVERSE_PROXY_INDICATORS if h in raw_response_lower]

        if not proxy_headers_found:
            return None

        # If a reverse proxy is present, missing HSTS might be intentional
        # (proxy handles TLS termination and adds HSTS)
        if finding.plugin_id.startswith("PASS-") and "hsts" in finding.title.lower():
            return {
                "action": "downgrade",
                "severity": Severity.INFO,
                "reason": f"Reverse-proxy indicators detected ({', '.join(proxy_headers_found[:3])}); TLS termination and HSTS may be handled upstream.",
                "confidence_adjustment": 0.15,
                "drop": False,
            }

        return None

    # ── Layer 3: Framework / Platform Exception ──────────────────────────────

    def _check_framework_exception(self, finding: EnrichedFinding) -> Optional[Dict[str, Any]]:
        """Some frameworks provide built-in protections that reduce scanner-flagged risk."""
        endpoint = finding.endpoint or ""
        path = urllib.parse.urlparse(endpoint).path.lower()

        detected_framework = None
        for framework, path_sigs in _FRAMEWORK_PATH_SIGNATURES.items():
            if any(sig in path for sig in path_sigs):
                detected_framework = framework
                break

        if not detected_framework:
            return None

        framework_headers = _FRAMEWORK_HEADERS.get(detected_framework, set())
        evidence = finding.evidence or []
        raw_response = ""
        for ev in evidence:
            raw_response = getattr(ev, "raw_response", "") or ""
            if raw_response:
                break

        raw_response_lower = raw_response.lower()
        present_headers = set()
        for line in raw_response_lower.split("\n"):
            if ":" in line:
                header_name = line.split(":")[0].strip()
                present_headers.add(header_name)

        # If the framework already provides the flagged header, it's a false positive
        if finding.plugin_id.startswith("PASS-"):
            title_lower = finding.title.lower()
            if "x-frame-options" in title_lower and "x-frame-options" in present_headers:
                return {
                    "action": "drop",
                    "severity": finding.severity,
                    "reason": f"{detected_framework.title()} framework already provides X-Frame-Options header.",
                    "confidence_adjustment": 0.0,
                    "drop": True,
                }
            if "x-content-type-options" in title_lower and "x-content-type-options" in present_headers:
                return {
                    "action": "drop",
                    "severity": finding.severity,
                    "reason": f"{detected_framework.title()} framework already provides X-Content-Type-Options header.",
                    "confidence_adjustment": 0.0,
                    "drop": True,
                }
            if "referrer-policy" in title_lower and "referrer-policy" in present_headers:
                return {
                    "action": "drop",
                    "severity": finding.severity,
                    "reason": f"{detected_framework.title()} framework already provides Referrer-Policy header.",
                    "confidence_adjustment": 0.0,
                    "drop": True,
                }

        return None

    # ── Layer 4: Browser Native Protection ───────────────────────────────────

    def _check_browser_protection(self, finding: EnrichedFinding) -> Optional[Dict[str, Any]]:
        """Modern browsers enforce some protections natively, reducing scanner risk."""
        if finding.detection_method != DetectionMethod.PASSIVE:
            return None

        evidence = finding.evidence or []
        raw_response = ""
        for ev in evidence:
            raw_response = getattr(ev, "raw_response", "") or ""
            if raw_response:
                break

        raw_response_lower = raw_response.lower()

        # Cookie findings with Secure/HttpOnly already present in response
        if "cookie" in finding.title.lower():
            if "secure" in raw_response_lower or "httponly" in raw_response_lower:
                return {
                    "action": "downgrade",
                    "severity": Severity.INFO,
                    "reason": "Browser-native cookie protections (Secure/HttpOnly) are present in the response.",
                    "confidence_adjustment": 0.2,
                    "drop": False,
                }

        # XSS findings in modern browsers with strong CSP
        if "xss" in finding.title.lower():
            csp_present = "content-security-policy" in raw_response_lower
            if csp_present:
                return {
                    "action": "downgrade",
                    "severity": Severity.MEDIUM if finding.severity == Severity.HIGH else finding.severity,
                    "reason": "Content-Security-Policy header is present; modern browsers provide additional XSS mitigation.",
                    "confidence_adjustment": 0.1,
                    "drop": False,
                }

        return None

    # ── Layer 5: Security Mitigations Present ────────────────────────────────

    def _check_mitigations_present(self, finding: EnrichedFinding) -> Optional[Dict[str, Any]]:
        """If multiple security mitigations are present, the finding is less likely to be exploitable."""
        evidence = finding.evidence or []
        raw_response = ""
        for ev in evidence:
            raw_response = getattr(ev, "raw_response", "") or ""
            if raw_response:
                break

        raw_response_lower = raw_response.lower()
        mitigation_count = sum(1 for h in _MITIGATION_HEADERS if h in raw_response_lower)

        if mitigation_count >= 3:
            return {
                "action": "downgrade",
                "severity": Severity.INFO if finding.severity in (Severity.LOW, Severity.MEDIUM) else Severity.MEDIUM,
                "reason": f"Multiple security mitigations present ({mitigation_count} headers); exploitability is reduced.",
                "confidence_adjustment": 0.2,
                "drop": False,
            }
        elif mitigation_count >= 2:
            return {
                "action": "downgrade",
                "severity": Severity.INFO if finding.severity == Severity.LOW else finding.severity,
                "reason": f"Security mitigations present ({mitigation_count} headers); finding confidence reduced.",
                "confidence_adjustment": 0.1,
                "drop": False,
            }

        return None

    # ── Layer 6: Known Secure Configuration ──────────────────────────────────

    def _check_secure_configuration(self, finding: EnrichedFinding) -> Optional[Dict[str, Any]]:
        """Detect known secure configurations that make the finding a false positive."""
        evidence = finding.evidence or []
        raw_response = ""
        for ev in evidence:
            raw_response = getattr(ev, "raw_response", "") or ""
            if raw_response:
                break

        raw_response_lower = raw_response.lower()

        # HSTS with preload
        if "hsts" in finding.title.lower():
            if "includesubdomains" in raw_response_lower and "preload" in raw_response_lower:
                return {
                    "action": "drop",
                    "severity": finding.severity,
                    "reason": "HSTS with includeSubdomains and preload is a known secure configuration.",
                    "confidence_adjustment": 0.0,
                    "drop": True,
                }

        # CSP with strict-dynamic + nonce/hash
        if "csp" in finding.title.lower() or "content-security-policy" in finding.title.lower():
            if "strict-dynamic" in raw_response_lower:
                nonce_present = "'nonce-" in raw_response_lower
                hash_present = "'sha256-" in raw_response_lower or "'sha384-" in raw_response_lower
                if nonce_present or hash_present:
                    return {
                        "action": "downgrade",
                        "severity": Severity.INFO,
                        "reason": "CSP with strict-dynamic and nonce/hash is a strong modern configuration that mitigates inline script risks.",
                        "confidence_adjustment": 0.2,
                        "drop": False,
                    }

        # Permissions-Policy present
        if "permissions-policy" in finding.title.lower():
            if "permissions-policy" in raw_response_lower:
                return {
                    "action": "drop",
                    "severity": finding.severity,
                    "reason": "Permissions-Policy header is already present in the response.",
                    "confidence_adjustment": 0.0,
                    "drop": True,
                }

        # Referrer-Policy present
        if "referrer-policy" in finding.title.lower():
            if "referrer-policy" in raw_response_lower:
                return {
                    "action": "drop",
                    "severity": finding.severity,
                    "reason": "Referrer-Policy header is already present in the response.",
                    "confidence_adjustment": 0.0,
                    "drop": True,
                }

        # X-XSS-Protection present
        if "x-xss-protection" in finding.title.lower():
            if "x-xss-protection" in raw_response_lower:
                return {
                    "action": "drop",
                    "severity": finding.severity,
                    "reason": "X-XSS-Protection header is already present in the response.",
                    "confidence_adjustment": 0.0,
                    "drop": True,
                }

        return None

    # ── Layer 7: Low-Value Endpoint Calibration ──────────────────────────────

    def _check_low_value_endpoint(self, finding: EnrichedFinding) -> Optional[Dict[str, Any]]:
        """Calibrate severity for low-value endpoints (static assets, media, feeds)."""
        endpoint_class = finding.endpoint_class or "Main Application"
        if endpoint_class in {"Static Assets", "Media", "Feed"}:
            if finding.severity == Severity.MEDIUM:
                return {
                    "action": "downgrade",
                    "severity": Severity.INFO,
                    "reason": f"Generic passive finding on a {endpoint_class.lower()} endpoint.",
                    "confidence_adjustment": 0.1,
                    "drop": False,
                }
            elif finding.severity == Severity.LOW:
                return {
                    "action": "downgrade",
                    "severity": Severity.INFO,
                    "reason": f"Low-severity finding on a {endpoint_class.lower()} endpoint.",
                    "confidence_adjustment": 0.1,
                    "drop": False,
                }
        return None

    # ── Helper: Extract raw response from evidence ───────────────────────────

    @staticmethod
    def _get_raw_response(finding: EnrichedFinding) -> str:
        evidence = finding.evidence or []
        for ev in evidence:
            raw = getattr(ev, "raw_response", "") or ""
            if raw:
                return raw
        return ""


class FalsePositiveReductionStep:
    """Pipeline step that applies false-positive reduction to every finding."""

    def __init__(self, http_manager: Optional[Any] = None):
        self.engine = FalsePositiveReductionEngine(http_manager)

    async def process(
        self,
        item: EnrichedFinding,
        scan_id: Optional[str] = None,
    ) -> Optional[EnrichedFinding]:
        if not isinstance(item, EnrichedFinding):
            return item

        result = self.engine.reduce(item)

        if result.dropped:
            logger.debug(
                "False-positive reduction dropped finding",
                plugin_id=item.plugin_id,
                endpoint=item.endpoint,
                reason=result.reason.value,
            )
            return None

        if result.action == "downgrade" and result.final_severity != result.original_severity:
            if item.original_severity is None:
                item.original_severity = result.original_severity
            item.severity = result.final_severity
            item.severity_reason = "; ".join(result.reasoning_chain)
            item.false_positive_reasons = list(result.reasoning_chain)
            if result.confidence_adjustment > 0:
                item.confidence_score = max(0.0, item.confidence_score - result.confidence_adjustment)

            logger.debug(
                "False-positive reduction downgraded finding",
                plugin_id=item.plugin_id,
                endpoint=item.endpoint,
                original=result.original_severity.value,
                final=result.final_severity.value,
                reason=result.reason.value,
            )
        elif result.action == "keep" and result.reasoning_chain:
            item.false_positive_reasons = list(result.reasoning_chain)

        # Compute per-finding false-positive probability
        conf_map = {"High": 0.9, "Medium": 0.6, "Low": 0.3}
        conf_score = getattr(item, "confidence_score", 0.0)
        if conf_score == 0.0:
            conf_score = conf_map.get(item.confidence.value, 0.5)
        verification_factor = 1.0 if item.is_verified else 0.0
        fp_prob = max(0.0, min(1.0, 1.0 - (conf_score * 0.7 + verification_factor * 0.3)))

        if result.action == "downgrade":
            fp_prob = min(fp_prob + 0.20, 1.0)
        elif result.action == "keep" and result.reason != FPRReason.NO_EXCEPTION:
            fp_prob = min(fp_prob + 0.10, 1.0)

        item.false_positive_probability = round(fp_prob, 3)
        return item
