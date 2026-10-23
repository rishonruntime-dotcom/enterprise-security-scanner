import structlog
from typing import List, Optional

from ...interfaces.passive import PassivePluginInterface
from ...passive.models import PluginMetadata, PassiveObservation
from ...network.models import HTTPResponse
from ...models.finding import Evidence, Severity
from ...models.standards import StandardsRegistry

logger = structlog.get_logger(__name__)


class CSPParser:
    """Parses Content-Security-Policy header strings using W3C CSP Level 3 context-aware risk evaluation."""

    @staticmethod
    def analyze_csp(csp_value: str, endpoint: str) -> List[PassiveObservation]:
        observations: List[PassiveObservation] = []
        if not csp_value:
            return observations

        directives: dict[str, set[str]] = {}
        for raw_directive in csp_value.split(";"):
            tokens = raw_directive.strip().split()
            if not tokens:
                continue
            dir_name = tokens[0].lower()
            dir_values = {t.lower() for t in tokens[1:]}
            directives[dir_name] = dir_values

        # ── Context Indicators (W3C CSP Level 3 & Trusted Types) ──────────────────
        script_sources = directives.get("script-src", directives.get("default-src", set()))
        style_sources = directives.get("style-src", directives.get("default-src", set()))
        object_sources = directives.get("object-src", directives.get("default-src", set()))
        
        has_nonce = any(v.startswith("'nonce-") for v in script_sources)
        has_hash = any(v.startswith("'sha256-") or v.startswith("'sha384-") or v.startswith("'sha512-") for v in script_sources)
        has_strict_dynamic = "'strict-dynamic'" in script_sources
        has_trusted_types = "require-trusted-types-for" in directives or "trusted-types" in directives

        # 1. script-src: 'unsafe-inline' Contextual Evaluation
        if "'unsafe-inline'" in script_sources:
            # W3C CSP Level 3 Rule: Modern browsers IGNORE 'unsafe-inline' if 'strict-dynamic' + (nonce|hash) is present.
            # 'unsafe-inline' is included strictly for backward compatibility with CSP Level 1 browsers.
            if has_strict_dynamic and (has_nonce or has_hash):
                logger.debug("CSP 'unsafe-inline' is overridden by 'strict-dynamic' and nonce/hash (W3C CSP3 compliance)", endpoint=endpoint)
                # Fully mitigated in modern browsers — emit Info or skip to prevent false positives
            elif has_nonce or has_hash:
                # CSP Level 2 Rule: Nonces/hashes override 'unsafe-inline' in CSP2+ browsers
                observations.append(
                    PassiveObservation(
                        plugin_id="PASS-001-CSP-SCRIPT-INLINE",
                        observation_type="csp_directive_weakness",
                        title="CSP Notice: 'script-src' Contains Backward-Compatible 'unsafe-inline'",
                        description="The CSP contains 'unsafe-inline' alongside nonces/hashes for legacy browser backward compatibility. Modern browsers enforce nonces and ignore 'unsafe-inline'.",
                        severity=Severity.INFO,
                        evidence=[
                            Evidence(
                                type="csp_directive",
                                description="script-src contains 'unsafe-inline' overridden by nonce/hash",
                                data={"directive": "script-src", "values": list(script_sources), "has_nonce": has_nonce, "has_hash": has_hash}
                            )
                        ],
                        endpoint=endpoint,
                        remediation="No immediate action required if modern browsers are targeted. Remove 'unsafe-inline' when dropping legacy browser support.",
                        **StandardsRegistry.get("missing_csp").__dict__
                    )
                )
            else:
                # True Vulnerability: Unrestricted inline scripts without nonce/hash/strict-dynamic
                observations.append(
                    PassiveObservation(
                        plugin_id="PASS-001-CSP-SCRIPT-INLINE",
                        observation_type="csp_directive_weakness",
                        title="CSP Directive Misconfiguration: Unrestricted 'script-src' Allows 'unsafe-inline'",
                        description="The Content-Security-Policy contains 'unsafe-inline' in script-src without nonces, hashes, or strict-dynamic, allowing arbitrary inline JavaScript execution (XSS risk).",
                        severity=Severity.MEDIUM,
                        evidence=[
                            Evidence(
                                type="csp_directive",
                                description="script-src directive contains unrestricted 'unsafe-inline'",
                                data={"directive": "script-src", "values": list(script_sources), "raw_csp": csp_value}
                            )
                        ],
                        endpoint=endpoint,
                        remediation="Remove 'unsafe-inline' from script-src and use nonces, cryptographic hashes, or 'strict-dynamic'.",
                        **StandardsRegistry.get("missing_csp").__dict__
                    )
                )

        # 2. script-src: 'unsafe-eval' Contextual Evaluation
        if "'unsafe-eval'" in script_sources:
            if has_trusted_types:
                # Trusted Types enforcement mitigates string-to-code DOM XSS primitives
                observations.append(
                    PassiveObservation(
                        plugin_id="PASS-001-CSP-SCRIPT-EVAL",
                        observation_type="csp_directive_weakness",
                        title="CSP Notice: 'script-src' Allows 'unsafe-eval' (Mitigated by Trusted Types)",
                        description="The CSP allows 'unsafe-eval', but DOM XSS string primitives are restricted by 'require-trusted-types-for'.",
                        severity=Severity.INFO,
                        evidence=[
                            Evidence(
                                type="csp_directive",
                                description="script-src allows 'unsafe-eval' under Trusted Types",
                                data={"directive": "script-src", "values": list(script_sources), "trusted_types": True}
                            )
                        ],
                        endpoint=endpoint,
                        remediation="Audit code for eval() usage and transition to Trusted Types policies.",
                        **StandardsRegistry.get("missing_csp").__dict__
                    )
                )
            else:
                observations.append(
                    PassiveObservation(
                        plugin_id="PASS-001-CSP-SCRIPT-EVAL",
                        observation_type="csp_directive_weakness",
                        title="CSP Directive Misconfiguration: 'script-src' Allows 'unsafe-eval'",
                        description="The Content-Security-Policy contains 'unsafe-eval' in script-src, permitting string-to-code execution primitives (e.g., eval, setTimeout).",
                        severity=Severity.LOW,
                        evidence=[
                            Evidence(
                                type="csp_directive",
                                description="script-src directive contains 'unsafe-eval'",
                                data={"directive": "script-src", "values": list(script_sources), "raw_csp": csp_value}
                            )
                        ],
                        endpoint=endpoint,
                        remediation="Remove 'unsafe-eval' from script-src or enforce Trusted Types.",
                        **StandardsRegistry.get("missing_csp").__dict__
                    )
                )

        # 3. script-src: Wildcard & HTTP Sources (Overridden by 'strict-dynamic')
        if ("*" in script_sources or "http:" in script_sources) and not has_strict_dynamic:
            observations.append(
                PassiveObservation(
                    plugin_id="PASS-001-CSP-SCRIPT-WILDCARD",
                    observation_type="csp_directive_weakness",
                    title="CSP Directive Misconfiguration: 'script-src' Allows Wildcard or Unencrypted Sources",
                    description="The script-src directive permits arbitrary external domains (*) or unencrypted HTTP sources without 'strict-dynamic' restriction.",
                    severity=Severity.MEDIUM,
                    evidence=[
                        Evidence(
                            type="csp_directive",
                            description="script-src allows wildcard or unencrypted http:",
                            data={"directive": "script-src", "values": list(script_sources)}
                        )
                    ],
                    endpoint=endpoint,
                    remediation="Restrict script-src to explicit trusted domain origins over HTTPS or use 'strict-dynamic'.",
                    **StandardsRegistry.get("missing_csp").__dict__
                )
            )

        # 4. style-src: 'unsafe-inline'
        if "'unsafe-inline'" in style_sources:
            observations.append(
                PassiveObservation(
                    plugin_id="PASS-001-CSP-STYLE-INLINE",
                    observation_type="csp_directive_weakness",
                    title="CSP Directive Misconfiguration: 'style-src' Allows 'unsafe-inline'",
                    description="The Content-Security-Policy contains 'unsafe-inline' in style-src, allowing arbitrary inline style attributes and style blocks.",
                    severity=Severity.LOW,
                    evidence=[
                        Evidence(
                            type="csp_directive",
                            description="style-src directive contains 'unsafe-inline'",
                            data={"directive": "style-src", "values": list(style_sources)}
                        )
                    ],
                    endpoint=endpoint,
                    remediation="Remove 'unsafe-inline' from style-src and use hashes or external stylesheets.",
                    **StandardsRegistry.get("missing_csp").__dict__
                )
            )

        # 5. Missing default-src Fallback (Policy Completeness Check)
        if "default-src" not in directives:
            major_directives = {"script-src", "style-src", "img-src", "connect-src", "object-src", "font-src"}
            is_complete = major_directives.issubset(set(directives.keys()))
            
            if not is_complete:
                observations.append(
                    PassiveObservation(
                        plugin_id="PASS-001-CSP-MISSING-DEFAULT",
                        observation_type="csp_directive_weakness",
                        title="CSP Directive Weakness: Missing 'default-src' Fallback Directive",
                        description="The Content-Security-Policy lacks a 'default-src' directive and does not cover all resource types.",
                        severity=Severity.LOW,
                        evidence=[
                            Evidence(
                                type="csp_directive",
                                description="Content-Security-Policy missing default-src directive",
                                data={"existing_directives": list(directives.keys())}
                            )
                        ],
                        endpoint=endpoint,
                        remediation="Define 'default-src \\'self\\'' as a fallback for unmentioned resource types.",
                        **StandardsRegistry.get("missing_csp").__dict__
                    )
                )

        # 6. object-src directives
        if "'none'" not in object_sources and "'none'" not in directives.get("default-src", set()):
            observations.append(
                PassiveObservation(
                    plugin_id="PASS-001-CSP-OBJECT-SRC",
                    observation_type="csp_directive_weakness",
                    title="CSP Directive Weakness: 'object-src' Not Set to 'none'",
                    description="The object-src directive is not set to 'none', allowing execution of legacy plugin objects (Flash, Java, ActiveX).",
                    severity=Severity.LOW,
                    evidence=[
                        Evidence(
                            type="csp_directive",
                            description="object-src is missing or not set to 'none'",
                            data={"directive": "object-src", "values": list(object_sources)}
                        )
                    ],
                    endpoint=endpoint,
                    remediation="Set 'object-src \\'none\\'' in Content-Security-Policy.",
                    **StandardsRegistry.get("missing_csp").__dict__
                )
            )

        # 7. base-uri directive
        if "base-uri" not in directives:
            observations.append(
                PassiveObservation(
                    plugin_id="PASS-001-CSP-MISSING-BASEURI",
                    observation_type="csp_directive_weakness",
                    title="CSP Directive Weakness: Missing 'base-uri' Directive",
                    description="The Content-Security-Policy lacks a 'base-uri' directive, allowing potential base tag injection attacks.",
                    severity=Severity.LOW,
                    evidence=[
                        Evidence(
                            type="csp_directive",
                            description="Content-Security-Policy missing base-uri directive",
                            data={"raw_csp": csp_value}
                        )
                    ],
                    endpoint=endpoint,
                    remediation="Set 'base-uri \\'self\\'' in Content-Security-Policy.",
                    **StandardsRegistry.get("missing_csp").__dict__
                )
            )

        return observations


class MissingSecurityHeadersPlugin(PassivePluginInterface):
    """Detects missing security headers like HSTS, CSP, and X-Frame-Options, and parses CSP directives granularly."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="PASS-001",
            name="Security Header and CSP Directive Analyzer",
            description="Checks response headers for security-hardening configs (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) and parses CSP into distinct actionable directive findings."
        )

    @staticmethod
    def _detect_reverse_proxy(headers_lower: dict) -> Optional[str]:
        specific_proxies = ["nginx", "apache", "cloudflare", "varnish", "squid"]
        proxy_headers = ["x-forwarded-for", "x-forwarded-host", "via", "forwarded", "x-real-ip"]
        
        all_values = []
        for h in proxy_headers:
            if h in headers_lower:
                all_values.append(headers_lower[h].lower())
        
        for val in all_values:
            for proxy in specific_proxies:
                if proxy in val:
                    return proxy
        
        if all_values:
            return "generic"
        return None

    @staticmethod
    def _detect_cdn(headers_lower: dict) -> Optional[str]:
        server = headers_lower.get("server", "")
        if "cloudflare" in server.lower():
            return "cloudflare"
        if "akamai" in server.lower():
            return "akamai"
        if "fastly" in server.lower():
            return "fastly"
        if "amazon" in server.lower() or "aws" in server.lower():
            return "aws"
        for h in ["cf-ray", "x-cache", "x-served-by", "x-cache-hits", "x-cache-status", "x-amz-cf-id"]:
            if h in headers_lower:
                if h.startswith("cf-"):
                    return "cloudflare"
                if h.startswith("x-amz"):
                    return "aws"
                if "akamai" in headers_lower.get(h, "").lower():
                    return "akamai"
                return "generic"
        return None

    @staticmethod
    def _check_hsts_preload(headers_lower: dict) -> Optional[bool]:
        hsts = headers_lower.get("strict-transport-security", "")
        if hsts:
            return "preload" in hsts.lower()
        return None

    @staticmethod
    def _detect_redirect(response: HTTPResponse) -> Optional[bool]:
        if response.status_code in (301, 302, 303, 307, 308):
            return True
        if response.request and response.request.url != response.url:
            return True
        return None

    @staticmethod
    def _get_csp_protections(headers_lower: dict) -> Optional[List[str]]:
        csp = headers_lower.get("content-security-policy", "")
        if not csp:
            return None
        protections = []
        csp_lower = csp.lower()
        if "default-src 'self'" in csp_lower or "default-src \"self\"" in csp_lower:
            protections.append("default-src 'self'")
        if "'nonce-" in csp_lower:
            protections.append("nonce-based scripts")
        if "'sha" in csp_lower:
            protections.append("hash-based scripts")
        if "strict-dynamic" in csp_lower:
            protections.append("strict-dynamic")
        if "require-trusted-types-for" in csp_lower:
            protections.append("Trusted Types")
        if "object-src 'none'" in csp_lower:
            protections.append("object-src 'none'")
        if "frame-ancestors" in csp_lower:
            protections.append("frame-ancestors")
        if "upgrade-insecure-requests" in csp_lower:
            protections.append("upgrade-insecure-requests")
        if "report-uri" in csp_lower or "report-to" in csp_lower:
            protections.append("violation reporting")
        return protections if protections else None

    @staticmethod
    def _get_browser_defaults_note(header_name: str) -> Optional[str]:
        notes = {
            "x-content-type-options": "Browsers perform MIME sniffing by default; 'nosniff' disables this behavior.",
            "x-xss-protection": "Modern browsers have built-in XSS filters; this header enables legacy XSS auditor.",
            "referrer-policy": "Browsers default to sending full referrer on same-origin and stripped on cross-origin.",
            "permissions-policy": "Browsers increasingly restrict risky APIs by default; this header provides explicit control.",
        }
        return notes.get(header_name.lower())

    def _build_enriched_evidence(self, header_name: str, extra_data: dict = None) -> List[Evidence]:
        data = {"missing_header": header_name}
        if extra_data:
            data.update(extra_data)
        return [Evidence(type="missing_header", description=f"Response headers received without {header_name}.", data=data)]

    def _adjust_severity_for_context(self, base_severity: Severity, response: HTTPResponse, headers_lower: dict) -> Severity:
        cdn = self._detect_cdn(headers_lower)
        proxy = self._detect_reverse_proxy(headers_lower)
        redirect = self._detect_redirect(response)
        csp_protections = self._get_csp_protections(headers_lower)

        downgrade = 0
        if cdn:
            downgrade += 1
        if proxy:
            downgrade += 1
        if redirect and "strict-transport-security" not in headers_lower:
            downgrade += 1
        if csp_protections and "frame-ancestors" in csp_protections:
            downgrade += 1

        if downgrade >= 2 and base_severity == Severity.LOW:
            return Severity.INFO
        return base_severity

    def analyze(self, response: HTTPResponse) -> List[PassiveObservation]:
        observations: List[PassiveObservation] = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        proxy_type = self._detect_reverse_proxy(headers_lower)
        cdn_provider = self._detect_cdn(headers_lower)
        hsts_preload = self._check_hsts_preload(headers_lower)
        redirect_observed = self._detect_redirect(response)
        csp_protections = self._get_csp_protections(headers_lower)

        common_kwargs = {
            "proxy_type": proxy_type,
            "cdn_provider": cdn_provider,
            "hsts_preload": hsts_preload,
            "redirect_observed": redirect_observed,
            "csp_protections_present": csp_protections,
        }

        # 0. Duplicate Header Check (e.g. duplicate HSTS or CSP headers)
        for h_key, h_val in response.headers.items():
            if h_val and (h_val.count("max-age=") > 1 or h_val.count("default-src") > 1):
                observations.append(
                    PassiveObservation(
                        plugin_id=self.metadata.id,
                        observation_type="duplicate_header",
                        title=f"Duplicate Security Header Detected ({h_key})",
                        description=f"The server returned multiple or duplicated '{h_key}' headers, which may cause browsers to ignore the policy or act unpredictably.",
                        severity=Severity.LOW,
                        evidence=[Evidence(type="duplicate_header", description=f"Duplicate {h_key} header value.", data={"header_name": h_key, "header_value": h_val})],
                        endpoint=response.url,
                        remediation=f"Ensure only a single '{h_key}' header is returned in web responses.",
                        **StandardsRegistry.get("missing_hsts").__dict__,
                        **common_kwargs
                    )
                )

        # 1. HSTS
        if response.url.startswith("https") and "strict-transport-security" not in headers_lower:
            severity = self._adjust_severity_for_context(Severity.LOW, response, headers_lower)
            extra = {}
            if proxy_type:
                extra["proxy_note"] = f"Reverse proxy '{proxy_type}' detected; HSTS may be configured at the proxy level."
            if cdn_provider:
                extra["cdn_note"] = f"CDN '{cdn_provider}' detected; HSTS may be managed by the CDN."
            if redirect_observed:
                extra["redirect_note"] = "HTTP->HTTPS redirect observed, providing partial transport security."
            observations.append(
                PassiveObservation(
                    plugin_id=self.metadata.id,
                    observation_type="missing_header",
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    description="The server does not enforce encrypted connections via HSTS, leaving users vulnerable to SSL stripping/downgrade attacks.",
                    severity=severity,
                    evidence=[
                        Evidence(
                            type="missing_header",
                            description="Response headers received without HSTS.",
                            data=self._build_enriched_evidence("Strict-Transport-Security", extra)[0].data
                        )
                    ],
                    endpoint=response.url,
                    remediation="Set the Strict-Transport-Security header.",
                    **StandardsRegistry.get("missing_hsts").__dict__,
                    **common_kwargs
                )
            )

        # 2. Clickjacking (X-Frame-Options / CSP frame-ancestors)
        has_xfo = "x-frame-options" in headers_lower
        has_csp_framing = "content-security-policy" in headers_lower and "frame-ancestors" in headers_lower["content-security-policy"].lower()
        if not has_xfo and not has_csp_framing:
            extra = {}
            if csp_protections and "frame-ancestors" not in csp_protections:
                extra["csp_note"] = "CSP is present but lacks frame-ancestors directive."
            observations.append(
                PassiveObservation(
                    plugin_id=self.metadata.id,
                    observation_type="missing_header",
                    title="Missing Anti-Clickjacking Headers",
                    description="The response lacks anti-clickjacking headers (X-Frame-Options or CSP frame-ancestors directive), allowing attackers to embed the page inside malicious frames.",
                    severity=Severity.LOW,
                    evidence=[
                        Evidence(
                            type="missing_header",
                            description="Response headers lack X-Frame-Options and CSP frame-ancestors.",
                            data=self._build_enriched_evidence("X-Frame-Options / CSP frame-ancestors", extra)[0].data
                        )
                    ],
                    endpoint=response.url,
                    remediation="Implement a Content-Security-Policy header.",
                    **StandardsRegistry.get("missing_csp").__dict__,
                    **common_kwargs
                )
            )

        # 3. Content-Security-Policy (CSP) is evaluated by PASS-006 (Context-Aware CSP Reasoning Engine)
        #    This plugin intentionally skips CSP directive-level findings to avoid duplicates.

        # 4. X-Content-Type-Options (MIME sniffing)
        if "x-content-type-options" not in headers_lower:
            browser_note = self._get_browser_defaults_note("x-content-type-options")
            extra = {}
            if browser_note:
                extra["browser_default"] = browser_note
            observations.append(
                PassiveObservation(
                    plugin_id=self.metadata.id,
                    observation_type="missing_header",
                    title="Missing X-Content-Type-Options Header",
                    description="The response does not send X-Content-Type-Options: nosniff, leaving browsers to interpret files based on content rather than declaring MIME type.",
                    severity=Severity.LOW,
                    evidence=[
                        Evidence(
                            type="missing_header",
                            description="Response headers received without X-Content-Type-Options.",
                            data=self._build_enriched_evidence("X-Content-Type-Options", extra)[0].data
                        )
                    ],
                    endpoint=response.url,
                    remediation="Set X-Content-Type-Options to nosniff.",
                    **StandardsRegistry.get("missing_x_content_type_options").__dict__,
                    **common_kwargs,
                    browser_defaults_applicable=bool(browser_note)
                )
            )

        # 5. Referrer-Policy
        if "referrer-policy" not in headers_lower:
            browser_note = self._get_browser_defaults_note("referrer-policy")
            extra = {}
            if browser_note:
                extra["browser_default"] = browser_note
            observations.append(
                PassiveObservation(
                    plugin_id=self.metadata.id,
                    observation_type="missing_header",
                    title="Missing Referrer-Policy Header",
                    description="The server did not return a Referrer-Policy header, which controls how much referrer information is passed to external links.",
                    severity=Severity.INFO,
                    evidence=[
                        Evidence(
                            type="missing_header",
                            description="Response headers received without Referrer-Policy.",
                            data=self._build_enriched_evidence("Referrer-Policy", extra)[0].data
                        )
                    ],
                    endpoint=response.url,
                    remediation="Set Referrer-Policy to strict-origin-when-cross-origin or similar.",
                    **StandardsRegistry.get("missing_referrer_policy").__dict__,
                    **common_kwargs,
                    browser_defaults_applicable=bool(browser_note)
                )
            )

        # 6. Permissions-Policy (Feature-Policy)
        if "permissions-policy" not in headers_lower:
            browser_note = self._get_browser_defaults_note("permissions-policy")
            extra = {}
            if browser_note:
                extra["browser_default"] = browser_note
            observations.append(
                PassiveObservation(
                    plugin_id=self.metadata.id,
                    observation_type="missing_header",
                    title="Missing Permissions-Policy Header",
                    description="The server did not send a Permissions-Policy header to restrict access to hardware APIs (geolocation, camera, microphone, etc.).",
                    severity=Severity.INFO,
                    evidence=[
                        Evidence(
                            type="missing_header",
                            description="Response headers received without Permissions-Policy.",
                            data=self._build_enriched_evidence("Permissions-Policy", extra)[0].data
                        )
                    ],
                    endpoint=response.url,
                    remediation="Configure the server with standard permissions exclusions, e.g. 'Permissions-Policy: geolocation=()'.",
                    **StandardsRegistry.get("missing_x_content_type_options").__dict__,  # generic 693
                    **common_kwargs,
                    browser_defaults_applicable=bool(browser_note)
                )
            )

        return observations
