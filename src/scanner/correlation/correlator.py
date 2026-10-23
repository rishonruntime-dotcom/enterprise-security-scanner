"""Evidence-based cross-finding correlation.

Correlation intentionally has a narrow rule set: a combined finding is only
created when independent observations establish an exploit chain.  It is not a
second deduplication pass and does not infer vulnerabilities from hardening
observations alone.
"""
from collections import defaultdict
from typing import Iterable, List
from urllib.parse import urlparse

from ..models.finding import Confidence, DetectionMethod, Evidence, Severity, VerificationStatus
from .models import EnrichedFinding, VulnerabilityIntelligence


_BROWSER_SECURITY_HEADERS = {
    "hsts", "strict-transport-security",
    "content-security-policy", "csp",
    "x-frame-options", "anti-clickjacking",
    "x-content-type-options",
    "referrer-policy", "permissions-policy",
}


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FindingCorrelator:
    """Create actionable attack-chain findings from verified component findings."""

    RULE_ID = "CORR-XSS-CSP-001"
    BROWSER_SECURITY_RULE_ID = "CORR-SECURITY-HEADERS-001"
    ATTACK_CHAIN_RULE_ID = "CORR-ATTACK-CHAIN-XSS-SESSION-001"

    def correlate(self, findings: Iterable[EnrichedFinding]) -> list[EnrichedFinding]:
        source_findings = list(findings)
        by_host: dict[str, list[EnrichedFinding]] = defaultdict(list)
        for finding in source_findings:
            host = self._host_key(finding.endpoint)
            if host:
                by_host[host].append(finding)

        consumed: set[int] = set()
        correlated: list[EnrichedFinding] = []
        for host_findings in by_host.values():
            xss_findings = [f for f in host_findings if self._is_verified_xss(f)]
            csp_findings = [f for f in host_findings if self._is_material_csp_weakness(f)]
            session_cookie_findings = [f for f in host_findings if self._is_session_theft_risk(f)]

            # Attack-chain correlation: Verified XSS + Material CSP weakness + Insecure session cookie
            if xss_findings and csp_findings and session_cookie_findings:
                supporting = [*xss_findings, *csp_findings, *session_cookie_findings]
                correlated.append(self._build_attack_chain_correlation(supporting))
                consumed.update(id(f) for f in supporting)
                continue

            if not xss_findings or not csp_findings:
                continue

            supporting = [*xss_findings, *csp_findings]
            correlated.append(self._build_xss_csp_correlation(supporting, xss_findings[0]))
            consumed.update(id(finding) for finding in supporting)

        # Group missing browser-security-header findings by host into a single
        # aggregated "Weak Browser Security Configuration" finding.
        for host, host_findings in by_host.items():
            header_findings = [
                f for f in host_findings
                if self._is_browser_security_header_finding(f) and id(f) not in consumed
            ]
            if len(header_findings) >= 2:
                correlated.append(self._build_browser_security_correlation(header_findings))
                consumed.update(id(f) for f in header_findings)

        # Correlated findings replace only the component findings that support
        # the proven chain; unrelated observations remain independently visible.
        return [finding for finding in source_findings if id(finding) not in consumed] + correlated

    @staticmethod
    def _host_key(endpoint: str) -> str:
        try:
            parsed = urlparse(endpoint)
            return (parsed.netloc or parsed.path).lower()
        except Exception:
            return ""

    @staticmethod
    def _is_verified_xss(finding: EnrichedFinding) -> bool:
        title = finding.title.lower()
        cwe_id = getattr(finding.intelligence, "cwe_id", None) if finding.intelligence else None
        return (
            finding.is_verified
            and finding.verification_status == VerificationStatus.VERIFIED
            and (finding.plugin_id == "ACT-XSS-001" or cwe_id == "CWE-79" or "cross-site scripting" in title or "xss" in title)
        )

    @staticmethod
    def _is_material_csp_weakness(finding: EnrichedFinding) -> bool:
        title = finding.title.lower()
        csp_related = finding.plugin_id.startswith("PASS-001-CSP-") or "content-security-policy" in title or "csp " in title
        mitigated = any(marker in title for marker in ("notice", "mitigated", "backward-compatible"))
        return csp_related and not mitigated and finding.severity != Severity.INFO

    @staticmethod
    def _is_missing_csp(finding: EnrichedFinding) -> bool:
        """Identify findings specifically about a missing Content-Security-Policy header."""
        title = finding.title.lower()
        plugin = finding.plugin_id
        if plugin.startswith("PASS-006") and "missing content-security-policy" in title:
            return True
        if plugin.startswith("PASS-001-CSP-MISSING"):
            return True
        return False

    @staticmethod
    def _is_session_theft_risk(finding: EnrichedFinding) -> bool:
        """Identify cookie findings that expose sensitive session tokens to XSS-based theft."""
        if finding.plugin_id != "PASS-002":
            return False
        title_lower = finding.title.lower()
        if "cookie security configuration" not in title_lower:
            return False
        if not any(evidence.data for evidence in finding.evidence if isinstance(evidence.data, dict)):
            return False
        cookie_type = None
        for evidence in finding.evidence:
            if isinstance(evidence.data, dict):
                detection_ev = evidence.data.get("detection_evidence", {})
                if isinstance(detection_ev, dict):
                    obs = detection_ev.get("observation", {})
                    if isinstance(obs, dict):
                        cookie_type = obs.get("cookie_type")
                        if cookie_type:
                            break
        sensitive_types = {"session", "authentication", "oauth"}
        return cookie_type in sensitive_types if cookie_type else False

    @staticmethod
    def _is_browser_security_header_finding(finding: EnrichedFinding) -> bool:
        title = finding.title.lower()
        plugin = finding.plugin_id
        is_pass_header = plugin == "PASS-001" and "missing" in title and any(
            kw in title for kw in _BROWSER_SECURITY_HEADERS
        )
        is_pass_csp_missing = plugin.startswith("PASS-006") and "missing content-security-policy" in title
        return is_pass_header or is_pass_csp_missing

    @staticmethod
    def _build_attack_chain_correlation(supporting: list[EnrichedFinding]) -> EnrichedFinding:
        """Build a single finding representing the Missing CSP → XSS → Session Theft chain."""
        xss_finding = next(f for f in supporting if FindingCorrelator._is_verified_xss(f))
        csp_finding = next(f for f in supporting if FindingCorrelator._is_material_csp_weakness(f))
        session_finding = next(f for f in supporting if FindingCorrelator._is_session_theft_risk(f))

        source_records = [
            {
                "plugin_id": finding.plugin_id,
                "title": finding.title,
                "endpoint": finding.endpoint,
                "severity": finding.severity.value,
                "verification_status": finding.verification_status.value,
                "deduplication_hash": finding.deduplication_hash,
            }
            for finding in supporting
        ]

        causal_edges = [
            {
                "edge_id": "EDGE-01",
                "source_finding": {
                    "title": csp_finding.title,
                    "endpoint": csp_finding.endpoint,
                    "plugin_id": csp_finding.plugin_id,
                    "finding_type": "Mitigation Weakness",
                },
                "causal_relationship": "Prerequisite Absence of Script Execution Boundary",
                "technical_mechanism": "Browser permits unconstrained inline script execution without Content-Security-Policy restrictions.",
                "destination_finding": {
                    "title": xss_finding.title,
                    "endpoint": xss_finding.endpoint,
                    "plugin_id": xss_finding.plugin_id,
                    "finding_type": "Executable Vulnerability",
                },
            },
            {
                "edge_id": "EDGE-02",
                "source_finding": {
                    "title": xss_finding.title,
                    "endpoint": xss_finding.endpoint,
                    "plugin_id": xss_finding.plugin_id,
                    "finding_type": "Executable Vulnerability",
                },
                "causal_relationship": "Arbitrary JavaScript Execution Context in Victim Session",
                "technical_mechanism": "Injected script reads un-flagged session tokens via `document.cookie` API and exfiltrates payload to attacker endpoint.",
                "destination_finding": {
                    "title": session_finding.title,
                    "endpoint": session_finding.endpoint,
                    "plugin_id": session_finding.plugin_id,
                    "finding_type": "Compromised Authentication Asset",
                },
            },
        ]

        evidence = Evidence(
            type="finding_correlation",
            description=(
                "A Content-Security-Policy weakness, a verified reflected XSS, and an insecure "
                "session cookie were observed on the same origin, forming an exploitable attack chain."
            ),
            data={
                "correlation_rule": FindingCorrelator.ATTACK_CHAIN_RULE_ID,
                "correlation_confidence": "high",
                "causal_edges": causal_edges,
                "chain": [
                    "Weak/absent Content-Security-Policy",
                    "Verified Reflected XSS",
                    "Insecure session cookie accessible to XSS",
                ],
                "supporting_findings": source_records,
                "rationale": (
                    "Without a restrictive CSP, a verified XSS sink can execute arbitrary JavaScript "
                    "in the victim's browser. An insecure session cookie (missing Secure/HttpOnly) "
                    "can then be exfiltrated via the XSS, enabling session theft."
                ),
            },
        )

        risk = xss_finding.risk.model_copy(deep=True) if xss_finding.risk else None
        if risk:
            risk.evidence_quality_score = max(risk.evidence_quality_score, 0.95)
            risk.risk_explanation = (
                "Verified XSS with absent CSP enables session theft via an insecure cookie chain."
            )

        return EnrichedFinding(
            plugin_id=FindingCorrelator.ATTACK_CHAIN_RULE_ID,
            title="Session Theft via XSS enabled by Weak Content Security Policy",
            description=(
                f"On {FindingCorrelator._host_key(xss_finding.endpoint)}, a {csp_finding.title.lower()} "
                "and a verified reflected XSS were observed together with an insecure session cookie. "
                "An attacker can inject JavaScript via the XSS sink (unmitigated by CSP) to steal the "
                "session cookie and hijack the victim's session."
            ),
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            confidence_score=0.9,
            endpoint=xss_finding.endpoint,
            endpoint_class=xss_finding.endpoint_class,
            evidence=[evidence],
            remediation=(
                "1. Fix the verified XSS sink via input validation and output encoding. "
                "2. Deploy a restrictive Content-Security-Policy with script-src 'self' (no 'unsafe-inline'), "
                "using nonces or hashes for legitimate inline scripts. "
                "3. Mark the session cookie with Secure, HttpOnly, and SameSite=Strict or Lax attributes."
            ),
            references=xss_finding.references,
            detection_method=DetectionMethod.ACTIVE,
            verification_status=VerificationStatus.VERIFIED,
            verification_details="Attack chain confirmed: verified XSS + CSP weakness + insecure session cookie on the same origin.",
            is_verified=True,
            intelligence=VulnerabilityIntelligence(
                cwe_id="CWE-79",
                cwe_name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                owasp_category="A03:2021-Injection",
                capec_id="CAPEC-63",
                description="Verified XSS with absent CSP enables session theft via an insecure cookie chain.",
            ),
            attack_payload=xss_finding.attack_payload,
            affected_parameter=xss_finding.affected_parameter,
            risk=risk,
            evidence_score=0.95,
            merge_count=len(supporting),
            priority_score=9.5,
        )

    @staticmethod
    def _build_browser_security_correlation(supporting: list[EnrichedFinding]) -> EnrichedFinding:
        titles = [finding.title for finding in supporting]
        host_endpoint = supporting[0].endpoint
        host = FindingCorrelator._host_key(host_endpoint)

        highest = max(
            (finding.severity for finding in supporting),
            key=lambda severity: _SEVERITY_ORDER[severity],
        )

        source_records = [
            {
                "plugin_id": finding.plugin_id,
                "title": finding.title,
                "endpoint": finding.endpoint,
                "severity": finding.severity.value,
                "verification_status": finding.verification_status.value,
                "deduplication_hash": finding.deduplication_hash,
            }
            for finding in supporting
        ]

        evidence = Evidence(
            type="finding_correlation",
            description=(
                f"Multiple missing browser-security headers were observed on the same origin ({host}). "
                f"Affected headers: {', '.join(titles)}."
            ),
            data={
                "correlation_rule": FindingCorrelator.BROWSER_SECURITY_RULE_ID,
                "correlation_confidence": "medium",
                "supporting_findings": source_records,
                "rationale": (
                    "The absence of multiple browser-side security headers weakens the application's "
                    "defense-in-depth posture, increasing exposure to clickjacking, MIME-sniffing, "
                    "SSL-stripping, and script-injection attacks."
                ),
            },
        )

        return EnrichedFinding(
            plugin_id=FindingCorrelator.BROWSER_SECURITY_RULE_ID,
            title="Weak Browser Security Configuration",
            description=(
                f"Multiple browser-security-hardening headers are absent from responses served by {host}. "
                f"This reduces browser-side mitigations and increases exposure to clickjacking, "
                f"MIME-sniffing, SSL-stripping, and script-injection attacks."
            ),
            severity=highest,
            confidence=Confidence.HIGH,
            confidence_score=0.8,
            endpoint=host_endpoint,
            endpoint_class=supporting[0].endpoint_class,
            evidence=[evidence],
            remediation=(
                "Implement the following security headers site-wide: "
                "Strict-Transport-Security, Content-Security-Policy, X-Frame-Options (or CSP frame-ancestors), "
                "X-Content-Type-Options: nosniff, Referrer-Policy, and Permissions-Policy."
            ),
            references=[],
            detection_method=DetectionMethod.PASSIVE,
            verification_status=VerificationStatus.NOT_ACTIVELY_VERIFIED,
            verification_details="Correlated from passive observations of missing security headers on the same origin.",
            is_verified=False,
            intelligence=VulnerabilityIntelligence(
                cwe_id="CWE-693",
                cwe_name="Protection Mechanism Failure",
                owasp_category="A05:2021-Security Misconfiguration",
                capec_id="CAPEC-34",
            ),
            merge_count=len(supporting),
        )

    @staticmethod
    def _build_xss_csp_correlation(
        supporting: list[EnrichedFinding],
        primary_xss: EnrichedFinding,
    ) -> EnrichedFinding:
        highest = max((finding.severity for finding in supporting), key=lambda severity: _SEVERITY_ORDER[severity])
        severity = max(highest, Severity.HIGH, key=lambda value: _SEVERITY_ORDER[value])
        source_records = [
            {
                "plugin_id": finding.plugin_id,
                "title": finding.title,
                "endpoint": finding.endpoint,
                "verification_status": finding.verification_status.value,
                "deduplication_hash": finding.deduplication_hash,
            }
            for finding in supporting
        ]
        evidence = Evidence(
            type="finding_correlation",
            description="A verified reflected XSS condition and an unmitigated CSP weakness were observed on the same origin.",
            data={
                "correlation_rule": FindingCorrelator.RULE_ID,
                "correlation_confidence": "high",
                "supporting_findings": source_records,
                "rationale": "Weak CSP does not create XSS, but it removes an important browser-side mitigation for the verified XSS condition.",
            },
        )
        risk = primary_xss.risk.model_copy(deep=True) if primary_xss.risk else None
        if risk:
            risk.evidence_quality_score = max(risk.evidence_quality_score, 0.9)
            risk.risk_explanation = "Verified XSS is correlated with a material CSP weakness on the same origin."

        return EnrichedFinding(
            plugin_id=FindingCorrelator.RULE_ID,
            title="High likelihood of exploitable XSS due to weak Content Security Policy",
            description=(
                "A verified cross-site scripting condition was found together with a material Content Security Policy weakness on the same origin. "
                "The CSP weakness reduces browser-side containment, increasing the likelihood and impact of successful XSS exploitation."
            ),
            severity=severity,
            confidence=Confidence.MEDIUM,
            confidence_score=0.5,
            endpoint=primary_xss.endpoint,
            endpoint_class=primary_xss.endpoint_class,
            evidence=[evidence],
            remediation=(
                "Remediate the verified XSS sink/source and deploy a restrictive script-src policy without unsafe-inline, "
                "using nonces or hashes where inline scripts are required."
            ),
            references=primary_xss.references,
            detection_method=DetectionMethod.ACTIVE,
            verification_status=VerificationStatus.VERIFIED,
            verification_details="Correlated from verified XSS evidence and CSP configuration evidence on the same origin.",
            is_verified=True,
            intelligence=VulnerabilityIntelligence(
                cwe_id="CWE-79",
                cwe_name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                owasp_category="A03:2021-Injection",
                capec_id="CAPEC-63",
                description="Verified XSS with weakened browser-side script execution controls.",
            ),
            risk=risk,
            evidence_score=0.9,
            merge_count=len(supporting),
        )
