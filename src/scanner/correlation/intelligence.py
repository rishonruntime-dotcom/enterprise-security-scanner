from typing import Optional, Dict
from .pipeline import PipelineStep
from .models import EnrichedFinding, VulnerabilityIntelligence

class CWEMapper:
    """Statically maps our internal plugin IDs to standard CWEs, CAPECs, and OWASP categories."""

    MAPPINGS: Dict[str, dict] = {
        "ACT-XSS-001": {
            "cwe_id": "CWE-79",
            "cwe_name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-63",
            "description": "The application reflects input without sanitization, leading to Reflected Cross-Site Scripting."
        },
        "ACT-SQLI-001": {
            "cwe_id": "CWE-89",
            "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-66",
            "description": "Constructing database commands using untrusted inputs allows attackers to execute arbitrary SQL statements."
        },
        "ACT-TRAV-001": {
            "cwe_id": "CWE-22",
            "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            "owasp_category": "A01:2021-Broken Access Control",
            "capec_id": "CAPEC-126",
            "description": "The software uses user-controllable input to construct a pathname that is intended to be within a restricted directory, but does not properly neutralize elements that can resolve to a path outside of that directory."
        },
        "ACT-SSRF-001": {
            "cwe_id": "CWE-918",
            "cwe_name": "Server-Side Request Forgery (SSRF)",
            "owasp_category": "A10:2021-Server-Side Request Forgery (SSRF)",
            "capec_id": "CAPEC-664",
            "description": "The web server receives a URL or similar request from an upstream client and retrieves the contents of this URL without sufficiently validating the destination."
        },
        "ACT-CMDI-001": {
            "cwe_id": "CWE-78",
            "cwe_name": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-88",
            "description": "Injecting operating system command separators and commands into inputs allows command execution directly on the server's shell."
        },
        "ACT-XXE-001": {
            "cwe_id": "CWE-611",
            "cwe_name": "Improper Restriction of XML External Entity Reference ('XXE')",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-221",
            "description": "The server parses XML data containing external entities DTD schemas, leaking host files or internal network endpoints."
        },
        "ACT-SSTI-001": {
            "cwe_id": "CWE-1336",
            "cwe_name": "Improper Neutralization of Special Elements Used in a Template Engine",
            "owasp_category": "A03:2021-Injection",
            "capec_id": "CAPEC-242",
            "description": "Fuzzing raw template engine operations leads to Server-Side Template Injection, executing code on the host machine."
        },
        "PASS-001": {
            "cwe_id": "CWE-693",
            "cwe_name": "Protection Mechanism Failure",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-180",
            "description": "The server did not return standard security-hardening headers (HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy)."
        },
        "PASS-002": {
            "cwe_id": "CWE-614",
            "cwe_name": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-94",
            "description": "The cookie was not configured with HTTP-only, Secure, or SameSite flags, risking capture over unencrypted channels or exposure to script environments."
        },
        "PASS-003": {
            "cwe_id": "CWE-200",
            "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "capec_id": "CAPEC-118",
            "description": "The server response contains verbose banner info, internal system errors, or directory listings."
        },
        "PASS-004": {
            "cwe_id": "CWE-937",
            "cwe_name": "Using Components with Known Vulnerabilities",
            "owasp_category": "A06:2021-Vulnerable and Outdated Components",
            "capec_id": "CAPEC-310",
            "description": "The application relies on outdated components or third-party libraries that contain publicly disclosed security bugs."
        },
        "PASS-005": {
            "cwe_id": "CWE-319",
            "cwe_name": "Cleartext Transmission of Sensitive Information",
            "owasp_category": "A02:2021-Cryptographic Failures",
            "capec_id": "CAPEC-94",
            "description": "Sensitive credentials (such as password fields) are submitted over unencrypted HTTP protocol."
        }
    }

    @classmethod
    def get_mapping(cls, plugin_id: str) -> Optional[dict]:
        return cls.MAPPINGS.get(plugin_id)

class IntelligenceEnrichmentStep(PipelineStep):
    """Enriches finding with standard threat intelligence data."""

    async def process(self, finding: EnrichedFinding, scan_id: Optional[str] = None) -> Optional[EnrichedFinding]:
        mapping = CWEMapper.get_mapping(finding.plugin_id)
        
        if mapping:
            finding.intelligence = VulnerabilityIntelligence(
                cwe_id=mapping["cwe_id"],
                cwe_name=mapping["cwe_name"],
                owasp_category=mapping["owasp_category"],
                description=mapping["description"],
                capec_id=mapping["capec_id"],
                cvss_vector=None  # CVSS step will dynamically construct vector
            )
            # Update description if it's the raw default
            if not finding.description or finding.description == "Unknown Finding":
                finding.description = mapping["description"]
                
        return finding
