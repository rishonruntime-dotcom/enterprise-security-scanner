from dataclasses import dataclass
from typing import Optional

@dataclass
class StandardMapping:
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    capec_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_vector: Optional[str] = None

class StandardsRegistry:
    """Centralized registry for OWASP, CWE, CAPEC, and CVSS mappings."""
    
    _registry = {
        # --- Missing Security Headers ---
        "missing_hsts": StandardMapping(
            cwe_id="CWE-319",
            cwe_name="Cleartext Transmission of Sensitive Information",
            capec_id="CAPEC-94",
            owasp_category="A02:2021-Cryptographic Failures"
        ),
        "missing_csp": StandardMapping(
            cwe_id="CWE-1021",
            cwe_name="Improper Restriction of Rendered UI Layers or Frames",
            capec_id="CAPEC-588",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        "missing_x_frame_options": StandardMapping(
            cwe_id="CWE-693",
            cwe_name="Protection Mechanism Failure",
            capec_id="CAPEC-588",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        "missing_x_content_type_options": StandardMapping(
            cwe_id="CWE-693",
            cwe_name="Protection Mechanism Failure",
            capec_id="CAPEC-115",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        "missing_server_header": StandardMapping(
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
            capec_id="CAPEC-118",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        "missing_referrer_policy": StandardMapping(
            cwe_id="CWE-693",
            cwe_name="Protection Mechanism Failure",
            capec_id="CAPEC-118",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        
        # --- Insecure Cookies ---
        "cookie_missing_secure": StandardMapping(
            cwe_id="CWE-614",
            cwe_name="Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
            capec_id="CAPEC-31",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        "cookie_missing_httponly": StandardMapping(
            cwe_id="CWE-1004",
            cwe_name="Sensitive Cookie Without 'HttpOnly' Flag",
            capec_id="CAPEC-60",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        "cookie_missing_both": StandardMapping(
            cwe_id="CWE-1004",
            cwe_name="Sensitive Cookie Without 'HttpOnly' and 'Secure' Flags",
            capec_id="CAPEC-60",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        
        # --- Form Security ---
        "insecure_password_transmission": StandardMapping(
            cwe_id="CWE-319",
            cwe_name="Cleartext Transmission of Sensitive Information",
            capec_id="CAPEC-94",
            owasp_category="A02:2021-Cryptographic Failures"
        ),
        
        # --- Outdated Components ---
        "vulnerable_component": StandardMapping(
            cwe_id="CWE-1104",
            cwe_name="Use of Unmaintained Third Party Components",
            capec_id="CAPEC-310",
            owasp_category="A06:2021-Vulnerable and Outdated Components"
        ),
        
        # --- Information Disclosure ---
        "info_version_banner": StandardMapping(
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information",
            capec_id="CAPEC-118",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        "info_stack_trace": StandardMapping(
            cwe_id="CWE-209",
            cwe_name="Generation of Error Message Containing Sensitive Information",
            capec_id="CAPEC-118",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        "info_credential_disclosure": StandardMapping(
            cwe_id="CWE-522",
            cwe_name="Insufficiently Protected Credentials",
            capec_id="CAPEC-37",
            owasp_category="A07:2021-Identification and Authentication Failures"
        ),
        "info_api_key": StandardMapping(
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            capec_id="CAPEC-37",
            owasp_category="A07:2021-Identification and Authentication Failures"
        ),
        "info_sensitive_comment": StandardMapping(
            cwe_id="CWE-615",
            cwe_name="Inclusion of Sensitive Information in Source Code Comments",
            capec_id="CAPEC-37",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        "info_internal_ip": StandardMapping(
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information",
            capec_id="CAPEC-118",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        "info_directory_listing": StandardMapping(
            cwe_id="CWE-548",
            cwe_name="Exposure of Information Through Directory Listing",
            capec_id="CAPEC-127",
            owasp_category="A05:2021-Security Misconfiguration"
        ),
        "info_security_file": StandardMapping(
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information",
            capec_id="CAPEC-118",
            owasp_category="A05:2021-Security Misconfiguration"
        )
    }
    
    @classmethod
    def get(cls, key: str) -> StandardMapping:
        """Retrieve a mapping by key. Returns an empty mapping if not found."""
        return cls._registry.get(key, StandardMapping())
