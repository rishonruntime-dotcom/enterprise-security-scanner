import re
import math
import urllib.parse
from typing import List, Tuple

from ...interfaces.passive import PassivePluginInterface
from ...passive.models import PluginMetadata, PassiveObservation
from ...network.models import HTTPResponse
from ...models.finding import Evidence, Severity
from ...models.standards import StandardsRegistry


class SecretValidator:
    """Context-aware validator to reduce false positives in secret detection."""

    FP_KEYWORDS = {
        "example", "test", "demo", "placeholder", "sample", "your_", "<your", 
        "xxx", "fill", "dummy", "fake", "redacted", "undefined", "null",
        "rollout_token", "visitor_info", "continuation", "playback", "analytics",
        "xsrf", "csrf", "type=\"password\"", "name=\"password\"", "input", "form",
        "session_token", "auth_token", "bearer_token", "access_token", "refresh_token",
        "client_secret", "window.", "localstorage", "sessionstorage", "state", "config",
        "webpack", "vite", "bundle", "script", "static", "assets", "chunk", "hash"
    }

    PUBLIC_PLATFORM_DOMAINS = {
        "youtube.com", "googlevideo.com", "ytimg.com", "instagram.com", "cdninstagram.com",
        "facebook.com", "fbcdn.net", "twitter.com", "google.com", "gstatic.com",
        "googletagmanager.com", "googleapis.com", "jsdelivr.net", "cloudflare.com", "unpkg.com"
    }

    @staticmethod
    def shannon_entropy(data: str) -> float:
        if not data:
            return 0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy += - p_x * math.log2(p_x)
        return entropy

    @classmethod
    def is_likely_false_positive(cls, match: re.Match, body: str, secret_type: str, url: str = "") -> bool:
        start_idx = match.start()
        end_idx = match.end()
        raw_secret = match.group(1) if match.lastindex else match.group(0)
        
        # Check domain directly against URL string
        url_lower = url.lower()
        if any(pub_domain in url_lower for pub_domain in cls.PUBLIC_PLATFORM_DOMAINS):
            return True

        # Context Window Check (±150 chars)
        window_start = max(0, start_idx - 150)
        window_end = min(len(body), end_idx + 150)
        context = body[window_start:window_end].lower()

        for kw in cls.FP_KEYWORDS:
            if kw in context and kw not in raw_secret.lower():
                return True
                
        # Inside Comment Check
        prefix = body[:start_idx]
        if prefix.rfind("<!--") > prefix.rfind("-->"):
            return True
        if prefix.rfind("/*") > prefix.rfind("*/"):
            return True
        if prefix.rfind("//") > prefix.rfind("\n"):
            return True

        # Entropy & Format Check
        if "AWS Access Key" in secret_type:
            if len(raw_secret) != 20 or not raw_secret.startswith("AKIA"):
                return True
            if cls.shannon_entropy(raw_secret) < 3.0:
                return True

        if "Password" in secret_type:
            if "name=" in context or "type=" in context or "flowname" in context or "<input" in context:
                return True
            if cls.shannon_entropy(raw_secret) < 3.2:
                return True

        if "Token" in secret_type or "API Key" in secret_type:
            if len(set(raw_secret)) < 8:
                return True
            if cls.shannon_entropy(raw_secret) < 4.2:
                return True

        return False


class InformationDisclosurePlugin(PassivePluginInterface):
    """
    Enterprise Information Disclosure & Fingerprinting Analyzer.
    Detects version banners, stack traces, internal IP addresses, email disclosures,
    API keys/tokens, sensitive comments, directory listings, and security-relevant files.
    """

    VERSION_BANNER_REGEX = (
        r"(nginx/\d+\.\d+\.\d+"
        r"|Apache/\d+\.\d+\.\d+"
        r"|PHP/\d+\.\d+\.\d+"
        r"|ASP\.NET.*?Version=[\d.]+"
        r"|IIS/\d+\.\d+"
        r"|Werkzeug/\d+\.\d+\.\d+"
        r"|gunicorn/\d+\.\d+\.\d+"
        r"|OpenSSL/\d+\.\d+\.\d+"
        r"|Microsoft-IIS/\d+\.\d+"
        r"|LiteSpeed/\d+\.\d+"
        r"|Tomcat/\d+\.\d+\.\d+)"
    )

    ERROR_SIGNATURES: List[Tuple[str, str, Severity]] = [
        (r"Exception in thread \".+?\".*?at\s+\w", "Java Stack Trace", Severity.HIGH),
        (r"Traceback \(most recent call last\):", "Python Stack Trace", Severity.HIGH),
        (r"Fatal error:.*?in.*?on line", "PHP Fatal Error", Severity.HIGH),
        (r"Warning:.*? in /.*? on line \d+", "PHP Warning Disclosure", Severity.MEDIUM),
        (r"Notice:.*? in /.*? on line \d+", "PHP Notice Disclosure", Severity.LOW),
        (r"Microsoft OLE DB Provider.*?error", "ASP.NET/SQL Error Message", Severity.HIGH),
        (r"You have an error in your SQL syntax", "SQL Syntax Error Disclosure", Severity.HIGH),
        (r"ORA-\d{5}:", "Oracle DB Error Disclosure", Severity.HIGH),
        (r"pg_query\(\).*?ERROR:", "PostgreSQL Error Disclosure", Severity.HIGH),
        (r"Uncaught (?:Error|TypeError|ReferenceError|SyntaxError):", "JavaScript Error Disclosure", Severity.MEDIUM),
        (r"Stack Trace:", "Generic Stack Trace", Severity.MEDIUM),
        (r"Index of /|Directory Listing For|Parent Directory", "Directory Listing Enabled", Severity.MEDIUM),
        (r"Whitelabel Error Page", "Spring Boot Error Page", Severity.MEDIUM),
        (r"Application Error \| Heroku", "Heroku Error Page", Severity.LOW),
        (r"ActiveRecord::RecordNotFound", "Rails Exception Disclosure", Severity.HIGH),
        (r"<b>Parse error</b>:", "PHP Parse Error", Severity.HIGH),
    ]

    SECRET_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])", "AWS Access Key ID", Severity.CRITICAL),
        (r"(?:aws[_\-\s]?secret|aws[_\-\s]?access[_\-\s]?key)[\"'\s:=]+([A-Za-z0-9/+=]{40})", "AWS Secret Key", Severity.CRITICAL),
        (r"(?:private[_\-\s]?api[_\-\s]?key|secret[_\-\s]?api[_\-\s]?key)[\"'\s:=]+([A-Za-z0-9\-_]{20,50})", "API Key Exposure", Severity.HIGH),
        (r"(?:bearer[_\-\s]?token|auth[_\-\s]?token|client[_\-\s]?secret)[\"'\s:=]+([A-Za-z0-9\-_\.]{32,})", "Bearer Token Exposure", Severity.HIGH),
        (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key", Severity.CRITICAL),
        (r"pk_live_[0-9a-zA-Z]{24,}", "Stripe Live Publishable Key", Severity.MEDIUM),
        (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid API Key", Severity.CRITICAL),
        (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token", Severity.CRITICAL),
        (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Token", Severity.CRITICAL),
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", Severity.INFO),
        (r"xox[baprs]-[0-9A-Za-z\-]{10,48}", "Slack Token", Severity.HIGH),
        (r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "RSA Private Key", Severity.CRITICAL),
        (r"(?:db_password|admin_pass|secret_password)[\"'\s:=]+(?![*]+)([^\s\"'<>&]{6,})", "Password Disclosure", Severity.HIGH),
    ]

    COMMENT_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r"<!--[^>]*(?:password|passwd|pwd|secret|api[_\s]?key|token|admin|hack|TODO|FIXME|credential|private|internal)[^>]*-->",
         "Sensitive HTML Comment", Severity.MEDIUM),
        (r"<!--[^>]*(?:\d{1,3}\.){3}\d{1,3}[^>]*-->",
         "Internal IP in HTML Comment", Severity.LOW),
    ]

    INTERNAL_IP_REGEX = (
        r"(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|localhost)(?!\d)"
    )

    EMAIL_REGEX = r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="PASS-003",
            name="Information Disclosure & Sensitive Data Analyzer",
            description="Analyzes responses for version banners, stack traces, internal IP addresses, email disclosures, API key/token leaks, sensitive comments, and directory listings."
        )

    def analyze(self, response: HTTPResponse) -> List[PassiveObservation]:
        observations: List[PassiveObservation] = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        body = response.text if isinstance(response.text, str) else ""

        # 1. Version Banners
        for h_key in ["server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache"]:
            if h_key in headers_lower:
                val = headers_lower[h_key]
                if re.search(self.VERSION_BANNER_REGEX, val, re.IGNORECASE):
                    observations.append(PassiveObservation(
                        plugin_id=self.metadata.id,
                        observation_type="version_disclosure",
                        title=f"Server Version Banner Disclosed via '{h_key.title()}' Header",
                        description=f"The server is disclosing detailed version information ('{val}') in the '{h_key}' response header.",
                        severity=Severity.LOW,
                        evidence=[Evidence(type="header_banner", description=f"Software version disclosed in '{h_key}' header.", data={"header_name": h_key, "header_value": val})],
                        endpoint=response.url,
                        remediation="Configure the web server to suppress version information.",
                        **StandardsRegistry.get("info_version_banner").__dict__
                    ))

        # 2. Stack Traces & Error Messages
        for pattern, desc, sev in self.ERROR_SIGNATURES:
            match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
            if match:
                snippet = match.group(0)[:200].strip()
                observations.append(PassiveObservation(
                    plugin_id=self.metadata.id,
                    observation_type="error_disclosure",
                    title=f"Sensitive Information Disclosure: {desc}",
                    description=f"The application response contains a '{desc}'.",
                    severity=sev,
                    evidence=[Evidence(type="error_message", description=f"Error pattern matched: '{desc}'", data={"matched_snippet": snippet})],
                    endpoint=response.url,
                    remediation="Disable verbose error reporting in production.",
                    **StandardsRegistry.get("info_stack_trace").__dict__
                ))

        # 3. Secret/API Key Patterns
        for pattern, label, base_sev in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, body, re.IGNORECASE):
                if SecretValidator.is_likely_false_positive(match, body, label, url=response.url):
                    continue
                
                raw = match.group(1) if match.lastindex else match.group(0)
                
                sev = base_sev
                if "Google API Key" in label:
                    sev = Severity.INFO
                    desc_extra = " Note: Browser-scoped Google API keys are intentionally public, but ensure they are appropriately restricted by domain."
                else:
                    desc_extra = ""

                redacted = raw[:6] + "*" * max(0, len(raw) - 6) if len(raw) > 6 else "***"
                
                observations.append(PassiveObservation(
                    plugin_id=self.metadata.id,
                    observation_type="secret_exposure",
                    title=f"Potential Secret Exposed in Response: {label}",
                    description=f"The page response appears to contain a {label}.{desc_extra}",
                    severity=sev,
                    evidence=[Evidence(
                        type="secret_pattern_match",
                        description=f"Pattern consistent with '{label}' detected in response body.",
                        matched_value=redacted,
                        detection_rule=pattern[:80],
                        detection_method="Passive Regex Search",
                        reason=f"Matched a known high-entropy or predefined secret pattern for {label}.",
                        data={"matched_pattern": pattern[:80]}
                    )],
                    endpoint=response.url,
                    remediation="Remove secrets, API keys, and tokens from client-facing responses.",
                    **StandardsRegistry.get("info_api_key" if "API" in label or "Token" in label else "info_credential_disclosure").__dict__
                ))
                break

        # 4. Sensitive HTML Comments
        for pattern, label, sev in self.COMMENT_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
            if match:
                snippet = match.group(0)[:300].strip()
                observations.append(PassiveObservation(
                    plugin_id=self.metadata.id,
                    observation_type="sensitive_comment",
                    title=f"Sensitive Data in HTML Comment: {label}",
                    description=f"The page HTML source contains a comment that may expose sensitive information.",
                    severity=sev,
                    evidence=[Evidence(type="html_comment", description="Sensitive HTML comment detected.", data={"comment_snippet": snippet[:200]})],
                    endpoint=response.url,
                    remediation="Remove all sensitive information from HTML comments before deployment.",
                    **StandardsRegistry.get("info_sensitive_comment").__dict__
                ))

        # 5. Internal IP Address Disclosure
        ip_matches = re.findall(self.INTERNAL_IP_REGEX, body)
        if ip_matches:
            unique_ips = list(set(ip_matches))[:5]
            observations.append(PassiveObservation(
                plugin_id=self.metadata.id,
                observation_type="internal_ip_disclosure",
                title="Internal IP Address Disclosed in Response",
                description=f"The application reveals internal network IP addresses ({', '.join(unique_ips)}).",
                severity=Severity.LOW,
                evidence=[Evidence(type="ip_disclosure", description="Internal IP addresses found in response body.", data={"internal_ips": unique_ips})],
                endpoint=response.url,
                remediation="Ensure internal IPs are never included in responses.",
                **StandardsRegistry.get("info_internal_ip").__dict__
            ))

        # 6. Email Address Disclosure
        email_matches = re.findall(self.EMAIL_REGEX, body)
        real_emails = [
            e for e in email_matches
            if not any(fp in e.lower() for fp in ["example.com", "schema.org", "w3.org", "test.com", "sentry.io"])
        ]
        if real_emails:
            unique_emails = list(set(real_emails))[:10]
            observations.append(PassiveObservation(
                plugin_id=self.metadata.id,
                observation_type="email_disclosure",
                title="Email Address(es) Disclosed in Response",
                description=f"The page response contains {len(unique_emails)} email address(es).",
                severity=Severity.INFO,
                evidence=[Evidence(type="email_addresses", description="Email addresses found in response body.", data={"emails": unique_emails[:5]})],
                endpoint=response.url,
                remediation="Evaluate whether displaying email addresses is necessary. Consider obfuscation.",
                cwe_id="CWE-359",
                cwe_name="Exposure of Private Personal Information to an Unauthorized Actor",
                owasp_category="A01:2021-Broken Access Control",
            ))

        # 7. Informational: Security-Relevant File Disclosures
        url_lower = response.url.lower()

        if "/robots.txt" in url_lower and response.status_code == 200:
            sensitive_disallows = re.findall(r"Disallow:\s*(/[^\n]+)", body, re.IGNORECASE)
            risky = [p.strip() for p in sensitive_disallows if any(
                kw in p.lower() for kw in ["admin", "backup", "config", "db", "secret", "api", "private", "internal"]
            )]
            severity = Severity.LOW if risky else Severity.INFO
            observations.append(PassiveObservation(
                plugin_id=self.metadata.id,
                observation_type="discovered_file",
                title="Robots.txt File Discovered" + (" with Sensitive Paths" if risky else ""),
                description="A robots.txt file was found.",
                severity=severity,
                evidence=[Evidence(type="discovered_file", description="robots.txt file identified.", data={"url": response.url, "sensitive_paths": risky})],
                endpoint=response.url,
                remediation="Review robots.txt to ensure sensitive paths are not disclosed.",
                **StandardsRegistry.get("info_security_file").__dict__
            ))

        if "/sitemap" in url_lower and response.status_code == 200:
            url_count = len(re.findall(r"<loc>", body, re.IGNORECASE))
            observations.append(PassiveObservation(
                plugin_id=self.metadata.id,
                observation_type="discovered_file",
                title="Sitemap File Discovered",
                description=f"A sitemap was found containing approximately {url_count} URL entries.",
                severity=Severity.INFO,
                evidence=[Evidence(type="discovered_file", description="Sitemap file identified.", data={"url": response.url, "url_count": url_count})],
                endpoint=response.url,
                remediation="Ensure sitemap does not expose non-public pages or admin sections.",
                **StandardsRegistry.get("info_security_file").__dict__
            ))

        if "/.well-known/security.txt" in url_lower and response.status_code == 200:
            observations.append(PassiveObservation(
                plugin_id=self.metadata.id,
                observation_type="discovered_file",
                title="Security.txt File Discovered (Positive Finding)",
                description="A security.txt file was found. This is a positive security practice.",
                severity=Severity.INFO,
                evidence=[Evidence(type="discovered_file", description="security.txt file identified.", data={"url": response.url})],
                endpoint=response.url,
                remediation="Ensure security.txt is up to date.",
                cwe_id=None,
                cwe_name="N/A",
                owasp_category="N/A",
            ))

        return observations