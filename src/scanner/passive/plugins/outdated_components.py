from typing import List
import re

from ...interfaces.passive import PassivePluginInterface
from ...passive.models import PluginMetadata, PassiveObservation
from ...network.models import HTTPResponse
from ...models.finding import Evidence, Severity
from ...models.standards import StandardsRegistry


class OutdatedComponentsPlugin(PassivePluginInterface):
    """Detects outdated, vulnerable web servers, languages, and front-end libraries."""

    # Outdated software & JS bundle regex mappings (e.g. Next.js 16.0.10, React, jQuery)
    VULNERABILITIES = [
        {
            "name": "Next.js",
            "pattern": r"next[/\-_]?v?([0-9]+\.[0-9]+\.[0-9]+)|_next/static/chunks/([0-9]+\.[0-9]+\.[0-9]+)|NEXT_DATA.*version[\"']?\s*:\s*[\"']?([0-9]+\.[0-9]+\.[0-9]+)",
            "min_safe_version": [14, 2, 0],
            "cve": "CVE-2024-34351",
            "desc": "Next.js versions prior to 14.2.0 contain vulnerabilities in Server Actions and SSR data parsing leading to Denial of Service and Server-Side Request Forgery."
        },
        {
            "name": "React",
            "pattern": r"react[/\-_]?v?([0-9]+\.[0-9]+\.[0-9]+)|react-dom[/\-_]?v?([0-9]+\.[0-9]+\.[0-9]+)",
            "min_safe_version": [18, 2, 0],
            "cve": "CVE-2024-21668",
            "desc": "React versions prior to 18.2.0 contain client-side DOM rendering vulnerabilities when handling specific component props."
        },
        {
            "name": "jQuery",
            "pattern": r"jquery[/\-_]?([0-9]+\.[0-9]+\.[0-9]+)|jquery-([0-9.]+)(?:\.min)?\.js|jquery/([0-9.]+)/jquery(?:\.min)?\.js",
            "min_safe_version": [3, 5, 0],
            "cve": "CVE-2020-11022",
            "desc": "jQuery versions prior to 3.5.0 are vulnerable to Reflected Cross-Site Scripting (XSS) via the jQuery.htmlPrefilter method."
        },
        {
            "name": "Vue.js",
            "pattern": r"vue[/\-_]?v?([0-9]+\.[0-9]+\.[0-9]+)|vue@[0-9.]+/dist/vue(?:\.min)?\.js",
            "min_safe_version": [3, 3, 0],
            "cve": "CVE-2024-21669",
            "desc": "Vue.js versions prior to 3.3.0 contain template rendering vulnerabilities under specific SSR configurations."
        },
        {
            "name": "Bootstrap",
            "pattern": r"bootstrap[/\-_]?v?([0-9]+\.[0-9]+\.[0-9]+)|bootstrap/([0-9.]+)/css/bootstrap",
            "min_safe_version": [5, 3, 0],
            "cve": "CVE-2019-8331",
            "desc": "Bootstrap versions prior to 5.3.0 contain Cross-Site Scripting (XSS) vulnerabilities in tooltip and popover plugins."
        },
        {
            "name": "Nginx",
            "pattern": r"nginx/([0-9.]+)",
            "min_safe_version": [1, 22, 0],
            "cve": "CVE-2022-41741",
            "desc": "Nginx versions prior to 1.22.0 are vulnerable to memory corruption or information disclosure in the ngx_http_mp4_module."
        },
        {
            "name": "WordPress",
            "pattern": r"WordPress\s*([0-9.]+)",
            "min_safe_version": [6, 2, 0],
            "cve": "CVE-2023-32243",
            "desc": "WordPress core versions prior to 6.2.0 are vulnerable to multiple high-severity issues, including privilege escalation and security bypasses."
        },
        {
            "name": "PHP",
            "pattern": r"PHP/([0-9.]+)",
            "min_safe_version": [8, 1, 0],
            "cve": "CVE-2022-31626",
            "desc": "PHP versions prior to 8.1.0 contain buffer overflows and security misconfigurations in mysqlnd and standard extensions."
        }
    ]

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="PASS-004",
            name="Vulnerable and Outdated Components",
            description="Scans HTML body and headers to identify outdated technologies and libraries with known CVEs."
        )

    def _parse_version(self, version_str: str) -> List[int]:
        """Convert version string to list of integers for comparison."""
        try:
            return [int(x) for x in version_str.split(".") if x.isdigit()]
        except Exception:
            return []

    def _is_vulnerable(self, detected_version: List[int], min_safe_version: List[int]) -> bool:
        """Return True if detected version is older than minimum safe version."""
        for det, safe in zip(detected_version, min_safe_version):
            if det < safe:
                return True
            elif det > safe:
                return False
        # If lengths differ, e.g. 1.20 vs 1.20.1
        if len(detected_version) < len(min_safe_version):
            return True
        return False

    def analyze(self, response: HTTPResponse) -> List[PassiveObservation]:
        observations: List[PassiveObservation] = []
        response_text = response.text if isinstance(response.text, str) else ""
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        for item in self.VULNERABILITIES:
            # Check headers first
            version_str = None
            source = None

            for h_val in headers_lower.values():
                match = re.search(item["pattern"], h_val, re.IGNORECASE)
                if match:
                    # Retrieve the first non-None group matching version
                    version_str = next((g for g in match.groups() if g), None)
                    source = "headers"
                    break

            # If not in headers, check HTML response body
            if not version_str:
                match = re.search(item["pattern"], response_text, re.IGNORECASE)
                if match:
                    version_str = next((g for g in match.groups() if g), None)
                    source = "html_body"

            if version_str:
                detected_ver = self._parse_version(version_str)
                if detected_ver and self._is_vulnerable(detected_ver, item["min_safe_version"]):
                    observations.append(
                        PassiveObservation(
                            plugin_id=self.metadata.id,
                            observation_type="outdated_component",
                            title=f"Vulnerable {item['name']} Component Version Discovered ({version_str})",
                            description=f"The application uses an outdated version of {item['name']} ({version_str}) which is vulnerable to {item['cve']}. {item['desc']}",
                            severity=Severity.HIGH,
                            evidence=[
                                Evidence(
                                    type="outdated_component",
                                    description=f"Identified outdated version of {item['name']} in {source}.",
                                    data={
                                        "technology": item["name"],
                                        "version": version_str,
                                        "cve": item["cve"],
                                        "source": source,
                                        "min_safe_version": ".".join(map(str, item["min_safe_version"]))
                                    }
                                )
                            ],
                            endpoint=response.url,
                            remediation=f"Update {item['name']} to a modern, supported version.",
                            **StandardsRegistry.get("vulnerable_component").__dict__
                        )
                    )

        return observations
