"""
Enterprise Open Redirect Detection Plugin.

Detects unvalidated redirects by injecting attacker-controlled URLs
into redirect-sensitive parameters and checking for 3xx responses.
Emits DetectionCandidate objects for centralized verification.
"""
import re
import time
import urllib.parse
from typing import List, Union, Dict, Optional

import structlog

from ...interfaces.active import ActivePluginInterface
from ...passive.models import PluginMetadata
from ...network.http.manager import HTTPClientManager
from ...network.models import HTTPRequest, HTTPResponse
from ...models.finding import Finding, Evidence, VerificationStatus, Severity, Confidence
from ...crawler.models import Endpoint
from ..models import DetectionCandidate, BaselineResult, Payload, PayloadTechnique, TestCase
from ..mutator import EnterpriseRequestMutator

logger = structlog.get_logger(__name__)

REDIRECT_PAYLOADS = [
    {"value": "//evil.com", "desc": "protocol-relative redirect"},
    {"value": "https://evil.com", "desc": "absolute https redirect"},
    {"value": "http://evil.com", "desc": "absolute http redirect"},
    {"value": "/\\evil.com", "desc": "backslash redirect"},
    {"value": "//evil.com%5c", "desc": "url-encoded backslash redirect"},
    {"value": "///evil.com/", "desc": "triple-slash redirect"},
    {"value": "https://google.com@evil.com", "desc": "userinfo redirect"},
    {"value": "http://evil.com%2f%2fgoogle.com", "desc": "double-encoded redirect"},
    {"value": "https://evil.com%23.google.com", "desc": "fragment redirect"},
    {"value": "/%2e%2e/%2e%2e/evil.com", "desc": "dot-encoded redirect"},
    {"value": "///evil.com", "desc": "triple-slash redirect"},
    {"value": "//evil.com/../", "desc": "path traversal redirect"},
    {"value": "https://evil.com?next=original.com", "desc": "query parameter obfuscation"},
    {"value": "javascript:alert(1)", "desc": "javascript protocol"},
]

ATTACKER_DOMAINS = ["evil.com", "attacker.com", "malicious.com", "evil.example", "example.org", "test.com"]


class OpenRedirectPlugin(ActivePluginInterface):
    """Enterprise Open Redirect detector emitting unverified candidates."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="ACT-REDIR-001",
            name="Open Redirect",
            description="Detects unvalidated redirects to attacker-controlled domains.",
        )

    async def execute(self, endpoint: Union[str, Endpoint], http_manager: HTTPClientManager) -> List[DetectionCandidate]:
        candidates = []
        client = http_manager.get_shared_client()
        endpoint_url = endpoint.url if not isinstance(endpoint, str) else endpoint
        mutator = EnterpriseRequestMutator()

        params = self._get_params(endpoint)
        if not params:
            return candidates

        baseline = await self._capture_baseline(client, endpoint_url)
        baseline_redirect = self._extract_redirect_location(baseline.response) if baseline and baseline.response else None

        vulnerable_params = set()

        for param_name in params:
            if param_name in vulnerable_params:
                continue

            for payload_def in REDIRECT_PAYLOADS:
                payload = Payload(
                    value=payload_def["value"],
                    technique=PayloadTechnique.PROTOCOL_ABUSE,
                    category="open_redirect",
                    metadata={"payload_desc": payload_def["desc"]},
                )

                case = next((tc for tc in mutator.mutate(endpoint, [payload]) if tc.mutated_parameter == param_name), None)
                if not case:
                    continue

                resp = await client.send(case.request)
                redirect_location = self._extract_redirect_location(resp)
                if not redirect_location:
                    continue

                if self._is_attacker_domain(redirect_location):
                    if baseline_redirect and self._is_attacker_domain(baseline_redirect):
                        continue

                    candidate = DetectionCandidate(
                        plugin_id=self.metadata.id,
                        vulnerability_type="open_redirect",
                        technique=PayloadTechnique.PROTOCOL_ABUSE,
                        endpoint=endpoint_url,
                        parameter=param_name,
                        payload=payload,
                        baseline=baseline,
                        fuzzed_request=case.request,
                        fuzzed_response=resp,
                        matched_signature=redirect_location,
                        detection_evidence={
                            "redirect_location": redirect_location,
                            "payload_desc": payload_def["desc"],
                            "baseline_redirect": baseline_redirect,
                        },
                    )
                    candidates.append(candidate)
                    vulnerable_params.add(param_name)
                    break

        return candidates

    def _get_params(self, endpoint: Union[str, Endpoint]) -> Dict[str, str]:
        if isinstance(endpoint, str):
            parsed = urllib.parse.urlparse(endpoint)
            return dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        return endpoint.parameters or {}

    async def _capture_baseline(self, client, url: str) -> BaselineResult:
        try:
            req = HTTPRequest(method="GET", url=url)
            start = time.monotonic()
            resp = await client.send(req)
            elapsed = (time.monotonic() - start) * 1000
            return BaselineResult(request=req, response=resp, response_time_ms=elapsed)
        except Exception as e:
            return BaselineResult(request=HTTPRequest(method="GET", url=url), error=str(e))

    def _extract_redirect_location(self, resp: Optional[HTTPResponse]) -> Optional[str]:
        if not resp:
            return None
        if resp.status_code in (301, 302, 303, 307, 308):
            return resp.headers.get("Location", resp.headers.get("location", ""))
        if resp.headers:
            location = resp.headers.get("Location") or resp.headers.get("location")
            if location:
                return location
        meta_refresh = re.search(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\d+;\s*url=([^"\'>\s]+)', resp.text if isinstance(resp.text, str) else "", re.IGNORECASE)
        if meta_refresh:
            return meta_refresh.group(1)
        return None

    def _is_attacker_domain(self, location: str) -> bool:
        if not location:
            return False
        location_lower = location.lower()
        return any(dom in location_lower for dom in ATTACKER_DOMAINS)
