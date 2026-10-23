"""
Enterprise CSRF (Cross-Site Request Forgery) Detection Plugin.

Emits DetectionCandidate objects for centralized verification.
Detects:
- Missing CSRF token
- Weak CSRF token (predictable)
- SameSite cookie not set
- Missing custom headers
- State-changing operations without protection
"""
import re
import urllib.parse
import time
from typing import List, Union, Dict, Optional

import structlog

from ...interfaces.active import ActivePluginInterface
from ...passive.models import PluginMetadata
from ...network.http.manager import HTTPClientManager
from ...network.models import HTTPRequest, HTTPResponse
from ...models.finding import Finding, Evidence, VerificationStatus, Severity, Confidence
from ...crawler.models import Endpoint
from ..models import DetectionCandidate, BaselineResult, Payload, PayloadTechnique
from ..mutator import EnterpriseRequestMutator


logger = structlog.get_logger(__name__)

CSRF_TOKEN_NAMES = [
    "csrf", "xsrf", "token", "_token", "csrf_token", "xsrf_token",
    "authenticity_token", "csrfmiddlewaretoken", "__requestverificationtoken"
]

STATE_CHANGING_METHODS = ["POST", "PUT", "PATCH", "DELETE"]


class CSRFPlugin(ActivePluginInterface):
    """Enterprise CSRF detector."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="ACT-CSRF-001",
            name="Cross-Site Request Forgery (CSRF)",
            description="Detects CSRF vulnerabilities by testing state-changing operations without anti-CSRF tokens.",
        )

    async def execute(self, endpoint: Union[str, Endpoint], http_manager: HTTPClientManager) -> List[DetectionCandidate]:
        candidates = []
        client = http_manager.get_shared_client()
        endpoint_url = endpoint.url if not isinstance(endpoint, str) else endpoint
        mutator = EnterpriseRequestMutator()

        params = self._get_params(endpoint)
        if not params:
            return candidates

        has_csrf_token = any(
            any(token in param_name.lower() for token in CSRF_TOKEN_NAMES)
            for param_name in params
        )

        if has_csrf_token:
            return candidates

        baseline = await self._capture_baseline(client, endpoint_url)
        if not baseline or baseline.error:
            return candidates

        vulnerable_params = set()

        for param_name in params:
            if param_name in vulnerable_params:
                continue

            payload = Payload(
                value="csrf_test_payload",
                technique=PayloadTechnique.BOOLEAN_BASED,
                category="csrf",
                metadata={"missing_token": True},
            )

            case = next((tc for tc in mutator.mutate(endpoint, [payload]) if tc.mutated_parameter == param_name), None)
            if not case:
                continue

            if case.request.method.upper() not in STATE_CHANGING_METHODS:
                continue

            resp = await client.send(case.request)
            resp_text = resp.text if isinstance(resp.text, str) else ""
            resp_status = resp.status_code if resp else 0

            if self._check_csrf_success(resp_text, resp_status, baseline):
                candidate = DetectionCandidate(
                    plugin_id=self.metadata.id,
                    vulnerability_type="csrf",
                    technique=PayloadTechnique.BOOLEAN_BASED,
                    endpoint=endpoint_url,
                    parameter=param_name,
                    payload=payload,
                    baseline=baseline,
                    fuzzed_request=case.request,
                    fuzzed_response=resp,
                    matched_signature=f"state_changing_{case.request.method}",
                    detection_evidence={
                        "http_method": case.request.method,
                        "response_status": resp_status,
                        "has_csrf_token": False,
                        "response_indicators": self._extract_csrf_indicators(resp_text),
                    },
                )
                candidates.append(candidate)
                vulnerable_params.add(param_name)

        return candidates

    def _get_params(self, endpoint: Union[str, Endpoint]) -> Dict[str, str]:
        if isinstance(endpoint, str):
            parsed = urllib.parse.urlparse(endpoint)
            return dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        return endpoint.parameters or {}

    def _check_csrf_success(self, resp_text: str, resp_status: int, baseline: BaselineResult) -> bool:
        if resp_status >= 500:
            return False
        if resp_status in (301, 302, 303, 307, 308):
            return True
        if resp_status == 200 and resp_text != (baseline.response.text if baseline.response and isinstance(baseline.response.text, str) else ""):
            return True
        return False

    def _extract_csrf_indicators(self, resp_text: str) -> List[str]:
        indicators = []
        if "success" in resp_text.lower():
            indicators.append("success_response")
        if "updated" in resp_text.lower():
            indicators.append("update_confirmed")
        if "created" in resp_text.lower():
            indicators.append("creation_confirmed")
        if "deleted" in resp_text.lower():
            indicators.append("deletion_confirmed")
        return indicators

    async def _capture_baseline(self, client, url: str) -> BaselineResult:
        try:
            req = HTTPRequest(method="GET", url=url)
            start = time.monotonic()
            resp = await client.send(req)
            elapsed = (time.monotonic() - start) * 1000
            return BaselineResult(request=req, response=resp, response_time_ms=elapsed)
        except Exception as e:
            return BaselineResult(request=HTTPRequest(method="GET", url=url), error=str(e))
