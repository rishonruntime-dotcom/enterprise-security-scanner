"""
Enterprise IDOR (Insecure Direct Object Reference) Detection Plugin.

Emits DetectionCandidate objects for centralized verification.
Detects:
- Horizontal privilege escalation (user A accessing user B's resources)
- Vertical privilege escalation (user accessing admin resources)
- Predictable resource IDs
- Missing authorization checks on object references
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

IDOR_INDICATORS = [
    "id", "user_id", "account_id", "customer_id", "order_id",
    "invoice_id", "document_id", "file_id", "record", "uid",
    "pid", "mid", "cid", "aid", "rid"
]


class IDORPlugin(ActivePluginInterface):
    """Enterprise IDOR detector."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="ACT-IDOR-001",
            name="Insecure Direct Object Reference (IDOR)",
            description="Detects IDOR vulnerabilities by testing for unauthorized access to resources via manipulated object references.",
        )

    async def execute(self, endpoint: Union[str, Endpoint], http_manager: HTTPClientManager) -> List[DetectionCandidate]:
        candidates = []
        client = http_manager.get_shared_client()
        endpoint_url = endpoint.url if not isinstance(endpoint, str) else endpoint
        mutator = EnterpriseRequestMutator()

        params = self._get_params(endpoint)
        if not params:
            return candidates

        idor_params = self._find_idor_params(params)
        if not idor_params:
            return candidates

        baseline = await self._capture_baseline(client, endpoint_url)
        if not baseline or baseline.error:
            return candidates
        baseline_text = baseline.response.text if baseline.response and isinstance(baseline.response.text, str) else ""

        vulnerable_params = set()

        for param_name in idor_params:
            if param_name in vulnerable_params:
                continue

            original_value = params.get(param_name, "1")
            if not self._is_numeric(original_value):
                continue

            original_num = int(original_value) if original_value.isdigit() else 1
            test_values = [str(original_num + 1), str(original_num - 1), "2", "100"]
            if original_num > 1:
                test_values = ["1", str(original_num - 1), str(original_num + 1)]

            for test_value in test_values:
                if param_name in vulnerable_params:
                    break

                payload = Payload(
                    value=test_value,
                    technique=PayloadTechnique.BOOLEAN_BASED,
                    category="idor",
                    metadata={"original_value": original_value, "test_value": test_value},
                )

                case = next((tc for tc in mutator.mutate(endpoint, [payload]) if tc.mutated_parameter == param_name), None)
                if not case:
                    continue

                resp = await client.send(case.request)
                resp_text = resp.text if isinstance(resp.text, str) else ""

                if self._check_idor_success(resp_text, baseline_text, original_value, test_value):
                    candidate = DetectionCandidate(
                        plugin_id=self.metadata.id,
                        vulnerability_type="idor",
                        technique=PayloadTechnique.BOOLEAN_BASED,
                        endpoint=endpoint_url,
                        parameter=param_name,
                        payload=payload,
                        baseline=baseline,
                        fuzzed_request=case.request,
                        fuzzed_response=resp,
                        matched_signature=f"idor_param_{param_name}",
                        detection_evidence={
                            "original_value": original_value,
                            "test_value": test_value,
                            "response_differs": True,
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

    def _find_idor_params(self, params: Dict[str, str]) -> List[str]:
        idor_params = []
        for param_name in params:
            lower_name = param_name.lower()
            if any(ind in lower_name for ind in IDOR_INDICATORS):
                idor_params.append(param_name)
            elif self._is_numeric(params.get(param_name, "")):
                idor_params.append(param_name)
        return idor_params

    def _is_numeric(self, value: str) -> bool:
        try:
            int(value)
            return True
        except (ValueError, TypeError):
            return False

    def _check_idor_success(self, resp_text: str, baseline_text: str, original: str, test: str) -> bool:
        if resp_text == baseline_text:
            return False
        if len(resp_text) < 10:
            return False
        if test in resp_text and original not in resp_text:
            return True
        if resp_text != baseline_text and len(resp_text) > 50:
            return True
        return False

    async def _capture_baseline(self, client, url: str) -> BaselineResult:
        try:
            req = HTTPRequest(method="GET", url=url)
            start = time.monotonic()
            resp = await client.send(req)
            elapsed = (time.monotonic() - start) * 1000
            return BaselineResult(request=req, response=resp, response_time_ms=elapsed)
        except Exception as e:
            return BaselineResult(request=HTTPRequest(method="GET", url=url), error=str(e))
