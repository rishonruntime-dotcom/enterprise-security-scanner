"""
Enterprise SSTI Detection Plugin.

Emits DetectionCandidate objects for centralized verification.
"""
import re
import urllib.parse
import time
from typing import List, Union, Dict

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

POLYGLOT_PROBES = [
    {
        "value": "${7*7}{{7*7}}", 
        "result": "49", 
        "engine_hints": ["freemarker", "jinja2", "twig", "nunjucks"]
    },
    {
        "value": "<% 7*7 %>", 
        "result": "49", 
        "engine_hints": ["erb", "velocity"]
    },
    {
        "value": "#{7*7}", 
        "result": "49", 
        "engine_hints": ["thymeleaf", "spring"]
    },
    {
        "value": "@(7*7)", 
        "result": "49", 
        "engine_hints": ["razor"]
    }
]

ENGINE_PROBES = {
    "jinja2": [
        {"value": "{{7*'7'}}", "result": "7777777"}
    ],
    "twig": [
        {"value": "{{7*'7'}}", "result": "49"}
    ],
    "freemarker": [
        {"value": "${.version}", "marker": r"\d+\.\d+\.\d+"}
    ],
    "thymeleaf": [
        {"value": "${#uris.escapePath('a/b')}", "result": "a%2Fb"}
    ],
    "spring": [
        {"value": "T(java.lang.Runtime).getRuntime().exec('id')", "marker": r"java.lang.ProcessImpl"}
    ]
}

class SSTIPlugin(ActivePluginInterface):
    """Enterprise SSTI detector emitting unverified candidates."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="ACT-SSTI-001",
            name="Server-Side Template Injection (SSTI)",
            description="Detects SSTI candidates for centralized verification.",
        )

    async def execute(self, endpoint: Union[str, Endpoint], http_manager: HTTPClientManager) -> List[DetectionCandidate]:
        candidates = []
        client = http_manager.get_shared_client()
        endpoint_url = endpoint.url if not isinstance(endpoint, str) else endpoint
        mutator = EnterpriseRequestMutator()

        params = self._get_params(endpoint)
        if not params: return candidates

        baseline = await self._capture_baseline(client, endpoint_url)
        baseline_text = baseline.response.text if baseline and baseline.response and isinstance(baseline.response.text, str) else ""

        vulnerable_params = set()

        for param_name in params:
            if param_name in vulnerable_params: continue

            for probe in POLYGLOT_PROBES:
                if param_name in vulnerable_params: break

                payload = Payload(value=probe["value"], technique=PayloadTechnique.TEMPLATE_EVAL, category="ssti")
                case = next((tc for tc in mutator.mutate(endpoint, [payload]) if tc.mutated_parameter == param_name), None)
                if not case: continue

                resp = await client.send(case.request)
                resp_text = resp.text if isinstance(resp.text, str) else ""

                if probe["result"] in resp_text and probe["value"] not in resp_text and probe["result"] not in baseline_text:
                    
                    # Try engine-specific fingerprinting
                    detected_engine = "unknown"
                    for engine_hint in probe["engine_hints"]:
                        for eprobe in ENGINE_PROBES.get(engine_hint, []):
                            ep = Payload(value=eprobe["value"], technique=PayloadTechnique.TEMPLATE_EVAL, category="ssti")
                            ep_case = next((tc for tc in mutator.mutate(endpoint, [ep]) if tc.mutated_parameter == param_name), None)
                            if ep_case:
                                ep_resp = await client.send(ep_case.request)
                                ep_text = ep_resp.text if isinstance(ep_resp.text, str) else ""
                                if "marker" in eprobe and re.search(eprobe["marker"], ep_text, re.IGNORECASE):
                                    detected_engine = engine_hint
                                    break
                                elif "result" in eprobe and eprobe["result"] in ep_text and eprobe["value"] not in ep_text:
                                    detected_engine = engine_hint
                                    break
                        if detected_engine != "unknown": break

                    candidate = DetectionCandidate(
                        plugin_id=self.metadata.id,
                        vulnerability_type="ssti",
                        technique=PayloadTechnique.TEMPLATE_EVAL,
                        endpoint=endpoint_url,
                        parameter=param_name,
                        payload=payload,
                        baseline=baseline,
                        fuzzed_request=case.request,
                        fuzzed_response=resp,
                        detection_evidence={"detected_engine": detected_engine},
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
