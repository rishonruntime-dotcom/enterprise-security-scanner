"""
Enterprise Command Injection Detection Plugin.

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

OUTPUT_PAYLOADS = [
    {"value": "; id", "os": "linux", "marker": r"uid=\d+\(\w+\)\s+gid=\d+", "desc": "id command output"},
    {"value": "| id", "os": "linux", "marker": r"uid=\d+\(\w+\)\s+gid=\d+", "desc": "id command output"},
    {"value": "|| id", "os": "linux", "marker": r"uid=\d+\(\w+\)\s+gid=\d+", "desc": "id command output"},
    {"value": "$(id)", "os": "linux", "marker": r"uid=\d+\(\w+\)\s+gid=\d+", "desc": "id command output"},
    {"value": "`id`", "os": "linux", "marker": r"uid=\d+\(\w+\)\s+gid=\d+", "desc": "id command output"},
    {"value": "; whoami", "os": "linux", "marker": r"^[a-z_][a-z0-9_-]*$", "desc": "whoami output"},
    {"value": "; cat /etc/passwd", "os": "linux", "marker": r"root:.:0:0:", "desc": "passwd file content"},
    {"value": "\nid\n", "os": "linux", "marker": r"uid=\d+\(\w+\)\s+gid=\d+", "desc": "newline separator"},
    {"value": "; hostname", "os": "linux", "marker": r"[a-zA-Z0-9._-]+", "desc": "hostname output"},
    {"value": "| ipconfig", "os": "windows", "marker": r"Windows IP Configuration|IPv4 Address|Subnet Mask", "desc": "ipconfig output"},
    {"value": "& ipconfig", "os": "windows", "marker": r"Windows IP Configuration|IPv4 Address", "desc": "ipconfig output"},
    {"value": "| dir", "os": "windows", "marker": r"Volume in drive|Directory of|<DIR>", "desc": "dir command output"},
    {"value": "& whoami", "os": "windows", "marker": r"[a-zA-Z0-9]+\\[a-zA-Z0-9]+", "desc": "whoami output"},
    {"value": "| type C:\\Windows\\win.ini", "os": "windows", "marker": r"\[extensions\]|\[fonts\]", "desc": "win.ini content"},
]

TIME_PAYLOADS = [
    {"value": "; sleep 5", "os": "linux", "delay": 5.0},
    {"value": "| sleep 5", "os": "linux", "delay": 5.0},
    {"value": "$(sleep 5)", "os": "linux", "delay": 5.0},
    {"value": "`sleep 5`", "os": "linux", "delay": 5.0},
    {"value": "& ping -n 5 127.0.0.1", "os": "windows", "delay": 4.0},
    {"value": "| timeout /t 5", "os": "windows", "delay": 5.0},
    {"value": "; ping -c 5 127.0.0.1", "os": "linux", "delay": 4.0},
]


class CommandInjectionPlugin(ActivePluginInterface):
    """Enterprise Command Injection detector emitting unverified candidates."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="ACT-CMDI-001",
            name="OS Command Injection",
            description="Detects command injection candidates for centralized verification.",
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

            # Output-based
            for payload_def in OUTPUT_PAYLOADS:
                if param_name in vulnerable_params: break
                
                payload = Payload(value=payload_def["value"], technique=PayloadTechnique.COMMAND_OUTPUT, category="cmdi")
                case = next((tc for tc in mutator.mutate(endpoint, [payload]) if tc.mutated_parameter == param_name), None)
                if not case: continue

                resp = await client.send(case.request)
                resp_text = resp.text if isinstance(resp.text, str) else ""

                if re.search(payload_def["marker"], resp_text, re.IGNORECASE | re.MULTILINE):
                    if not re.search(payload_def["marker"], baseline_text, re.IGNORECASE | re.MULTILINE):
                        candidate = DetectionCandidate(
                            plugin_id=self.metadata.id,
                            vulnerability_type="cmdi",
                            technique=PayloadTechnique.COMMAND_OUTPUT,
                            endpoint=endpoint_url,
                            parameter=param_name,
                            payload=payload,
                            baseline=baseline,
                            fuzzed_request=case.request,
                            fuzzed_response=resp,
                            matched_signature=payload_def["marker"],
                        )
                        candidates.append(candidate)
                        vulnerable_params.add(param_name)
                        break

            if param_name in vulnerable_params: continue

            # Time-based
            for payload_def in TIME_PAYLOADS:
                if param_name in vulnerable_params: break
                
                payload = Payload(value=payload_def["value"], technique=PayloadTechnique.BLIND, category="cmdi")
                case = next((tc for tc in mutator.mutate(endpoint, [payload]) if tc.mutated_parameter == param_name), None)
                if not case: continue

                start = time.monotonic()
                resp = await client.send(case.request)
                elapsed = (time.monotonic() - start) * 1000

                if (elapsed - baseline.response_time_ms) > (payload_def["delay"] * 1000 * 0.8):
                    candidate = DetectionCandidate(
                        plugin_id=self.metadata.id,
                        vulnerability_type="cmdi",
                        technique=PayloadTechnique.BLIND,
                        endpoint=endpoint_url,
                        parameter=param_name,
                        payload=payload,
                        baseline=baseline,
                        fuzzed_request=case.request,
                        fuzzed_response=resp,
                        fuzzed_timing_ms=elapsed,
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
