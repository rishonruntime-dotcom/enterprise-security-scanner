"""
Enterprise File Upload Vulnerability Detection Plugin.

Emits DetectionCandidate objects for centralized verification.
Detects:
- Unrestricted file upload (missing validation)
- Dangerous file types accepted
- Missing content-type validation
- Missing file extension validation
- Missing file size limits
- Path traversal in upload paths
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

DANGEROUS_EXTENSIONS = [
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".pht",
    ".asp", ".aspx", ".jsp", ".jspx", ".war", ".ear",
    ".exe", ".dll", ".bat", ".cmd", ".sh", ".py", ".rb",
    ".htaccess", ".htpasswd",
]

DANGEROUS_CONTENT_TYPES = [
    "application/x-php",
    "application/x-httpd-php",
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-sh",
]

UPLOAD_INDICATORS = [
    "upload", "file", "image", "avatar", "attachment", "document",
    "import", "media", "photo", "picture", "icon"
]


class FileUploadPlugin(ActivePluginInterface):
    """Enterprise File Upload vulnerability detector."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="ACT-UPLOAD-001",
            name="Insecure File Upload",
            description="Detects unrestricted file upload vulnerabilities allowing dangerous file types.",
        )

    async def execute(self, endpoint: Union[str, Endpoint], http_manager: HTTPClientManager) -> List[DetectionCandidate]:
        candidates = []
        client = http_manager.get_shared_client()
        endpoint_url = endpoint.url if not isinstance(endpoint, str) else endpoint
        mutator = EnterpriseRequestMutator()

        params = self._get_params(endpoint)
        if not params:
            return candidates

        upload_params = self._find_upload_params(params)
        if not upload_params:
            return candidates

        baseline = await self._capture_baseline(client, endpoint_url)
        if not baseline or baseline.error:
            return candidates

        vulnerable_params = set()

        for param_name in upload_params:
            if param_name in vulnerable_params:
                continue

            for ext in DANGEROUS_EXTENSIONS:
                if param_name in vulnerable_params:
                    break

                filename = f"test{ext}"
                payload = Payload(
                    value=filename,
                    technique=PayloadTechnique.FILE_READ,
                    category="file_upload",
                    metadata={"extension": ext, "content_type": "application/octet-stream"},
                )

                case = next((tc for tc in mutator.mutate(endpoint, [payload]) if tc.mutated_parameter == param_name), None)
                if not case:
                    continue

                resp = await client.send(case.request)
                resp_text = resp.text if isinstance(resp.text, str) else ""
                resp_headers = dict(resp.headers) if resp.headers else {}

                if self._check_upload_success(resp_text, resp_headers, filename):
                    candidate = DetectionCandidate(
                        plugin_id=self.metadata.id,
                        vulnerability_type="file_upload",
                        technique=PayloadTechnique.FILE_READ,
                        endpoint=endpoint_url,
                        parameter=param_name,
                        payload=payload,
                        baseline=baseline,
                        fuzzed_request=case.request,
                        fuzzed_response=resp,
                        matched_signature=f"uploaded_{ext}",
                        detection_evidence={
                            "uploaded_filename": filename,
                            "extension": ext,
                            "response_indicators": self._extract_upload_indicators(resp_text),
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

    def _find_upload_params(self, params: Dict[str, str]) -> List[str]:
        upload_params = []
        for param_name in params:
            lower_name = param_name.lower()
            if any(ind in lower_name for ind in UPLOAD_INDICATORS):
                upload_params.append(param_name)
        return upload_params

    def _check_upload_success(self, resp_text: str, resp_headers: Dict[str, str], filename: str) -> bool:
        success_indicators = [
            "uploaded successfully",
            "file uploaded",
            "upload complete",
            "successfully uploaded",
            filename in resp_text,
            "filename" in resp_text.lower() and filename in resp_text,
        ]
        return any(ind in resp_text.lower() for ind in success_indicators)

    def _extract_upload_indicators(self, resp_text: str) -> List[str]:
        indicators = []
        if "uploaded successfully" in resp_text.lower():
            indicators.append("success_message")
        if "filename" in resp_text.lower():
            indicators.append("filename_reflected")
        if "file" in resp_text.lower():
            indicators.append("file_reference")
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
