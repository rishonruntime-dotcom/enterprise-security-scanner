import structlog
from typing import List, Optional

from ...interfaces.passive import PassivePluginInterface
from ...passive.models import PluginMetadata, PassiveObservation
from ...network.models import HTTPResponse
from ...models.finding import Evidence, Severity
from ...models.standards import StandardsRegistry
from ..csp_engine import CSPReasoningEngine

logger = structlog.get_logger(__name__)


class CSPReasoningPlugin(PassivePluginInterface):
    """Context-aware CSP reasoning plugin that evaluates the entire policy holistically."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="PASS-006",
            name="Context-Aware CSP Reasoning Engine",
            description="Evaluates the entire Content-Security-Policy holistically, considering directive interactions, modern mitigations (nonces, hashes, strict-dynamic, Trusted Types), and browser compatibility.",
            version="2.0.0"
        )

    def analyze(self, response: HTTPResponse) -> List[PassiveObservation]:
        observations: List[PassiveObservation] = []
        url_lower = response.url.lower()

        if any(url_lower.endswith(ext) or f"{ext}?" in url_lower for ext in [
            '.otf', '.ttf', '.woff', '.woff2', '.eot', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.mp4', '.webm', '.map', '.js'
        ]):
            return observations

        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        csp_value = headers_lower.get("content-security-policy")

        if not csp_value:
            observations.append(
                PassiveObservation(
                    plugin_id=self.metadata.id,
                    observation_type="csp_policy_assessment",
                    title="Missing Content-Security-Policy Header",
                    description="No Content-Security-Policy header was detected. CSP is essential for mitigating XSS and data injection attacks.",
                    endpoint=response.url,
                    severity=Severity.LOW,
                    evidence=[Evidence(type="missing_csp", description="CSP header absent", data={"header": "Content-Security-Policy"})],
                    remediation="Implement a Content-Security-Policy header starting with 'default-src \\'self\\''.",
                    **StandardsRegistry.get("missing_csp").__dict__
                )
            )
            return observations

        observation = CSPReasoningEngine.evaluate(csp_value, response.url)
        observations.append(observation)

        return observations
