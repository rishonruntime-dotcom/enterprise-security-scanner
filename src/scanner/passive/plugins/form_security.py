from typing import List
from selectolax.parser import HTMLParser
import urllib.parse

from ...interfaces.passive import PassivePluginInterface
from ...passive.models import PluginMetadata, PassiveObservation
from ...network.models import HTTPResponse
from ...models.finding import Evidence, Severity
from ...models.standards import StandardsRegistry
from ...crawler.utils import URLNormalizer


class FormSecurityPlugin(PassivePluginInterface):
    """Detects insecure form actions, particularly forms submitting sensitive details over plaintext HTTP."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="PASS-005",
            name="Insecure Form Submissions",
            description="Checks for forms containing sensitive fields (e.g. passwords) that submit over plaintext HTTP."
        )

    def analyze(self, response: HTTPResponse) -> List[PassiveObservation]:
        observations: List[PassiveObservation] = []
        response_text = response.text if isinstance(response.text, str) else ""
        if not response_text:
            return observations

        try:
            tree = HTMLParser(response_text)
        except Exception:
            return observations

        # Select all form elements
        for form_node in tree.css("form"):
            action = form_node.attributes.get("action", "")
            
            # Resolve the absolute action URL
            full_action = URLNormalizer.resolve_relative(response.url, action)
            parsed_action = urllib.parse.urlparse(full_action)

            # Check if this form has any password input fields
            has_password = False
            for input_node in form_node.css("input"):
                inp_type = input_node.attributes.get("type", "").lower()
                if inp_type == "password":
                    has_password = True
                    break

            if has_password:
                is_action_insecure = (parsed_action.scheme == "http")
                is_current_insecure = response.url.startswith("http://")

                if is_action_insecure or is_current_insecure:
                    observations.append(
                        PassiveObservation(
                            plugin_id=self.metadata.id,
                            observation_type="insecure_form",
                            title="Insecure Form Transmission (Password over HTTP)",
                            description=f"A form on this page contains a password input field but submits to an insecure HTTP URL: '{full_action}'. Credentials will be transmitted in plaintext.",
                            severity=Severity.HIGH,
                            evidence=[
                                Evidence(
                                    type="insecure_form",
                                    description="Sensitive form discovered submitting over HTTP.",
                                    data={
                                        "form_action": full_action,
                                        "action_scheme": parsed_action.scheme,
                                        "current_page": response.url
                                    }
                                )
                            ],
                            endpoint=response.url,
                            remediation="Ensure the login form submits to an HTTPS endpoint.",
                            **StandardsRegistry.get("insecure_password_transmission").__dict__
                        )
                    )

        return observations
