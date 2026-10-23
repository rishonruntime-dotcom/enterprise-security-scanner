import importlib
import inspect
import pkgutil
from typing import List, Type, Dict
import structlog

from ..interfaces.passive import PassivePluginInterface
from ..network.models import HTTPResponse
from ..passive.models import PassiveObservation
from .plugins import __name__ as plugins_package_name

logger = structlog.get_logger(__name__)


class PassiveScannerManager:
    """Orchestrates passive security plugins against HTTP responses."""

    def __init__(self, plugin_package: str = plugins_package_name):
        self.plugin_package = plugin_package
        self.plugins: Dict[str, PassivePluginInterface] = {}
        self._load_plugins()

    def _load_plugins(self):
        """Dynamically load all plugins implementing PassivePluginInterface and guarantee built-ins."""
        # 1. Explicitly register built-in plugins for deterministic execution
        try:
            from .plugins.headers import MissingSecurityHeadersPlugin
            from .plugins.cookies import CookieSecurityPlugin
            from .plugins.form_security import FormSecurityPlugin
            from .plugins.info_disclosure import InformationDisclosurePlugin
            from .plugins.outdated_components import OutdatedComponentsPlugin
            from .plugins.csp_reasoning import CSPReasoningPlugin

            builtins = [
                MissingSecurityHeadersPlugin,
                CookieSecurityPlugin,
                FormSecurityPlugin,
                InformationDisclosurePlugin,
                OutdatedComponentsPlugin,
                CSPReasoningPlugin,
            ]
            for cls in builtins:
                try:
                    inst = cls()
                    self.plugins[inst.metadata.id] = inst
                    logger.debug("Registered built-in passive plugin", plugin_id=inst.metadata.id)
                except Exception as ex:
                    logger.error("Failed to register built-in passive plugin", plugin=cls.__name__, error=str(ex))
        except Exception as e:
            logger.error("Error importing built-in passive plugins", error=str(e))

        # 2. Dynamically scan package for additional custom plugins
        try:
            package = importlib.import_module(self.plugin_package)
            for _, module_name, _ in pkgutil.iter_modules(package.__path__):
                full_module_name = f"{self.plugin_package}.{module_name}"
                module = importlib.import_module(full_module_name)
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, PassivePluginInterface) and obj != PassivePluginInterface:
                        try:
                            plugin_instance = obj()
                            plugin_id = plugin_instance.metadata.id
                            self.plugins[plugin_id] = plugin_instance
                            logger.debug("Loaded passive plugin", plugin_id=plugin_id, plugin_name=plugin_instance.metadata.name)
                        except Exception as e:
                            logger.error("Failed to instantiate plugin", plugin_class=name, error=str(e))
                            
            logger.info("Passive plugins loading complete", total_plugins=len(self.plugins))
        except Exception as e:
            logger.error("Failed to load passive plugins package", package=self.plugin_package, error=str(e))

    def analyze_response(self, response: HTTPResponse) -> List[PassiveObservation]:
        """Run all loaded passive plugins against the response."""
        all_observations: List[PassiveObservation] = []
        
        # Exclude passive header/clickjacking checks on static fonts, images, media & CSS
        url_lower = response.url.lower()
        if any(url_lower.endswith(ext) or f"{ext}?" in url_lower for ext in [
            '.otf', '.ttf', '.woff', '.woff2', '.eot', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.mp4', '.webm', '.map'
        ]):
            logger.debug("Skipping passive analysis on static asset URL", url=response.url)
            return all_observations

        logger.debug("Running passive analysis", url=response.url, plugins_count=len(self.plugins))
        
        for plugin_id, plugin in self.plugins.items():
            try:
                observations = plugin.analyze(response)
                if observations:
                    all_observations.extend(observations)
                    logger.debug("Plugin generated observations", plugin_id=plugin_id, count=len(observations))
            except Exception as e:
                # Isolate plugin failures so one bad plugin doesn't crash the scanner
                logger.error("Passive plugin execution failed", plugin_id=plugin_id, error=str(e))
                
        if all_observations:
            logger.info("Passive analysis found observations", url=response.url, total_observations=len(all_observations))
            
        return all_observations
