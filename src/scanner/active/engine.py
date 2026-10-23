import importlib
import inspect
import pkgutil
import asyncio
from typing import List, Dict, Union
import structlog

from ..interfaces.active import ActivePluginInterface
from ..network.http.manager import HTTPClientManager
from ..active.models import DetectionCandidate
from ..crawler.models import Endpoint
from .plugins import __name__ as plugins_package_name

logger = structlog.get_logger(__name__)


class ActiveScannerManager:
    """Orchestrates active security plugins against endpoints."""

    def __init__(self, http_manager: HTTPClientManager, plugin_package: str = plugins_package_name):
        self.http_manager = http_manager
        self.plugin_package = plugin_package
        self.plugins: Dict[str, ActivePluginInterface] = {}
        self._load_plugins()

    def _load_plugins(self):
        """Dynamically load all plugins implementing ActivePluginInterface."""
        try:
            package = importlib.import_module(self.plugin_package)
            
            for _, module_name, _ in pkgutil.iter_modules(package.__path__):
                full_module_name = f"{self.plugin_package}.{module_name}"
                module = importlib.import_module(full_module_name)
                
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, ActivePluginInterface) and obj != ActivePluginInterface:
                        try:
                            plugin_instance = obj()
                            plugin_id = plugin_instance.metadata.id
                            self.plugins[plugin_id] = plugin_instance
                            logger.debug("Loaded active plugin", plugin_id=plugin_id, plugin_name=plugin_instance.metadata.name)
                        except Exception as e:
                            logger.error("Failed to instantiate active plugin", plugin_class=name, error=str(e))
                            
            logger.info("Active plugins loading complete", total_plugins=len(self.plugins))
        except Exception as e:
            logger.error("Failed to load active plugins package", package=self.plugin_package, error=str(e))

    async def analyze_endpoint(self, endpoint: Union[str, Endpoint]) -> List[DetectionCandidate]:
        """Run all loaded active plugins against the target endpoint."""
        all_candidates: List[DetectionCandidate] = []
        
        url = endpoint.url if not isinstance(endpoint, str) else endpoint
        logger.debug("Running active analysis", url=url, plugins_count=len(self.plugins))
        
        # Sequentially evaluate plugins
        for plugin_id, plugin in self.plugins.items():
            try:
                candidates = await plugin.execute(endpoint, self.http_manager)
                if candidates:
                    all_candidates.extend(candidates)
                    logger.debug("Active plugin generated candidates", plugin_id=plugin_id, count=len(candidates))
            except Exception as e:
                logger.error("Active plugin execution failed", plugin_id=plugin_id, error=str(e))
                
        if all_candidates:
            logger.warning("Active analysis discovered candidates!", url=url, total_candidates=len(all_candidates))
            
        return all_candidates

    async def scan_endpoints(self, endpoints: List[Union[str, Endpoint]]) -> List[DetectionCandidate]:
        """Run active plugins against a list of endpoints."""
        all_candidates: List[DetectionCandidate] = []
        for ep in endpoints:
            cands = await self.analyze_endpoint(ep)
            if cands:
                all_candidates.extend(cands)
        return all_candidates

    async def scan(self, endpoints: List[Union[str, Endpoint]]) -> List[DetectionCandidate]:
        """Alias for scan_endpoints."""
        return await self.scan_endpoints(endpoints)

    async def run_plugins(self, endpoints: List[Union[str, Endpoint]]) -> List[DetectionCandidate]:
        """Alias for scan_endpoints."""
        return await self.scan_endpoints(endpoints)
