from abc import ABC, abstractmethod
from typing import List, Union

from ..network.http.manager import HTTPClientManager
from ..passive.models import PluginMetadata
from ..active.models import TestCase, DetectionCandidate
from ..crawler.models import Endpoint

class ActivePluginInterface(ABC):
    """Interface for active security analysis plugins."""
    
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return the metadata for this plugin."""
        pass
        
    @abstractmethod
    async def execute(self, endpoint: Union[str, Endpoint], http_manager: HTTPClientManager) -> List[DetectionCandidate]:
        """Execute active tests against the target endpoint."""
        pass

class RequestMutatorInterface(ABC):
    """Interface for generating mutated requests."""
    
    @abstractmethod
    def mutate(self, target: Union[str, Endpoint], payloads: List[str]) -> List[TestCase]:
        """Generate test cases by mutating the target endpoint."""
        pass
