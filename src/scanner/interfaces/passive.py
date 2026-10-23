from abc import ABC, abstractmethod
from typing import List

from ..network.models import HTTPResponse
from ..passive.models import PluginMetadata, PassiveObservation

class PassivePluginInterface(ABC):
    """Interface for passive security analysis plugins."""
    
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return the metadata for this plugin."""
        pass
        
    @abstractmethod
    def analyze(self, response: HTTPResponse) -> List[PassiveObservation]:
        """Analyze an HTTP response and return any discovered passive observations."""
        pass
