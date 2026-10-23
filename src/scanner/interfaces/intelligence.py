from abc import ABC, abstractmethod
from typing import List, Any

from ..network.models import HTTPResponse
from ..intelligence.models import Fingerprint


class DetectorInterface(ABC):
    """Interface for analyzing content to detect technologies."""
    
    @abstractmethod
    def analyze(self, response: HTTPResponse, html_content: str) -> List[Fingerprint]:
        """Analyze response data and return discovered fingerprints."""
        pass


class SignatureProviderInterface(ABC):
    """Interface for providing detection rules."""
    
    @abstractmethod
    def get_rules(self) -> List[Any]:
        """Return a list of detection rules."""
        pass
