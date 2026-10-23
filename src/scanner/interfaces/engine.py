from abc import ABC, abstractmethod
from typing import Any, Dict

from ..domain.scan import Scan


class ScannerEngine(ABC):
    """Interface for independent scanner engines."""

    @abstractmethod
    async def run(self, scan: Scan) -> Dict[str, Any]:
        """Execute the scan and return findings."""
        pass
