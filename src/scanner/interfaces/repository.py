from abc import ABC, abstractmethod
from typing import Optional, List

from ..domain.scan import Scan


class ScanRepository(ABC):
    """Interface for scan persistence."""

    @abstractmethod
    async def save(self, scan: Scan) -> None:
        """Save a scan to the repository."""
        pass

    @abstractmethod
    async def get(self, scan_id: str) -> Optional[Scan]:
        """Retrieve a scan by ID."""
        pass

    @abstractmethod
    async def list_scans(self) -> List[Scan]:
        """List all scans (pagination omitted for simplicity)."""
        pass
