from typing import Dict, List, Optional
import structlog

from ..domain.scan import Scan
from ..interfaces.repository import ScanRepository

logger = structlog.get_logger(__name__)


class InMemoryScanRepository(ScanRepository):
    """In-memory implementation of ScanRepository for development/testing."""

    def __init__(self):
        self._storage: Dict[str, Scan] = {}

    async def save(self, scan: Scan) -> None:
        """Save a scan to memory."""
        self._storage[scan.id] = scan
        logger.debug("Saved scan to memory", scan_id=scan.id, status=scan.status.value)

    async def get(self, scan_id: str) -> Optional[Scan]:
        """Retrieve a scan by ID from memory."""
        return self._storage.get(scan_id)

    async def list_scans(self) -> List[Scan]:
        """List all scans in memory."""
        return list(self._storage.values())
