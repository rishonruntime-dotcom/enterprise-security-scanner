import asyncio
from typing import Optional, Tuple, Set, List
import structlog

from ..interfaces.crawler import URLQueueInterface
from .utils import URLNormalizer

logger = structlog.get_logger(__name__)


class InMemoryURLQueue(URLQueueInterface):
    """An in-memory, async-safe implementation of a crawler URL queue with state export support."""

    def __init__(self, max_depth: int = 3):
        self._queue: asyncio.Queue[Tuple[str, int]] = asyncio.Queue()
        self._visited: Set[str] = set()
        self._enqueued: Set[str] = set()
        self.max_depth = max_depth
        self._flat_queue: List[Tuple[str, int]] = []

    async def enqueue(self, url: str, depth: int, source_url: Optional[str] = None) -> None:
        """Add a URL to the queue if it meets criteria."""
        normalized_url = URLNormalizer.normalize(url)
        
        if depth > self.max_depth:
            return
            
        if normalized_url in self._visited or normalized_url in self._enqueued:
            return

        self._enqueued.add(normalized_url)
        self._flat_queue.append((normalized_url, depth))
        await self._queue.put((normalized_url, depth))
        logger.debug("Enqueued URL", url=normalized_url, depth=depth, source=source_url)

    async def dequeue(self) -> Optional[Tuple[str, int]]:
        """Retrieve the next URL from the queue."""
        if self._queue.empty():
            return None
            
        item = await self._queue.get()
        if item in self._flat_queue:
            self._flat_queue.remove(item)
        return item

    def mark_visited(self, url: str) -> None:
        """Mark a URL as definitively visited."""
        normalized_url = URLNormalizer.normalize(url)
        self._visited.add(normalized_url)

    def is_visited(self, url: str) -> bool:
        """Check if a URL has been visited."""
        normalized_url = URLNormalizer.normalize(url)
        return normalized_url in self._visited

    def qsize(self) -> int:
        """Get the current approximate size of the queue."""
        return self._queue.qsize()

    def get_visited_set(self) -> Set[str]:
        return self._visited

    def get_flat_queue(self) -> List[Tuple[str, int]]:
        return self._flat_queue

    def restore_state(self, visited: List[str], flat_queue: List[Tuple[str, int]]) -> None:
        """Restore queue state from saved serialization structures."""
        self._visited = set(visited)
        self._enqueued = set(visited) | {item[0] for item in flat_queue}
        self._flat_queue = list(flat_queue)
        
        # Re-populate asyncio queue
        while not self._queue.empty():
            self._queue.get_nowait()
            
        for item in flat_queue:
            self._queue.put_nowait(item)
