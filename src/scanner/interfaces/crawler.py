from abc import ABC, abstractmethod
from typing import List, Optional, Tuple, Union

from ..crawler.models import Endpoint, Form, Asset


class URLQueueInterface(ABC):
    """Interface for managing the crawler queue."""

    @abstractmethod
    async def enqueue(self, url: str, depth: int, source_url: Optional[str] = None) -> None:
        """Add a URL to the queue if it hasn't been visited and is within depth."""
        pass

    @abstractmethod
    async def dequeue(self) -> Optional[Tuple[str, int]]:
        """Retrieve the next URL and its depth from the queue."""
        pass

    @abstractmethod
    def mark_visited(self, url: str) -> None:
        """Mark a URL as visited."""
        pass
        
    @abstractmethod
    def is_visited(self, url: str) -> bool:
        """Check if a URL has already been visited."""
        pass

    @abstractmethod
    def qsize(self) -> int:
        """Get the current queue size."""
        pass


class DiscoveryExtractorInterface(ABC):
    """Interface for parsing content and discovering assets."""

    @abstractmethod
    def extract(self, html_content: str, current_url: str) -> List[Union[Endpoint, Form, Asset]]:
        """Parse HTML and return discovered items."""
        pass
