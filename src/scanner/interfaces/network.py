from abc import ABC, abstractmethod
from typing import Optional

from ..network.models import HTTPRequest, HTTPResponse, AuthenticationContext


class HTTPClientInterface(ABC):
    """Interface for sending HTTP requests."""

    @abstractmethod
    async def send(self, request: HTTPRequest) -> HTTPResponse:
        """Send an HTTP request and return the response."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the underlying client and free resources."""
        pass


class BrowserInterface(ABC):
    """Interface for browser automation."""

    @abstractmethod
    async def get_page_content(self, url: str, discovered_endpoints: Optional[list] = None, local_storage: Optional[dict] = None) -> str:
        """Navigate to a URL and return the rendered HTML content, optionally capturing dynamic requests and injecting local storage."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the browser context."""
        pass


class SessionInterface(ABC):
    """Interface for session persistence and management."""

    @abstractmethod
    async def save_context(self, context: AuthenticationContext) -> None:
        """Persist an authentication context."""
        pass

    @abstractmethod
    async def get_context(self, context_id: str) -> Optional[AuthenticationContext]:
        """Retrieve an authentication context by ID."""
        pass
