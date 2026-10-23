import structlog
import httpx
from typing import Optional, Dict

from ...interfaces.network import HTTPClientInterface
from .client import HttpxClientAdapter

logger = structlog.get_logger(__name__)


class HTTPClientManager:
    """Manages creation and configuration of HTTP clients."""

    def __init__(self, default_timeout: float = 30.0, max_connections: int = 100):
        self.default_timeout = default_timeout
        self.max_connections = max_connections
        self._shared_client: Optional[HTTPClientInterface] = None
        self.total_requests = 0

    def create_client(self, timeout: Optional[float] = None) -> HTTPClientInterface:
        """Create a new, isolated HTTP client."""
        limits = httpx.Limits(max_connections=self.max_connections)
        httpx_client = httpx.AsyncClient(
            timeout=timeout or self.default_timeout,
            limits=limits,
            http2=True,
            verify=False  # Typically false for a security scanner, but should be configurable
        )
        adapter = HttpxClientAdapter(httpx_client)
        adapter.manager = self
        return adapter

    def get_shared_client(self) -> HTTPClientInterface:
        """Get or create a shared client for connection pooling across components."""
        if self._shared_client is None:
            self._shared_client = self.create_client()
            logger.info("Initialized shared HTTP client")
        return self._shared_client

    async def close(self):
        """Close all managed clients."""
        if self._shared_client:
            await self._shared_client.close()
            self._shared_client = None
            logger.info("Closed shared HTTP client")
