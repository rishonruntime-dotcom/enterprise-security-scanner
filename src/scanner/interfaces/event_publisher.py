"""
Abstract EventPublisher interface.
Business logic publishes events through this interface.
Current implementation: in-memory asyncio queues + WebSocket broadcast.
Future implementation: Redis Pub/Sub — swap only the concrete class in the DI container.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict


class AbstractEventPublisher(ABC):
    """Publish domain events to all subscribers."""

    @abstractmethod
    async def publish(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Publish an event of the given type with an arbitrary payload."""
        ...

    @abstractmethod
    async def subscribe(self, event_type: str) -> Any:
        """Return an async context manager or queue to consume events of the given type."""
        ...
