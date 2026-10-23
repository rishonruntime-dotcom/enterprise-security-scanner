from abc import ABC, abstractmethod
from typing import Any


class EventPublisher(ABC):
    """Interface for publishing events."""

    @abstractmethod
    async def publish(self, event_type: str, payload: Any) -> None:
        """Publish an event to the message bus."""
        pass
