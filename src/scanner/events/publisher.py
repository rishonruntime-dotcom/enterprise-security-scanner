import structlog
from typing import Any, List

from ..interfaces.events import EventPublisher
from .models import Event

logger = structlog.get_logger(__name__)


class InMemoryEventPublisher(EventPublisher):
    """An in-memory event publisher for development and testing."""

    def __init__(self):
        self.published_events: List[Event] = []

    async def publish(self, event_type: str, payload: Any) -> None:
        """Publish an event by logging it and storing it in memory."""
        event = Event(type=event_type, payload=payload)
        self.published_events.append(event)
        
        logger.info(
            "Event published",
            event_type=event.type,
            event_id=event.id,
        )
