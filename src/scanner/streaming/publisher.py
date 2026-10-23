"""
InMemoryEventPublisher — concrete implementation of AbstractEventPublisher.

Uses asyncio.Queue per event type for in-process pub/sub.
WebSocket connections subscribe to the 'scan.progress' topic.

To swap in Redis Pub/Sub:
  1. Create RedisEventPublisher(AbstractEventPublisher)
  2. Update the DI container binding — zero changes to business logic.
"""
import asyncio
import json
from collections import defaultdict
from typing import Any, Dict, AsyncGenerator

from ..interfaces.event_publisher import AbstractEventPublisher


class InMemoryEventPublisher(AbstractEventPublisher):
    """In-process asyncio-queue event publisher. Not suitable for multi-process deployments."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue]] = defaultdict(list)

    async def publish(self, event_type: str, payload: Dict[str, Any]) -> None:
        message = json.dumps({"type": event_type, "payload": payload})
        dead = []
        for queue in self._subscribers.get(event_type, []):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                dead.append(queue)
        # Clean up full/dead queues
        for q in dead:
            self._subscribers[event_type].remove(q)

    async def subscribe(self, event_type: str) -> asyncio.Queue:
        """Returns a queue that will receive published messages for event_type."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers[event_type].append(queue)
        return queue

    def unsubscribe(self, event_type: str, queue: asyncio.Queue) -> None:
        try:
            self._subscribers[event_type].remove(queue)
        except ValueError:
            pass
