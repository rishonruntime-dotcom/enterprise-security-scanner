"""
WebSocket connection manager.
Keeps a registry of active WebSocket connections and provides
broadcast / targeted send capabilities, backed by the EventPublisher.
"""
import asyncio
import json
from typing import Dict
from fastapi import WebSocket
import structlog

from .publisher import InMemoryEventPublisher

logger = structlog.get_logger(__name__)


class WebSocketConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self, publisher: InMemoryEventPublisher) -> None:
        self._connections: Dict[str, WebSocket] = {}
        self._publisher = publisher

    async def connect(self, connection_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[connection_id] = websocket
        logger.info("WebSocket connected", connection_id=connection_id, total=len(self._connections))

    def disconnect(self, connection_id: str) -> None:
        self._connections.pop(connection_id, None)
        logger.info("WebSocket disconnected", connection_id=connection_id)

    async def send_to(self, connection_id: str, message: dict) -> None:
        ws = self._connections.get(connection_id)
        if ws:
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(connection_id)

    async def broadcast(self, message: dict) -> None:
        dead = []
        for cid, ws in list(self._connections.items()):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(cid)
        for cid in dead:
            self.disconnect(cid)

    async def listen_and_forward(self, event_type: str) -> None:
        """Background task: listen to event_type and broadcast to all WebSocket clients."""
        queue = await self._publisher.subscribe(event_type)
        while True:
            try:
                raw = await asyncio.wait_for(queue.get(), timeout=30)
                data = json.loads(raw)
                await self.broadcast(data)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("WebSocket forward error", error=str(e))

    @property
    def active_connections(self) -> int:
        return len(self._connections)
