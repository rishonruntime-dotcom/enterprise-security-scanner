"""WebSocket endpoint for real-time scan progress."""
import uuid
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import structlog

router = APIRouter(tags=["WebSockets"])
logger = structlog.get_logger(__name__)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    from ...api.app import get_ws_manager
    manager = get_ws_manager()
    connection_id = str(uuid.uuid4())
    await manager.connect(connection_id, websocket)
    try:
        while True:
            # Keep connection alive; client can send ping
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(connection_id)
        logger.info("WebSocket disconnected cleanly", connection_id=connection_id)
    except Exception as e:
        manager.disconnect(connection_id)
        logger.error("WebSocket error", error=str(e))
