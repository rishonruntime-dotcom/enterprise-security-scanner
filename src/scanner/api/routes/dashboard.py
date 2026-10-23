from fastapi import APIRouter
from typing import Dict, Any

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])


@router.get("/summary")
async def get_dashboard_summary() -> Dict[str, Any]:
    from ...api.app import get_dashboard_service
    return await get_dashboard_service().get_summary()
