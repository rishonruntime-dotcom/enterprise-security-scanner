from fastapi import APIRouter
from typing import List, Dict, Any

router = APIRouter(prefix="/api/v1/analytics", tags=["Analytics"])


@router.get("/findings-trend")
async def findings_trend(days: int = 30) -> List[Dict[str, Any]]:
    from ...api.app import get_analytics_service
    return await get_analytics_service().get_findings_trend(days=days)


@router.get("/severity-breakdown")
async def severity_breakdown() -> Dict[str, int]:
    from ...api.app import get_analytics_service
    return await get_analytics_service().get_severity_breakdown()


@router.get("/risk-distribution")
async def risk_distribution() -> List[Dict[str, Any]]:
    from ...api.app import get_analytics_service
    return await get_analytics_service().get_risk_distribution()


@router.get("/scan-status")
async def scan_status_breakdown() -> Dict[str, int]:
    from ...api.app import get_analytics_service
    return await get_analytics_service().get_scan_status_breakdown()
