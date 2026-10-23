from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
from datetime import datetime

from ...database.models.scan import ScanStatus

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])


class CreateScanRequest(BaseModel):
    target_url: str
    scan_type: str = "full"
    profile: str = "default"
    asset_criticality: str | None = None
    exposure: str | None = None


class ScanResponse(BaseModel):
    id: str
    target_url: str
    status: str
    progress: float
    total_findings: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    asset_criticality: str | None
    exposure: str | None

    model_config = {"from_attributes": True}


@router.get("", response_model=List[ScanResponse])
async def list_scans(skip: int = 0, limit: int = 50):
    from ...api.app import get_db_session_factory, get_scan_manager
    async with get_db_session_factory()() as session:
        from ...repositories.scan_repo import SQLAlchemyScanRepository
        repo = SQLAlchemyScanRepository(session)
        scans = await repo.get_all(skip=skip, limit=limit)
    return [ScanResponse.model_validate(s) for s in scans]


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(request: CreateScanRequest):
    from ...api.app import get_db_session_factory, get_scan_manager
    async with get_db_session_factory()() as session:
        from ...repositories.scan_repo import SQLAlchemyScanRepository
        from ...management.scan_manager import ScanManager
        repo = SQLAlchemyScanRepository(session)
        manager = get_scan_manager()
        scan = await manager.create_scan(
            target_url=request.target_url,
            scan_type=request.scan_type,
            profile=request.profile,
            asset_criticality=request.asset_criticality,
            exposure=request.exposure,
        )
        # Auto-start
        scan = await manager.start_scan(scan.id)
    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str):
    from ...api.app import get_db_session_factory
    async with get_db_session_factory()() as session:
        from ...repositories.scan_repo import SQLAlchemyScanRepository
        repo = SQLAlchemyScanRepository(session)
        scan = await repo.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse.model_validate(scan)


@router.post("/{scan_id}/pause", response_model=ScanResponse)
async def pause_scan(scan_id: str):
    from ...api.app import get_scan_manager
    scan = await get_scan_manager().pause_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse.model_validate(scan)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(scan_id: str):
    from ...api.app import get_scan_manager
    scan = await get_scan_manager().cancel_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse.model_validate(scan)
