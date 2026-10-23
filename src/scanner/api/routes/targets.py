from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
from datetime import datetime

router = APIRouter(prefix="/api/v1/targets", tags=["Targets"])


class CreateTargetRequest(BaseModel):
    url: str
    name: str
    description: str = ""
    group: str = ""


class UpdateTargetRequest(BaseModel):
    name: str | None = None
    description: str | None = None


class TargetResponse(BaseModel):
    id: str
    url: str
    name: str
    description: str | None
    is_active: bool
    group: str | None
    created_at: datetime
    last_scanned_at: datetime | None
    total_scans: int
    total_findings: int

    model_config = {"from_attributes": True}


@router.get("", response_model=List[TargetResponse])
async def list_targets(skip: int = 0, limit: int = 100):
    from ...api.app import get_target_manager
    targets = await get_target_manager().list_targets(skip=skip, limit=limit)
    return [TargetResponse.model_validate(t) for t in targets]


@router.post("", response_model=TargetResponse, status_code=201)
async def create_target(request: CreateTargetRequest):
    from ...api.app import get_target_manager
    try:
        target = await get_target_manager().create_target(
            url=request.url,
            name=request.name,
            description=request.description,
            group=request.group,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return TargetResponse.model_validate(target)


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: str):
    from ...api.app import get_target_manager
    target = await get_target_manager().get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return TargetResponse.model_validate(target)


@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(target_id: str, request: UpdateTargetRequest):
    from ...api.app import get_target_manager
    target = await get_target_manager().update_target(target_id, name=request.name, description=request.description)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return TargetResponse.model_validate(target)


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: str):
    from ...api.app import get_target_manager
    deleted = await get_target_manager().delete_target(target_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Target not found")
