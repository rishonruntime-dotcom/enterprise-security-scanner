from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1")


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "2.4.0-enterprise"


@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    return HealthResponse()
