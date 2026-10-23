from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Dict
from datetime import datetime

router = APIRouter(prefix="/api/v1/technologies", tags=["Technologies"])


class TechnologyResponse(BaseModel):
    id: str
    name: str
    category: str
    version: str | None
    vendor: str | None
    confidence: float
    target_url: str
    cpe: str | None
    detected_at: datetime
    occurrence_count: int
    detection_method: str | None = None
    detection_methods: List[str] = []

    model_config = {"from_attributes": True}


class TechnologyGroupResponse(BaseModel):
    category: str
    technologies: List[TechnologyResponse]
    count: int

    model_config = {"from_attributes": True}


@router.get("", response_model=List[TechnologyResponse])
async def list_technologies(skip: int = 0, limit: int = 100):
    from ...api.app import get_db_session_factory
    async with get_db_session_factory()() as session:
        from ...repositories.technology_repo import SQLAlchemyTechnologyRepository
        repo = SQLAlchemyTechnologyRepository(session)
        techs = await repo.get_all(skip=skip, limit=limit)
    return [_tech_to_response(t) for t in techs]


@router.get("/grouped", response_model=List[TechnologyGroupResponse])
async def list_technologies_grouped(scan_id: str | None = None):
    from ...api.app import get_db_session_factory
    async with get_db_session_factory()() as session:
        from ...repositories.technology_repo import SQLAlchemyTechnologyRepository
        repo = SQLAlchemyTechnologyRepository(session)
        if scan_id:
            techs = await repo.get_by_scan(scan_id)
        else:
            techs = await repo.get_all()

    grouped: Dict[str, List[dict]] = {}
    for t in techs:
        cat = t.category or "General"
        grouped.setdefault(cat, []).append(_tech_to_response(t).model_dump())

    return [
        TechnologyGroupResponse(
            category=cat,
            technologies=[_tech_to_response_from_dict(d) for d in tech_list],
            count=len(tech_list),
        )
        for cat, tech_list in sorted(grouped.items())
    ]


def _tech_to_response(t) -> TechnologyResponse:
    det_methods = []
    dm = getattr(t, "detection_methods", None)
    if dm:
        import json
        try:
            det_methods = json.loads(dm)
        except (json.JSONDecodeError, TypeError):
            det_methods = [dm]
    return TechnologyResponse(
        id=getattr(t, "id", ""),
        name=getattr(t, "name", ""),
        category=getattr(t, "category", ""),
        version=getattr(t, "version", None),
        vendor=getattr(t, "vendor", None),
        confidence=getattr(t, "confidence", 0.0),
        target_url=getattr(t, "target_url", ""),
        cpe=getattr(t, "cpe", None),
        detected_at=getattr(t, "detected_at", datetime.now()),
        occurrence_count=getattr(t, "occurrence_count", 1),
        detection_method=getattr(t, "detection_method", None),
        detection_methods=det_methods,
    )


def _tech_to_response_from_dict(d: dict) -> TechnologyResponse:
    return TechnologyResponse(**d)


@router.get("/categories", response_model=List[str])
async def list_categories():
    from ...api.app import get_db_session_factory
    from sqlalchemy import select
    from ...database.models.technology import TechnologyORM
    async with get_db_session_factory()() as session:
        stmt = select(TechnologyORM.category).distinct()
        result = await session.execute(stmt)
        cats = [row[0] for row in result.all()]
    return cats
