"""SQLAlchemy implementation of AbstractTechnologyRepository."""
import inspect
import json
from typing import List, Dict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .base import BaseRepository
from ..database.models.technology import TechnologyORM
from ..interfaces.repositories import AbstractTechnologyRepository


class SQLAlchemyTechnologyRepository(BaseRepository[TechnologyORM], AbstractTechnologyRepository):

    def __init__(self, session: AsyncSession):
        super().__init__(TechnologyORM, session)

    async def upsert(self, technology: TechnologyORM) -> TechnologyORM:
        stmt = select(TechnologyORM).where(
            TechnologyORM.scan_id == technology.scan_id,
            TechnologyORM.name == technology.name,
        )
        result = await self.session.execute(stmt)
        existing = result.scalar_one_or_none()
        # Real SQLAlchemy async Result.scalar_one_or_none() is synchronous, but
        # some async test doubles return a coroutine; normalise to the value.
        if inspect.isawaitable(existing):
            existing = await existing

        if existing:
            existing.occurrence_count = (existing.occurrence_count or 0) + 1
            existing.confidence = max(existing.confidence or 0.0, technology.confidence or 0.0)
            if technology.version and technology.version != "N/A":
                existing.version = technology.version
            if technology.category and technology.category != "General":
                existing.category = technology.category

            # Track all detection methods used for this technology
            methods: list[str] = []
            if existing.detection_methods:
                try:
                    methods = json.loads(existing.detection_methods)
                except (json.JSONDecodeError, TypeError):
                    methods = [existing.detection_methods]
            if technology.detection_method and technology.detection_method not in methods:
                methods.append(technology.detection_method)
            if methods:
                existing.detection_methods = json.dumps(methods)
            if technology.detection_method:
                existing.detection_method = technology.detection_method

            return await self.update(existing)
        else:
            return await self.create(technology)

    async def get_all(self, skip: int = 0, limit: int = 100) -> List[TechnologyORM]:
        stmt = select(TechnologyORM).order_by(TechnologyORM.occurrence_count.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_scan(self, scan_id: str) -> List[TechnologyORM]:
        stmt = select(TechnologyORM).where(TechnologyORM.scan_id == scan_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_scan_id(self, scan_id: str) -> List[TechnologyORM]:
        return await self.get_by_scan(scan_id)

    async def get_by_category(self, category: str) -> List[TechnologyORM]:
        stmt = select(TechnologyORM).where(TechnologyORM.category == category)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_grouped_by_category(self, scan_id: str) -> Dict[str, List[TechnologyORM]]:
        """Group technologies by category for structured reporting."""
        techs = await self.get_by_scan(scan_id)
        grouped: Dict[str, List[TechnologyORM]] = {}
        for tech in techs:
            cat = tech.category or "General"
            grouped.setdefault(cat, []).append(tech)
        return grouped

    async def get_unique(self, scan_id: str) -> List[TechnologyORM]:
        """Return de-duplicated technologies, merging occurrence counts and detection methods."""
        from sqlalchemy import func
        stmt = (
            select(
                TechnologyORM.name,
                TechnologyORM.category,
                func.max(TechnologyORM.version).label("version"),
                func.max(TechnologyORM.vendor).label("vendor"),
                func.max(TechnologyORM.confidence).label("confidence"),
                func.max(TechnologyORM.cpe).label("cpe"),
                func.max(TechnologyORM.detection_method).label("detection_method"),
                func.sum(TechnologyORM.occurrence_count).label("occurrence_count"),
            )
            .where(TechnologyORM.scan_id == scan_id)
            .group_by(TechnologyORM.name, TechnologyORM.category)
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count(self) -> int:
        return await super().count()
