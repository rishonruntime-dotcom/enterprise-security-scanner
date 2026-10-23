"""SQLAlchemy implementation of AbstractFindingRepository."""
from typing import List, Optional
from datetime import datetime, timedelta
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from .base import BaseRepository
from ..database.models.finding import FindingORM
from ..interfaces.repositories import AbstractFindingRepository


class SQLAlchemyFindingRepository(BaseRepository[FindingORM], AbstractFindingRepository):

    def __init__(self, session: AsyncSession):
        super().__init__(FindingORM, session)

    async def get_by_id(self, finding_id: str) -> Optional[FindingORM]:
        return await super().get_by_id(finding_id)

    async def get_all(self, skip: int = 0, limit: int = 100) -> List[FindingORM]:
        stmt = select(FindingORM).order_by(FindingORM.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_scan(self, scan_id: str) -> List[FindingORM]:
        stmt = select(FindingORM).where(FindingORM.scan_id == scan_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_scan_id(self, scan_id: str) -> List[FindingORM]:
        return await self.get_by_scan(scan_id)

    async def count_by_severity(self) -> dict:
        stmt = select(FindingORM.severity, func.count(FindingORM.id)).group_by(FindingORM.severity)
        result = await self.session.execute(stmt)
        return {row[0]: row[1] for row in result.all()}

    async def get_trend(self, days: int = 30) -> List[dict]:
        since = datetime.utcnow() - timedelta(days=days)
        stmt = (
            select(
                func.date(FindingORM.created_at).label("date"),
                FindingORM.severity,
                func.count(FindingORM.id).label("count")
            )
            .where(FindingORM.created_at >= since)
            .group_by(func.date(FindingORM.created_at), FindingORM.severity)
            .order_by(func.date(FindingORM.created_at))
        )
        result = await self.session.execute(stmt)
        return [{"date": str(row.date), "severity": row.severity, "count": row.count} for row in result.all()]

    async def count(self) -> int:
        return await super().count()
