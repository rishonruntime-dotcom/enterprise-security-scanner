"""SQLAlchemy implementation of AbstractScanRepository."""
from typing import List, Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from .base import BaseRepository
from ..database.models.scan import ScanORM, ScanStatus
from ..interfaces.repositories import AbstractScanRepository


class SQLAlchemyScanRepository(BaseRepository[ScanORM], AbstractScanRepository):

    def __init__(self, session: AsyncSession):
        super().__init__(ScanORM, session)

    async def get_by_id(self, scan_id: str) -> Optional[ScanORM]:
        return await super().get_by_id(scan_id)

    async def get_all(self, skip: int = 0, limit: int = 100) -> List[ScanORM]:
        stmt = select(ScanORM).order_by(ScanORM.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def delete(self, scan_id: str) -> None:
        instance = await self.get_by_id(scan_id)
        if instance:
            await super().delete(instance)

    async def get_recent(self, limit: int = 10) -> List[ScanORM]:
        stmt = select(ScanORM).order_by(ScanORM.created_at.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_status(self) -> dict:
        stmt = select(ScanORM.status, func.count(ScanORM.id)).group_by(ScanORM.status)
        result = await self.session.execute(stmt)
        return {row[0]: row[1] for row in result.all()}
