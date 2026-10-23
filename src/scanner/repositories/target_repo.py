"""SQLAlchemy implementation of AbstractTargetRepository."""
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .base import BaseRepository
from ..database.models.target import TargetORM
from ..interfaces.repositories import AbstractTargetRepository


class SQLAlchemyTargetRepository(BaseRepository[TargetORM], AbstractTargetRepository):

    def __init__(self, session: AsyncSession):
        super().__init__(TargetORM, session)

    async def get_by_id(self, target_id: str) -> Optional[TargetORM]:
        return await super().get_by_id(target_id)

    async def get_all(self, skip: int = 0, limit: int = 100) -> List[TargetORM]:
        stmt = select(TargetORM).order_by(TargetORM.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update(self, target: TargetORM) -> TargetORM:
        return await super().update(target)

    async def delete(self, target_id: str) -> None:
        instance = await self.get_by_id(target_id)
        if instance:
            await super().delete(instance)

    async def get_by_url(self, url: str) -> Optional[TargetORM]:
        stmt = select(TargetORM).where(TargetORM.url == url)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def count(self) -> int:
        return await super().count()
