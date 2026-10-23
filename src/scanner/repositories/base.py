"""Generic async CRUD base repository using SQLAlchemy."""
import inspect
from typing import Any, Generic, List, Optional, Type, TypeVar, cast
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

ModelT = TypeVar("ModelT")


async def _maybe_await(value: Any) -> Any:
    """Await a value if it is awaitable, otherwise return it as-is.

    SQLAlchemy ``AsyncSession.add`` is a synchronous call, but async test
    doubles may return a coroutine; normalise both paths.
    """
    if inspect.isawaitable(value):
        return await value
    return value


class BaseRepository(Generic[ModelT]):
    """Generic CRUD operations over SQLAlchemy ORM models."""

    def __init__(self, model: Type[ModelT], session: AsyncSession):
        self.model = model
        self.session = session

    async def create(self, instance: ModelT) -> ModelT:
        await _maybe_await(cast(Any, self.session.add(instance)))
        await self.session.flush()
        await self.session.refresh(instance)
        return instance

    async def get_by_id(self, pk: Any) -> Optional[ModelT]:
        result = await self.session.get(self.model, pk)
        return result

    async def get_all(self, skip: int = 0, limit: int = 100) -> List[ModelT]:
        stmt = select(self.model).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update(self, instance: ModelT) -> ModelT:
        await _maybe_await(cast(Any, self.session.add(instance)))
        await self.session.flush()
        await self.session.refresh(instance)
        return instance

    async def delete(self, instance: ModelT) -> None:
        await self.session.delete(instance)
        await self.session.flush()

    async def count(self) -> int:
        stmt = select(func.count()).select_from(self.model)
        result = await self.session.execute(stmt)
        return result.scalar_one()
