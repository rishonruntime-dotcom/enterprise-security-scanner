"""
AsyncSession factory and FastAPI dependency.
Usage in routes: session: AsyncSession = Depends(get_session)
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, AsyncEngine


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker:
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


async def get_session(session_factory: async_sessionmaker) -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a managed AsyncSession per request."""
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
