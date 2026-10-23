"""
SQLAlchemy async engine.
The connection URL is injected from configuration — swap to
postgresql+asyncpg://... without touching any business logic.
"""
import os
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Common SQLAlchemy declarative base for all ORM models."""
    pass


def build_engine(database_url: str) -> AsyncEngine:
    """
    Build an async SQLAlchemy engine from a connection URL.

    SQLite (current): sqlite+aiosqlite:///./scanner.db
    PostgreSQL (future): postgresql+asyncpg://user:pass@host/db
    """
    connect_args = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    return create_async_engine(
        database_url,
        echo=False,
        connect_args=connect_args,
    )
