"""
Abstract repository interfaces.
These contracts define the data access layer API.
Implementations (SQLAlchemy, in-memory, etc.) live in src/scanner/repositories/.
Swapping from SQLite to PostgreSQL requires only changing the implementation,
never the business logic or API layer.
"""
from abc import ABC, abstractmethod
from typing import List, Optional, Any
from datetime import datetime


class AbstractScanRepository(ABC):
    """Interface for scan persistence operations."""

    @abstractmethod
    async def create(self, scan: Any) -> Any: ...

    @abstractmethod
    async def get_by_id(self, scan_id: str) -> Optional[Any]: ...

    @abstractmethod
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[Any]: ...

    @abstractmethod
    async def update(self, scan: Any) -> Any: ...

    @abstractmethod
    async def delete(self, scan_id: str) -> None: ...

    @abstractmethod
    async def get_recent(self, limit: int = 10) -> List[Any]: ...

    @abstractmethod
    async def count_by_status(self) -> dict: ...


class AbstractTargetRepository(ABC):
    """Interface for target persistence operations."""

    @abstractmethod
    async def create(self, target: Any) -> Any: ...

    @abstractmethod
    async def get_by_id(self, target_id: str) -> Optional[Any]: ...

    @abstractmethod
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[Any]: ...

    @abstractmethod
    async def update(self, target: Any) -> Any: ...

    @abstractmethod
    async def delete(self, target_id: str) -> None: ...

    @abstractmethod
    async def get_by_url(self, url: str) -> Optional[Any]: ...

    @abstractmethod
    async def count(self) -> int: ...


class AbstractFindingRepository(ABC):
    """Interface for finding persistence operations."""

    @abstractmethod
    async def create(self, finding: Any) -> Any: ...

    @abstractmethod
    async def get_by_id(self, finding_id: str) -> Optional[Any]: ...

    @abstractmethod
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[Any]: ...

    @abstractmethod
    async def get_by_scan(self, scan_id: str) -> List[Any]: ...

    @abstractmethod
    async def count_by_severity(self) -> dict: ...

    @abstractmethod
    async def get_trend(self, days: int = 30) -> List[Any]: ...

    @abstractmethod
    async def count(self) -> int: ...


class AbstractTechnologyRepository(ABC):
    """Interface for technology inventory persistence."""

    @abstractmethod
    async def upsert(self, technology: Any) -> Any: ...

    @abstractmethod
    async def get_all(self, skip: int = 0, limit: int = 100) -> List[Any]: ...

    @abstractmethod
    async def get_by_scan(self, scan_id: str) -> List[Any]: ...

    @abstractmethod
    async def get_by_category(self, category: str) -> List[Any]: ...

    @abstractmethod
    async def count(self) -> int: ...
