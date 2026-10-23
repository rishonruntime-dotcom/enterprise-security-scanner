"""TargetManager — CRUD and validation for scan targets."""
import re
import uuid
from typing import List, Optional
from urllib.parse import urlparse
import structlog

from ..database.models.target import TargetORM
from ..interfaces.repositories import AbstractTargetRepository

logger = structlog.get_logger(__name__)


class TargetManager:

    def __init__(self, target_repo: AbstractTargetRepository) -> None:
        self._repo = target_repo

    def _validate_url(self, url: str) -> str:
        """Validate and normalize a target URL. Raises ValueError on SSRF risks."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid scheme '{parsed.scheme}'. Only http/https allowed.")
        hostname = parsed.hostname or ""
        # SSRF guard: block loopback and private ranges
        blocked = ["localhost", "127.", "169.254.", "10.", "192.168.", "::1"]
        if any(hostname.startswith(b) for b in blocked):
            raise ValueError(f"Target hostname '{hostname}' is blocked (SSRF protection).")
        return url

    async def create_target(self, url: str, name: str, description: str = "", group: str = "") -> TargetORM:
        url = self._validate_url(url)
        existing = await self._repo.get_by_url(url)
        if existing:
            raise ValueError(f"Target with URL '{url}' already exists.")
        target = TargetORM(
            id=str(uuid.uuid4()),
            url=url,
            name=name,
            description=description,
            group=group or None,
        )
        target = await self._repo.create(target)
        logger.info("Target created", target_id=target.id, url=url)
        return target

    async def get_target(self, target_id: str) -> Optional[TargetORM]:
        return await self._repo.get_by_id(target_id)

    async def list_targets(self, skip: int = 0, limit: int = 100) -> List[TargetORM]:
        return await self._repo.get_all(skip=skip, limit=limit)

    async def update_target(self, target_id: str, name: str = None, description: str = None) -> Optional[TargetORM]:
        target = await self._repo.get_by_id(target_id)
        if not target:
            return None
        if name:
            target.name = name
        if description is not None:
            target.description = description
        return await self._repo.update(target)

    async def delete_target(self, target_id: str) -> bool:
        target = await self._repo.get_by_id(target_id)
        if not target:
            return False
        await self._repo.delete(target_id)
        logger.info("Target deleted", target_id=target_id)
        return True

    async def count(self) -> int:
        return await self._repo.count()
