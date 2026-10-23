from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import uuid

from .base import DomainEntity


class ScanStatus(str, Enum):
    """Represents the current state of a scan."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Target(DomainEntity):
    """Represents a target for scanning."""
    identifier: str
    target_type: str = "auto"
    metadata: Dict[str, Any] = {}


class ScanConfig(DomainEntity):
    """Configuration for a specific scan."""
    engines: List[str] = ["default"]
    timeout_seconds: int = 3600
    parameters: Dict[str, Any] = {}


class ScanResult(DomainEntity):
    """Represents the output from scanning engines."""
    findings: List[Dict[str, Any]] = []
    errors: List[str] = []
    engine_results: Dict[str, Any] = {}


class Scan(DomainEntity):
    """The aggregate root representing a scan lifecycle."""
    id: str
    target: Target
    config: ScanConfig
    status: ScanStatus = ScanStatus.PENDING
    result: Optional[ScanResult] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    @classmethod
    def create(cls, target: Target, config: Optional[ScanConfig] = None) -> "Scan":
        """Factory method for creating a new Scan."""
        return cls(
            id=str(uuid.uuid4()),
            target=target,
            config=config or ScanConfig(),
            created_at=datetime.now(timezone.utc),
        )
