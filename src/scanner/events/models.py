from datetime import datetime, timezone
import uuid
from typing import Any, Dict

from pydantic import BaseModel, ConfigDict, Field


class Event(BaseModel):
    """Base event model."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    type: str
    payload: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)
