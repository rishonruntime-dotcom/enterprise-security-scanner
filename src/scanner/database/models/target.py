"""ORM model: Target management."""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from ..engine import Base


class TargetORM(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    url: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    group: Mapped[str | None] = mapped_column(String, nullable=True)
    tags: Mapped[str | None] = mapped_column(String, nullable=True)  # CSV tags
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    total_scans: Mapped[int] = mapped_column(default=0)
    total_findings: Mapped[int] = mapped_column(default=0)
