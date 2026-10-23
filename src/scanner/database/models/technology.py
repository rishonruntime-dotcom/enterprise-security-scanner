"""ORM model: Technology inventory."""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Float, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column
from ..engine import Base


class TechnologyORM(Base):
    __tablename__ = "technologies"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[str] = mapped_column(String, nullable=False)  # framework, cms, server, etc.
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    target_url: Mapped[str] = mapped_column(String, nullable=False)
    scan_id: Mapped[str | None] = mapped_column(String, nullable=True)
    cpe: Mapped[str | None] = mapped_column(String, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    detection_method: Mapped[str | None] = mapped_column(String, nullable=True, default="fingerprinting")
    detection_methods: Mapped[str | None] = mapped_column(Text, nullable=True)
    detection_source: Mapped[str | None] = mapped_column(String, nullable=True, default="Header")
    confidence_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_count: Mapped[int] = mapped_column(Integer, default=1)
    observed_on: Mapped[str | None] = mapped_column(String, nullable=True)
