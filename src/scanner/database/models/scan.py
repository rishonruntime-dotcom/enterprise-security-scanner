"""ORM model: Scan lifecycle."""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Float, Integer, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column
from enum import Enum
from ..engine import Base


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanORM(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    high_findings: Mapped[int] = mapped_column(Integer, default=0)
    medium_findings: Mapped[int] = mapped_column(Integer, default=0)
    low_findings: Mapped[int] = mapped_column(Integer, default=0)
    pages_discovered: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    endpoints_discovered: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    forms_discovered: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    parameters_discovered: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    browser_routes_discovered: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    http_requests_sent: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    payloads_executed: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    verification_requests: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error_message: Mapped[str | None] = mapped_column(String, nullable=True)
    scan_type: Mapped[str] = mapped_column(String, default="full")
    profile: Mapped[str] = mapped_column(String, default="default")
    asset_criticality: Mapped[str | None] = mapped_column(String, nullable=True)
    exposure: Mapped[str | None] = mapped_column(String, nullable=True)
    network_open_ports: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    network_services_detected: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    network_risky_services: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)
    network_exposure_result: Mapped[str | None] = mapped_column(String, nullable=True)

    @property
    def urls_discovered(self) -> int:
        return self.endpoints_discovered or self.pages_discovered or 0

    @urls_discovered.setter
    def urls_discovered(self, value: int):
        self.endpoints_discovered = value
        self.pages_discovered = value

    @property
    def endpoints_tested(self) -> int:
        return self.http_requests_sent or 0

    @endpoints_tested.setter
    def endpoints_tested(self, value: int):
        self.http_requests_sent = value
