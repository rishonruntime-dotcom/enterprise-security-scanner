"""ORM model: Persistent findings store."""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Float, Text
from sqlalchemy.orm import Mapped, mapped_column
from ..engine import Base


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str | None] = mapped_column(String, nullable=True)
    plugin_id: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    original_severity: Mapped[str | None] = mapped_column(String, nullable=True)
    confidence: Mapped[str] = mapped_column(String, nullable=False)
    endpoint: Mapped[str] = mapped_column(String, nullable=False)
    endpoint_class: Mapped[str | None] = mapped_column(String, nullable=True)
    asset_category: Mapped[str | None] = mapped_column(String, nullable=True)
    why_detected: Mapped[str | None] = mapped_column(Text, nullable=True)
    how_verified: Mapped[str | None] = mapped_column(String, nullable=True)
    severity_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    false_positive_reasons: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_verified: Mapped[bool] = mapped_column(default=False)
    verification_status: Mapped[str | None] = mapped_column(String, nullable=True)
    detection_method: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String, nullable=True)
    capec_id: Mapped[str | None] = mapped_column(String, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    matched_value: Mapped[str | None] = mapped_column(String, nullable=True)
    detection_rule: Mapped[str | None] = mapped_column(String, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_request: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String, nullable=True)
    raw_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    raw_risk: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON: RiskScore including risk_breakdown
    false_positive_probability: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
