from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from typing import List
from pydantic import BaseModel, Field
from datetime import datetime
import json

from ...database.session import get_session
from ...database.models.finding import FindingORM
from ...repositories.finding_repo import SQLAlchemyFindingRepository
from ...management.analytics_service import AnalyticsService
from ...repositories.scan_repo import SQLAlchemyScanRepository
from ...risk.models import RiskBreakdown

router = APIRouter(prefix="/api/v1/findings", tags=["Findings"])


class FindingResponse(BaseModel):
    id: str
    scan_id: str | None
    plugin_id: str
    title: str
    description: str
    severity: str
    original_severity: str | None = None
    confidence: str
    endpoint: str
    endpoint_class: str | None = None
    affected_endpoints: List[str] = Field(default_factory=list)
    cwe_id: str | None
    cvss_score: float | None
    priority_score: float | None
    is_verified: bool
    epss_score: float | None = None
    owasp_category: str | None = None
    raw_evidence: str | None = None
    created_at: datetime

    likelihood: float | None = None
    impact: float | None = None
    exploitability: float | None = None
    confidence_score: float | None = None
    risk_score: float | None = None
    risk_breakdown: RiskBreakdown | None = None
    false_positive_probability: float | None = None

    model_config = {"from_attributes": True}


# Injected via app state
def get_session_factory(session_factory: async_sessionmaker = None):
    from ...api.app import get_session_factory as _get
    return _get()


@router.get("", response_model=dict)
async def list_findings(skip: int = 0, limit: int = 100):
    from ...api.app import get_db_session_factory
    factory = get_db_session_factory()
    async with factory() as session:
        repo = SQLAlchemyFindingRepository(session)
        findings = await repo.get_all(skip=skip, limit=limit)
        count = await repo.count()
    response_findings = []
    for finding in findings:
        response = FindingResponse.model_validate(finding)
        try:
            raw_evidence = json.loads(finding.raw_evidence) if finding.raw_evidence else {}
            response.affected_endpoints = raw_evidence.get("affected_endpoints", [])
        except (TypeError, json.JSONDecodeError):
            pass

        raw_risk = json.loads(finding.raw_risk) if finding.raw_risk else None
        if raw_risk:
            response.likelihood = raw_risk.get("risk_breakdown", {}).get("likelihood") if isinstance(raw_risk.get("risk_breakdown"), dict) else None
            response.impact = raw_risk.get("risk_breakdown", {}).get("impact") if isinstance(raw_risk.get("risk_breakdown"), dict) else None
            response.exploitability = raw_risk.get("risk_breakdown", {}).get("exploitability") if isinstance(raw_risk.get("risk_breakdown"), dict) else None
            response.risk_score = raw_risk.get("final_priority")
            breakdown = raw_risk.get("risk_breakdown")
            if isinstance(breakdown, dict):
                response.risk_breakdown = RiskBreakdown(**breakdown)

        response_findings.append(response)
    return {
        "findings": response_findings,
        "count": count,
    }
