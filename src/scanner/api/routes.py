from fastapi import APIRouter, Depends, HTTPException
from typing import List

from .schemas import HealthResponse, ReportGenerationRequest, ReportGenerationResponse, FindingListResponse
from ..di.containers import ApplicationContainer
from ..correlation.models import EnrichedFinding

router = APIRouter(prefix="/api/v1")

# In a real app, this would be a proper FastAPI dependency that yields the container.
# For simplicity, we'll instantiate it or assume it's injected.
def get_container() -> ApplicationContainer:
    from scanner.di.containers import ApplicationContainer
    import os
    config_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "config")
    container = ApplicationContainer(config_path=config_dir)
    container.init_resources()
    return container

# Since we don't have a database, we'll store findings in memory for the API layer to serve.
# Normally the `StateController` or a Repository would handle this.
# For demonstration of the REST API, we'll use a global list.
global_findings: List[EnrichedFinding] = []

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Returns the health status of the API."""
    return HealthResponse()

@router.get("/findings", response_model=FindingListResponse)
async def get_findings():
    """Retrieve all correlated and enriched security findings."""
    return FindingListResponse(findings=global_findings, count=len(global_findings))

@router.post("/reports", response_model=ReportGenerationResponse)
async def generate_reports(request: ReportGenerationRequest, container: ApplicationContainer = Depends(get_container)):
    """Triggers the report generation engine."""
    
    if not global_findings:
        raise HTTPException(status_code=400, detail="No findings available to report.")
        
    report_manager = container.report_manager()
    
    output_files = report_manager.generate_report(
        findings=global_findings,
        formats=request.formats,
        target_urls=request.target_urls
    )
    
    return ReportGenerationResponse(files=output_files)
