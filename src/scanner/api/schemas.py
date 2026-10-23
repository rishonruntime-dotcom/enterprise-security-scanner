from typing import List, Dict, Optional
from pydantic import BaseModel, Field

from ..correlation.models import EnrichedFinding

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "2.4.0-enterprise"
    
class ReportGenerationRequest(BaseModel):
    formats: List[str] = Field(default=["json", "md"], description="List of formats to export (json, md, sarif)")
    target_urls: List[str] = Field(default=[], description="List of URLs to include in the metadata")
    
class ReportGenerationResponse(BaseModel):
    message: str = "Reports generated successfully"
    files: Dict[str, str] = Field(description="Map of format to generated file path")

class FindingListResponse(BaseModel):
    findings: List[EnrichedFinding]
    count: int
