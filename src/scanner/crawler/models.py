from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


class Endpoint(BaseModel):
    """Represents a discovered URL endpoint."""
    method: str = "GET"
    url: str
    source_url: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    endpoint_class: str = "Main Application"
    classification_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    classification_reason: Optional[str] = None
    asset_category: str = Field(default="First-party")
    asset_category_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    asset_category_reason: Optional[str] = None

    @model_validator(mode="after")
    def assign_endpoint_classification(self) -> "Endpoint":
        """Classify every discovered endpoint once, close to its source."""
        from ..classification.classifier import EndpointClassifier, AssetClassifier

        classified = EndpointClassifier.classify_endpoint(self.url, self.method, self.parameters)
        self.endpoint_class = classified.endpoint_class.value
        self.classification_confidence = classified.confidence
        self.classification_reason = classified.reason

        asset_classified = AssetClassifier.classify(self.url)
        self.asset_category = asset_classified.asset_category.value
        self.asset_category_confidence = asset_classified.confidence
        self.asset_category_reason = asset_classified.reason
        return self


class Form(BaseModel):
    """Represents an HTML form discovered."""
    action: str
    method: str
    inputs: List[Dict[str, str]] = Field(default_factory=list)
    source_url: str


class Asset(BaseModel):
    """Represents a static resource (e.g. JS, CSS)."""
    url: str
    type: str  # e.g., 'script', 'stylesheet', 'image'
    source_url: str


class CrawlSession(BaseModel):
    """Holds state for an active crawl."""
    scan_id: str
    allowed_domains: List[str] = Field(default_factory=list)
    max_depth: int = 3
    max_urls: int = 1000
    use_browser: bool = False
    session_cookies: Dict[str, str] = Field(default_factory=dict)
    local_storage: Dict[str, str] = Field(default_factory=dict)
    custom_headers: Dict[str, str] = Field(default_factory=dict)


class CrawlResult(BaseModel):
    """Stores total discovered items from a crawl."""
    endpoints: List[Endpoint] = Field(default_factory=list)
    forms: List[Form] = Field(default_factory=list)
    assets: List[Asset] = Field(default_factory=list)
    disallowed_paths: List[str] = Field(default_factory=list)
    websocket_urls: List[str] = Field(default_factory=list)
    spa_routes: List[str] = Field(default_factory=list)
    openapi_specs: List[str] = Field(default_factory=list)
    manifest_urls: List[str] = Field(default_factory=list)
    service_worker_urls: List[str] = Field(default_factory=list)
    assets_skipped: int = 0
    third_party_assets: int = 0
    javascript_files_analyzed: int = 0
