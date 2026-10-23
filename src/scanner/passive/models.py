from typing import List, Optional, Any
from pydantic import BaseModel, Field
from ..models.finding import Evidence

class PluginMetadata(BaseModel):
    """Metadata describing a passive security plugin."""
    id: str = Field(..., description="Unique identifier (e.g., 'PASS-001')")
    name: str = Field(..., description="Human readable name")
    description: str = Field(..., description="Description of the security checks performed")
    version: str = Field(default="1.0.0")
    author: str = Field(default="Scanner Team")

class PassiveObservation(BaseModel):
    """Raw observation signal detected passively."""
    plugin_id: str
    observation_type: str = Field(..., description="Type of passive observation (e.g. cookie_flag, missing_header)")
    title: str
    description: str
    endpoint: str
    severity: Optional[Any] = None
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    owasp_category: Optional[str] = None
    capec_id: Optional[str] = None
    evidence: List[Evidence] = Field(default_factory=list)
    remediation: Optional[str] = None
    proxy_type: Optional[str] = Field(None, description="Detected reverse proxy type (e.g. nginx, apache, cloudflare)")
    cdn_provider: Optional[str] = Field(None, description="Detected CDN provider (e.g. cloudflare, akamai)")
    hsts_preload: Optional[bool] = Field(None, description="Whether HSTS preload directive is present")
    redirect_observed: Optional[bool] = Field(None, description="Whether an HTTP->HTTPS redirect was observed")
    browser_defaults_applicable: Optional[bool] = Field(None, description="Whether browser default security behaviors apply")
    csp_protections_present: Optional[List[str]] = Field(None, description="List of CSP protections detected in policy")
    cookie_type: Optional[str] = Field(None, description="Cookie type classification (session, authentication, oauth, analytics, third_party, functional, unknown)")
    cookie_role: Optional[str] = Field(None, description="Cookie role classification (authentication/session, analytics, client-readable, application)")
    cookie_first_party: Optional[bool] = Field(None, description="Whether cookie is first-party")
    cookie_persistent: Optional[bool] = Field(None, description="Whether cookie is persistent")
    cookie_same_site: Optional[str] = Field(None, description="Cookie SameSite attribute value")
    cookie_security_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="Cookie security configuration score 0.0-1.0")
    cookie_has_host_prefix: Optional[bool] = Field(None, description="Whether cookie uses __Host- prefix")
    cookie_has_secure_prefix: Optional[bool] = Field(None, description="Whether cookie uses __Secure- prefix")
    cookie_is_third_party: Optional[bool] = Field(None, description="Whether cookie is third-party")

