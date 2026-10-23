from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field


class ProxyConfiguration(BaseModel):
    """Proxy configuration."""
    url: str
    username: Optional[str] = None
    password: Optional[str] = None


class Cookie(BaseModel):
    """Domain model for a cookie."""
    name: str
    value: str
    domain: Optional[str] = None
    path: Optional[str] = "/"
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None
    max_age: Optional[int] = None
    expires: Optional[datetime] = None
    host_only: bool = True
    partitioned: bool = False


class HTTPRequest(BaseModel):
    """Standardized HTTP Request model."""
    method: str
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: List[Cookie] = Field(default_factory=list)
    body: Optional[Union[str, bytes, dict]] = None
    timeout: Optional[float] = None
    allow_redirects: bool = True
    proxy: Optional[ProxyConfiguration] = None


class HTTPResponse(BaseModel):
    """Standardized HTTP Response model."""
    status_code: int
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: List[Cookie] = Field(default_factory=list)
    body: bytes
    text: str
    request: HTTPRequest
    latency: float = 0.0


class AuthenticationContext(BaseModel):
    """Model for storing authentication state."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: Optional[str] = None
    tokens: Dict[str, str] = Field(default_factory=dict)
    cookies: List[Cookie] = Field(default_factory=list)
    is_authenticated: bool = False
    expires_at: Optional[datetime] = None
