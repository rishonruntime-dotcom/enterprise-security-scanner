from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from enum import Enum


class TechnologyCategory(str, Enum):
    WEB_SERVER = "Web Server"
    CDN = "CDN & Proxy"
    CLOUD = "Cloud Platform"
    CMS = "CMS"
    FRAMEWORK = "Web Framework"
    JS_FRAMEWORK = "JavaScript Framework"
    JS_LIBRARY = "JavaScript Library"
    TEMPLATE = "Template Engine"
    LANGUAGE = "Programming Language"
    DATABASE = "Database"
    ANALYTICS = "Analytics"
    PROTOCOL = "Protocol & Encoding"
    FEATURE = "Web Feature & API"
    API = "API"
    SECURITY = "Security"
    VIDEO = "Video Platform"
    UNKNOWN = "Unknown"


class Fingerprint(BaseModel):
    """A matched signature rule."""
    name: str
    category: TechnologyCategory
    confidence: int = Field(default=0, ge=0, le=100)
    version: Optional[str] = None
    website: Optional[str] = None


class Technology(BaseModel):
    """Represents a specific detected technology."""
    name: str
    category: TechnologyCategory
    confidence: int = Field(default=0, ge=0, le=100)
    versions: List[str] = Field(default_factory=list)
    website: Optional[str] = None
    icon: Optional[str] = None


class TechnologyProfile(BaseModel):
    """Aggregated fingerprint intelligence for a target."""
    technologies: List[Technology] = Field(default_factory=list)
    
    def add_fingerprint(self, fp: Fingerprint):
        """Merge a fingerprint into the profile."""
        existing = next((t for t in self.technologies if t.name == fp.name), None)
        if existing:
            # Update confidence (keep highest)
            existing.confidence = max(existing.confidence, fp.confidence)
            # Add version if new
            if fp.version and fp.version not in existing.versions:
                existing.versions.append(fp.version)
        else:
            tech = Technology(
                name=fp.name,
                category=fp.category,
                confidence=fp.confidence,
                versions=[fp.version] if fp.version else [],
                website=fp.website
            )
            self.technologies.append(tech)


class DetectionRule(BaseModel):
    """A signature pattern used for matching."""
    name: str
    category: str
    website: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    meta: Dict[str, str] = Field(default_factory=dict)
    html: List[str] = Field(default_factory=list)
    script_src: List[str] = Field(default_factory=list)
    implies: List[str] = Field(default_factory=list)
