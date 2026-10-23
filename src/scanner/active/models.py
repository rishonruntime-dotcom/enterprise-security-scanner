"""
Enterprise active scanner models.

Defines payloads, test cases, baselines, detection candidates,
and verification context used throughout the active scanning pipeline.
"""
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from ..network.models import HTTPRequest, HTTPResponse
from ..models.finding import Evidence


class PayloadTechnique(str, Enum):
    """Classification of injection technique."""
    ERROR_BASED = "error_based"
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"
    UNION_BASED = "union_based"
    REFLECTION = "reflection"
    CONTEXT_BREAKOUT = "context_breakout"
    FILE_READ = "file_read"
    PROTOCOL_ABUSE = "protocol_abuse"
    COMMAND_OUTPUT = "command_output"
    TEMPLATE_EVAL = "template_eval"
    ENTITY_EXPANSION = "entity_expansion"
    BLIND = "blind"


class PayloadEncoding(str, Enum):
    """Encoding applied to payload."""
    NONE = "none"
    URL = "url_encoded"
    DOUBLE_URL = "double_url_encoded"
    UNICODE = "unicode"
    HTML_ENTITY = "html_entity"
    BASE64 = "base64"
    MIXED = "mixed"


class Payload(BaseModel):
    """Represents a malicious or test payload to be injected."""
    value: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    technique: PayloadTechnique = Field(default=PayloadTechnique.ERROR_BASED)
    encoding: PayloadEncoding = Field(default=PayloadEncoding.NONE)
    category: str = Field(default="generic", description="Vulnerability category (sqli, xss, etc.)")
    expected_marker: Optional[str] = Field(None, description="Expected string in response if successful")
    expected_timing_delta: Optional[float] = Field(None, description="Expected timing delta in seconds for time-based")


class TestCase(BaseModel):
    """A specific HTTP request mutated with a payload."""
    request: HTTPRequest
    payload: Payload
    mutated_parameter: str = Field(..., description="The name of the parameter/field mutated")
    mutation_location: str = Field(default="query", description="Where mutation occurred: query, body, header, cookie, xml")
    original_value: Optional[str] = Field(None, description="Original parameter value before mutation")


class BaselineResult(BaseModel):
    """Stores baseline request/response data for differential analysis."""
    request: HTTPRequest
    response: Optional[HTTPResponse] = None
    status_code: int = 0
    body_length: int = 0
    body_hash: str = ""
    response_time_ms: float = 0.0
    headers: Dict[str, str] = Field(default_factory=dict)
    content_type: str = ""
    error: Optional[str] = None


class DetectionCandidate(BaseModel):
    """Raw detection signal before verification. Plugins emit these; the Verification Engine confirms them."""
    plugin_id: str
    vulnerability_type: str = Field(..., description="Type: sqli, xss, path_traversal, ssrf, cmdi, xxe, ssti")
    technique: PayloadTechnique
    endpoint: str
    parameter: str
    payload: Payload
    baseline: Optional[BaselineResult] = None
    fuzzed_request: Optional[HTTPRequest] = None
    fuzzed_response: Optional[HTTPResponse] = None
    fuzzed_timing_ms: float = 0.0
    detection_evidence: Dict[str, Any] = Field(default_factory=dict, description="Raw detection data")
    raw_request_str: Optional[str] = None
    raw_response_str: Optional[str] = None

    # For boolean-based: TRUE and FALSE responses
    true_response: Optional[HTTPResponse] = None
    false_response: Optional[HTTPResponse] = None
    true_timing_ms: float = 0.0
    false_timing_ms: float = 0.0

    # Additional evidence data
    matched_signature: Optional[str] = Field(None, description="Regex or string that matched")
    db_type: Optional[str] = Field(None, description="Database type detected (for SQLi)")
    reflection_context: Optional[str] = Field(None, description="Context where reflection occurs (for XSS)")
    file_marker: Optional[str] = Field(None, description="File content marker detected (for path traversal/XXE)")
    template_engine: Optional[str] = Field(None, description="Template engine detected (for SSTI)")


class VerificationContext(BaseModel):
    """Context passed between detection and verification phases."""
    scan_id: Optional[str] = None
    endpoint: str = ""
    candidates: List[DetectionCandidate] = Field(default_factory=list)
    waf_detected: bool = False
    waf_type: Optional[str] = None
    target_os: Optional[str] = Field(None, description="Detected OS: linux, windows, unknown")
    target_technologies: List[str] = Field(default_factory=list)


class DetectionResult(BaseModel):
    """The outcome of evaluating a TestCase."""
    is_vulnerable: bool
    evidence: Optional[Evidence] = None
    response: Optional[HTTPResponse] = None
