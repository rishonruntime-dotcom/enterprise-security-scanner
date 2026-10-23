"""
Enterprise Evidence Collector.

Captures and normalizes all evidence artifacts from detection and verification:
raw HTTP request/response, headers, cookies, timing, diffs, hashes, and reproduction steps.
"""
import hashlib
import difflib
import time
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse, urlencode

import structlog

from ..models.finding import Evidence
from ..network.models import HTTPRequest, HTTPResponse

logger = structlog.get_logger(__name__)


class EvidenceCollector:
    """Collects, normalizes, and stores evidence from HTTP interactions."""

    @staticmethod
    def format_raw_request(request: HTTPRequest) -> str:
        """Format an HTTPRequest into a raw HTTP request string."""
        parsed = urlparse(request.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = [f"{request.method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")

        for key, value in request.headers.items():
            lines.append(f"{key}: {value}")

        if request.cookies:
            cookie_str = "; ".join(f"{c.name}={c.value}" for c in request.cookies)
            lines.append(f"Cookie: {cookie_str}")

        lines.append("")  # blank line before body

        if request.body:
            if isinstance(request.body, dict):
                import json
                lines.append(json.dumps(request.body))
            elif isinstance(request.body, bytes):
                lines.append(request.body.decode("utf-8", errors="replace"))
            else:
                lines.append(str(request.body))

        return "\r\n".join(lines)

    @staticmethod
    def format_raw_response(response: HTTPResponse, max_body: int = 10240) -> str:
        """Format an HTTPResponse into a raw HTTP response string (truncated body)."""
        lines = [f"HTTP/1.1 {response.status_code}"]

        for key, value in response.headers.items():
            lines.append(f"{key}: {value}")

        lines.append("")  # blank line before body

        body_text = response.text or ""
        if len(body_text) > max_body:
            body_text = body_text[:max_body] + f"\n\n[...truncated, total {len(response.text)} bytes...]"
        lines.append(body_text)

        return "\r\n".join(lines)

    @staticmethod
    def compute_response_hash(response: HTTPResponse) -> str:
        """Compute SHA-256 hash of response body."""
        body = response.body if isinstance(response.body, bytes) else response.text.encode("utf-8", errors="replace")
        return hashlib.sha256(body).hexdigest()

    @staticmethod
    def compute_body_similarity(text_a: str, text_b: str) -> float:
        """Compute similarity ratio between two response bodies using SequenceMatcher."""
        if not text_a and not text_b:
            return 1.0
        if not text_a or not text_b:
            return 0.0
        return difflib.SequenceMatcher(None, text_a, text_b).ratio()

    @staticmethod
    def compute_diff(baseline_text: str, fuzzed_text: str, context_lines: int = 3) -> str:
        """Compute unified diff between baseline and fuzzed response bodies."""
        baseline_lines = baseline_text.splitlines(keepends=True)
        fuzzed_lines = fuzzed_text.splitlines(keepends=True)

        diff = difflib.unified_diff(
            baseline_lines, fuzzed_lines,
            fromfile="baseline_response",
            tofile="fuzzed_response",
            n=context_lines
        )
        result = "".join(list(diff)[:200])  # Cap diff output
        return result if result else "(no differences)"

    @staticmethod
    def generate_curl_command(request: HTTPRequest) -> str:
        """Generate a curl command that reproduces the HTTP request."""
        parts = ["curl", "-v"]

        if request.method != "GET":
            parts.extend(["-X", request.method])

        for key, value in request.headers.items():
            parts.extend(["-H", f"'{key}: {value}'"])

        if request.cookies:
            cookie_str = "; ".join(f"{c.name}={c.value}" for c in request.cookies)
            parts.extend(["--cookie", f"'{cookie_str}'"])

        if request.body:
            if isinstance(request.body, dict):
                import json
                parts.extend(["-d", f"'{json.dumps(request.body)}'"])
            elif isinstance(request.body, bytes):
                parts.extend(["--data-binary", f"'{request.body.decode('utf-8', errors='replace')}'"])
            else:
                parts.extend(["-d", f"'{request.body}'"])

        parts.append(f"'{request.url}'")
        return " ".join(parts)

    @classmethod
    def build_evidence(
        cls,
        evidence_type: str,
        description: str,
        data: Any,
        request: Optional[HTTPRequest] = None,
        response: Optional[HTTPResponse] = None,
        baseline_response: Optional[HTTPResponse] = None,
        timing_ms: Optional[float] = None,
        baseline_timing_ms: Optional[float] = None,
        dom_snapshot: Optional[str] = None,
        screenshot_path: Optional[str] = None,
    ) -> Evidence:
        """Build a complete Evidence object with all available data."""
        raw_request = cls.format_raw_request(request) if request else None
        raw_response = cls.format_raw_response(response) if response else None
        response_hash = cls.compute_response_hash(response) if response else None

        diff = None
        if baseline_response and response:
            baseline_text = baseline_response.text or ""
            fuzzed_text = response.text or ""
            diff = cls.compute_diff(baseline_text, fuzzed_text)

        reproduction_steps = []
        if request:
            reproduction_steps.append(cls.generate_curl_command(request))

        request_headers = dict(request.headers) if request else None
        response_headers = dict(response.headers) if response else None
        cookies = None
        if response and response.cookies:
            cookies = {c.name: c.value for c in response.cookies}

        return Evidence(
            type=evidence_type,
            description=description,
            data=data,
            raw_request=raw_request,
            raw_response=raw_response,
            request_headers=request_headers,
            response_headers=response_headers,
            cookies=cookies,
            dom_snapshot=dom_snapshot[:5000] if dom_snapshot else None,
            screenshot_path=screenshot_path,
            timing_ms=timing_ms,
            baseline_timing_ms=baseline_timing_ms,
            diff=diff,
            response_hash=response_hash,
            reproduction_steps=reproduction_steps,
        )

    @classmethod
    def build_reproduction_steps(cls, steps: List[Dict[str, Any]]) -> List[str]:
        """Build human-readable reproduction steps from structured step data."""
        result = []
        for i, step in enumerate(steps, 1):
            action = step.get("action", "Send request")
            url = step.get("url", "")
            method = step.get("method", "GET")
            payload = step.get("payload", "")
            expected = step.get("expected", "")

            line = f"Step {i}: {action}"
            if url:
                line += f" to {url}"
            if method != "GET":
                line += f" using {method}"
            if payload:
                line += f" with payload: {payload}"
            if expected:
                line += f" — Expected: {expected}"
            result.append(line)

        return result
