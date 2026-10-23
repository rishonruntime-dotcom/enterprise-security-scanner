"""
Central Finding Evaluation Engine.

Provides a single authoritative location for converting raw plugin outputs
into standardized Finding objects.  All plugins emit lightweight raw evidence;
the evaluator handles normalization, intelligence mapping, evidence enrichment,
and Finding construction.

Architecture:
  Plugin (passive/active)
      ↓
  RawEvidence  ← unified normalization layer
      ↓
  CentralFindingEvaluator  ← single place for detection quality
      ↓
  Finding  ← standardized, fully-formed finding
      ↓
  Correlation / Mitigation / Confidence / Severity / FP Reduction
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import structlog

from ..models.finding import (
    Finding,
    Evidence,
    Severity,
    Confidence,
    DetectionMethod,
    VerificationStatus,
)
from ..passive.models import PassiveObservation, PluginMetadata
from ..active.models import DetectionCandidate, PayloadTechnique
from ..network.models import HTTPResponse
from ..network.exposure.models import ExposedServiceFinding

logger = structlog.get_logger(__name__)


# ── Unified Raw Evidence Model ────────────────────────────────────────────────

class EvidenceSource(str, Enum):
    """Origin of the raw evidence."""
    PASSIVE_PLUGIN = "passive_plugin"
    ACTIVE_PLUGIN = "active_plugin"
    CORRELATION = "correlation"
    MANUAL = "manual"


@dataclass
class RawEvidence:
    """Normalized raw evidence from any plugin type.

    This is the single input format for the Central Finding Evaluator.
    Both passive and active plugins produce (or are adapted into) this model.
    """
    source: EvidenceSource
    plugin_id: str
    plugin_name: str
    vulnerability_type: str  # e.g. "missing_header", "xss", "sqli", "ssrf"
    endpoint: str
    method: str = "GET"
    parameter: Optional[str] = None
    payload: Optional[str] = None
    technique: Optional[str] = None  # PayloadTechnique value for active

    # Raw detection data
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None
    raw_response_headers: Dict[str, str] = field(default_factory=dict)
    raw_request_headers: Dict[str, str] = field(default_factory=dict)
    response_status: int = 0
    response_time_ms: float = 0.0
    baseline_response_time_ms: float = 0.0

    # Detection signals
    matched_signature: Optional[str] = None
    matched_value: Optional[str] = None
    diff: Optional[str] = None
    reflection_context: Optional[str] = None
    file_marker: Optional[str] = None
    db_type: Optional[str] = None
    template_engine: Optional[str] = None

    # Additional context
    detection_evidence: Dict[str, Any] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    meta_tags: Dict[str, str] = field(default_factory=dict)
    script_sources: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)

    # Original plugin output (preserved for audit)
    original_observation: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.value,
            "plugin_id": self.plugin_id,
            "plugin_name": self.plugin_name,
            "vulnerability_type": self.vulnerability_type,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "technique": self.technique,
            "raw_request": self.raw_request,
            "raw_response": self.raw_response,
            "response_status": self.response_status,
            "response_time_ms": self.response_time_ms,
            "matched_signature": self.matched_signature,
            "matched_value": self.matched_value,
            "detection_evidence": self.detection_evidence,
        }


# ── Central Finding Evaluator ─────────────────────────────────────────────────

class CentralFindingEvaluator:
    """Single authoritative evaluator for all raw plugin evidence.

    Responsibilities:
    1. Normalize plugin outputs into RawEvidence
    2. Evaluate evidence quality and completeness
    3. Map to standardized CWE/OWASP/CAPEC intelligence
    4. Construct Finding objects with proper Evidence
    5. Assign initial severity, confidence, and detection method
    6. Produce explainability metadata (why_detected, how_verified)

    This is the ONLY place where Finding objects should be constructed from
    plugin output.  All other components (correlation, risk, severity, etc.)
    operate on the Finding objects produced here.
    """

    def __init__(self, intelligence_mapper: Optional[Any] = None):
        self.intelligence_mapper = intelligence_mapper

    def evaluate(self, raw: RawEvidence) -> Optional[Finding]:
        """Evaluate raw evidence and return a standardized Finding, or None if dropped."""
        try:
            intelligence = self._map_intelligence(raw)
            evidence = self._build_evidence(raw)
            severity = self._initial_severity(raw)
            confidence = self._initial_confidence(raw)
            detection_method = self._detection_method(raw)
            verification_status = self._initial_verification_status(raw)

            finding = Finding(
                plugin_id=raw.plugin_id,
                title=self._build_title(raw),
                description=self._build_description(raw, intelligence),
                severity=severity,
                original_severity=severity,
                confidence=confidence,
                endpoint=raw.endpoint,
                evidence=[evidence] if evidence else [],
                remediation=self._remediation(raw, intelligence),
                references=intelligence.get("references", []),
                detection_method=detection_method,
                verification_status=verification_status,
                confidence_score=self._confidence_score(raw),
                owasp_category=intelligence.get("owasp_category"),
                cwe_id=intelligence.get("cwe_id"),
                capec_id=intelligence.get("capec_id"),
                cvss_vector=intelligence.get("cvss_vector"),
                attack_payload=raw.payload,
                affected_parameter=raw.parameter,
                http_request=raw.raw_request,
                http_response=raw.raw_response,
                why_detected=self._why_detected(raw),
                how_verified=self._how_verified(raw),
                severity_reason=self._severity_reason(raw, severity),
                false_positive_reasons=self._false_positive_reasons(raw),
                reproduction_steps=self._reproduction_steps(raw),
            )
            return finding
        except Exception as e:
            logger.error("Failed to evaluate raw evidence", plugin_id=raw.plugin_id, error=str(e))
            return None

    # ── Adapters ──────────────────────────────────────────────────────────────

    @staticmethod
    def from_passive_observation(obs: PassiveObservation) -> RawEvidence:
        """Adapt a PassiveObservation into RawEvidence."""
        raw_resp = ""
        raw_req = ""
        resp_headers: Dict[str, str] = {}
        req_headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        status = 0
        time_ms = 0.0

        if obs.evidence:
            first_ev = obs.evidence[0]
            raw_resp = getattr(first_ev, "raw_response", "") or ""
            raw_req = getattr(first_ev, "raw_request", "") or ""
            resp_headers = getattr(first_ev, "response_headers", {}) or {}
            req_headers = getattr(first_ev, "request_headers", {}) or {}
            cookies = getattr(first_ev, "cookies", {}) or {}
            time_ms = getattr(first_ev, "timing_ms", 0.0) or 0.0

        return RawEvidence(
            source=EvidenceSource.PASSIVE_PLUGIN,
            plugin_id=obs.plugin_id,
            plugin_name=obs.title,
            vulnerability_type=obs.observation_type or obs.plugin_id,
            endpoint=obs.endpoint,
            raw_request=raw_req,
            raw_response=raw_resp,
            raw_response_headers=resp_headers,
            raw_request_headers=req_headers,
            response_status=status,
            response_time_ms=time_ms,
            matched_value=getattr(obs.evidence[0] if obs.evidence else None, "matched_value", None),
            cookies=cookies,
            detection_evidence={"observation": obs.model_dump() if hasattr(obs, "model_dump") else obs.__dict__},
            original_observation=obs,
        )

    @staticmethod
    def from_detection_candidate(candidate: DetectionCandidate) -> RawEvidence:
        """Adapt a DetectionCandidate into RawEvidence."""
        raw_req = candidate.raw_request_str or ""
        raw_resp = candidate.raw_response_str or ""
        resp_headers: Dict[str, str] = {}
        req_headers: Dict[str, str] = {}
        status = 0
        time_ms = candidate.fuzzed_timing_ms or 0.0
        baseline_time = candidate.baseline.response_time_ms if candidate.baseline else 0.0

        if candidate.fuzzed_response:
            resp_headers = {k.lower(): str(v) for k, v in candidate.fuzzed_response.headers.items()}
            status = candidate.fuzzed_response.status_code
            if not raw_resp:
                raw_resp = getattr(candidate.fuzzed_response, "text", "") or ""
        if candidate.fuzzed_request:
            req_headers = {k.lower(): str(v) for k, v in candidate.fuzzed_request.headers.items()}
            if not raw_req:
                raw_req = str(candidate.fuzzed_request)
        if candidate.baseline and candidate.baseline.response:
            resp_headers = {k.lower(): str(v) for k, v in candidate.baseline.response.headers.items()}
            if not raw_resp:
                raw_resp = getattr(candidate.baseline.response, "text", "") or ""

        return RawEvidence(
            source=EvidenceSource.ACTIVE_PLUGIN,
            plugin_id=candidate.plugin_id,
            plugin_name=candidate.plugin_id,
            vulnerability_type=candidate.vulnerability_type,
            endpoint=candidate.endpoint,
            method=getattr(candidate.fuzzed_request, "method", "GET") if candidate.fuzzed_request else "GET",
            parameter=candidate.parameter,
            payload=candidate.payload.value if candidate.payload else None,
            technique=candidate.technique.value if candidate.technique else None,
            raw_request=raw_req,
            raw_response=raw_resp,
            raw_response_headers=resp_headers,
            raw_request_headers=req_headers,
            response_status=status,
            response_time_ms=time_ms,
            baseline_response_time_ms=baseline_time,
            matched_signature=candidate.matched_signature,
            matched_value=candidate.matched_signature,
            reflection_context=candidate.reflection_context,
            file_marker=candidate.file_marker,
            db_type=candidate.db_type,
            template_engine=candidate.template_engine,
            detection_evidence=candidate.detection_evidence or {},
            original_observation=candidate,
        )

    # ── Evaluation Helpers ────────────────────────────────────────────────────

    def _map_intelligence(self, raw: RawEvidence) -> Dict[str, Any]:
        intelligence: Dict[str, Any] = {}
        vuln_type = (raw.vulnerability_type or "").lower()

        mapping = self._get_mapping(raw.plugin_id, vuln_type)
        intelligence.update(mapping)

        if raw.db_type and "sql" in vuln_type:
            intelligence["db_type"] = raw.db_type
        if raw.template_engine and "ssti" in vuln_type:
            intelligence["template_engine"] = raw.template_engine

        return intelligence

    def _get_mapping(self, plugin_id: str, vuln_type: str) -> Dict[str, Any]:
        mappings = {
            "PASS-001": {"cwe_id": "CWE-693", "owasp_category": "A05:2021-Security Misconfiguration", "capec_id": "CAPEC-34"},
            "PASS-001-CSP-": {"cwe_id": "CWE-79", "owasp_category": "A03:2021-Injection", "capec_id": "CAPEC-63"},
            "PASS-002": {"cwe_id": "CWE-614", "owasp_category": "A05:2021-Security Misconfiguration", "capec_id": "CAPEC-35"},
            "PASS-003": {"cwe_id": "CWE-200", "owasp_category": "A01:2021-Broken Access Control", "capec_id": "CAPEC-37"},
            "PASS-004": {"cwe_id": "CWE-1104", "owasp_category": "A06:2021-Vulnerable and Outdated Components", "capec_id": "CAPEC-29"},
            "PASS-005": {"cwe_id": "CWE-352", "owasp_category": "A01:2021-Broken Access Control", "capec_id": "CAPEC-62"},
            "PASS-006": {"cwe_id": "CWE-79", "owasp_category": "A03:2021-Injection", "capec_id": "CAPEC-63"},
            "ACT-XSS-001": {"cwe_id": "CWE-79", "owasp_category": "A03:2021-Injection", "capec_id": "CAPEC-63"},
            "ACT-SQLI-001": {"cwe_id": "CWE-89", "owasp_category": "A03:2021-Injection", "capec_id": "CAPEC-66"},
            "ACT-TRAV-001": {"cwe_id": "CWE-22", "owasp_category": "A01:2021-Broken Access Control", "capec_id": "CAPEC-37"},
            "ACT-SSRF-001": {"cwe_id": "CWE-918", "owasp_category": "A10:2021-Server-Side Request Forgery", "capec_id": "CAPEC-115"},
            "ACT-CMDI-001": {"cwe_id": "CWE-78", "owasp_category": "A03:2021-Injection", "capec_id": "CAPEC-88"},
            "ACT-XXE-001": {"cwe_id": "CWE-611", "owasp_category": "A03:2021-Injection", "capec_id": "CAPEC-165"},
            "ACT-SSTI-001": {"cwe_id": "CWE-94", "owasp_category": "A03:2021-Injection", "capec_id": "CAPEC-86"},
            "ACT-REDIR-001": {"cwe_id": "CWE-601", "owasp_category": "A01:2021-Broken Access Control", "capec_id": "CAPEC-31"},
        }
        return mappings.get(plugin_id, {})

    def _build_evidence(self, raw: RawEvidence) -> Evidence:
        evidence_type = raw.vulnerability_type or raw.observation_type or "generic"
        description = self._build_title(raw)
        data = raw.to_dict()

        # Remove severity from embedded observation data to prevent inconsistency
        # between the evidence's original severity and the finding's adjusted severity.
        detection_ev = data.get("detection_evidence")
        if isinstance(detection_ev, dict):
            obs = detection_ev.get("observation")
            if isinstance(obs, dict):
                obs.pop("severity", None)
                obs.pop("confidence", None)

        return Evidence(
            type=evidence_type,
            description=description,
            data=data,
            matched_value=raw.matched_value,
            detection_rule=raw.matched_signature,
            detection_method=raw.source.value,
            reason=raw.detection_evidence.get("reason"),
            raw_request=raw.raw_request,
            raw_response=raw.raw_response,
            request_headers=raw.raw_request_headers,
            response_headers=raw.raw_response_headers,
            cookies=raw.cookies,
            timing_ms=raw.response_time_ms,
            baseline_timing_ms=raw.baseline_response_time_ms,
            diff=raw.diff,
            reproduction_steps=self._reproduction_steps(raw),
        )

    def _build_title(self, raw: RawEvidence) -> str:
        if raw.plugin_name and raw.plugin_name != raw.plugin_id:
            return raw.plugin_name
        vuln = raw.vulnerability_type.replace("_", " ").title()
        return f"{raw.plugin_id}: {vuln}"

    def _build_description(self, raw: RawEvidence, intelligence: Dict[str, Any]) -> str:
        parts = []
        if raw.source == EvidenceSource.ACTIVE_PLUGIN:
            parts.append(f"Active detection using {raw.technique or 'unknown'} technique.")
        elif raw.source == EvidenceSource.PASSIVE_PLUGIN:
            parts.append("Passive observation from response analysis.")

        if raw.parameter:
            parts.append(f"Affected parameter: {raw.parameter}.")
        if raw.payload:
            parts.append(f"Payload: {raw.payload}.")
        if raw.matched_signature:
            parts.append(f"Matched signature: {raw.matched_signature}.")
        if raw.reflection_context:
            parts.append(f"Reflection context: {raw.reflection_context}.")
        if raw.file_marker:
            parts.append(f"File marker detected: {raw.file_marker}.")
        if raw.db_type:
            parts.append(f"Database type: {raw.db_type}.")
        if raw.template_engine:
            parts.append(f"Template engine: {raw.template_engine}.")

        cwe = intelligence.get("cwe_id")
        if cwe:
            parts.append(f"Mapped to {cwe}.")

        return " ".join(parts) if parts else f"Detection from {raw.plugin_id}."

    def _remediation(self, raw: RawEvidence, intelligence: Dict[str, Any]) -> str:
        remediations = {
            "missing_header": "Add the missing security header to server responses.",
            "cookie": "Set the Secure and HttpOnly flags on sensitive cookies.",
            "xss": "Implement output encoding and input validation. Deploy a restrictive Content-Security-Policy.",
            "sqli": "Use parameterized queries or ORM. Never concatenate user input into SQL strings.",
            "path_traversal": "Validate and sanitize file paths. Use allowlists for file access.",
            "ssrf": "Validate and allowlist URLs. Block internal/reserved IP ranges.",
            "cmdi": "Avoid shell execution with user input. Use allowlists for commands.",
            "xxe": "Disable external entity processing in XML parsers.",
            "ssti": "Use auto-escaping template engines. Avoid user-controlled template strings.",
            "open_redirect": "Validate redirect URLs against an allowlist. Avoid user-controlled redirects.",
            "csp": "Strengthen Content-Security-Policy to restrict inline scripts and eval.",
            "info_disclosure": "Remove sensitive information from responses.",
            "outdated": "Update the affected component to the latest stable version.",
        }
        vuln = raw.vulnerability_type.lower()
        for key, remedy in remediations.items():
            if key in vuln:
                return remedy
        return "Review and remediate according to security best practices."

    def _reproduction_steps(self, raw: RawEvidence) -> List[str]:
        steps = [f"1. Navigate to: {raw.endpoint}"]
        if raw.parameter:
            steps.append(f"2. Inject payload into parameter '{raw.parameter}'.")
        if raw.payload:
            steps.append(f"3. Payload: {raw.payload}")
        if raw.raw_request:
            steps.append(f"4. Request:\n{raw.raw_request}")
        if raw.raw_response:
            steps.append(f"5. Response:\n{raw.raw_response}")
        return steps

    def _initial_severity(self, raw: RawEvidence) -> Severity:
        passive_severity = {
            "missing_header": Severity.LOW,
            "cookie": Severity.LOW,
            "csp": Severity.MEDIUM,
            "info_disclosure": Severity.MEDIUM,
            "outdated": Severity.MEDIUM,
            "form_security": Severity.MEDIUM,
        }
        active_severity = {
            "xss": Severity.HIGH,
            "sqli": Severity.CRITICAL,
            "path_traversal": Severity.HIGH,
            "ssrf": Severity.HIGH,
            "cmdi": Severity.HIGH,
            "xxe": Severity.HIGH,
            "ssti": Severity.HIGH,
            "open_redirect": Severity.MEDIUM,
        }
        vuln = raw.vulnerability_type.lower()
        if raw.source == EvidenceSource.PASSIVE_PLUGIN:
            for key, sev in passive_severity.items():
                if key in vuln:
                    return sev
            return Severity.INFO
        else:
            for key, sev in active_severity.items():
                if key in vuln:
                    return sev
            return Severity.MEDIUM

    def _initial_confidence(self, raw: RawEvidence) -> Confidence:
        from .confidence import DynamicConfidenceEngine
        score = self._confidence_score(raw)
        return DynamicConfidenceEngine._score_to_confidence(score)

    def _confidence_score(self, raw: RawEvidence) -> float:
        score = 0.0
        if raw.raw_request:
            score += 0.2
        if raw.raw_response:
            score += 0.2
        if raw.matched_signature:
            score += 0.2
        if raw.matched_value:
            score += 0.15
        if raw.raw_response_headers:
            score += 0.1
        if raw.cookies:
            score += 0.05
        if raw.technique:
            score += 0.1
        # Active findings with both request and response get a boost
        if raw.source == EvidenceSource.ACTIVE_PLUGIN and raw.raw_request and raw.raw_response:
            score += 0.05
        return min(1.0, score)

    def _detection_method(self, raw: RawEvidence) -> DetectionMethod:
        return DetectionMethod.ACTIVE if raw.source == EvidenceSource.ACTIVE_PLUGIN else DetectionMethod.PASSIVE

    def _initial_verification_status(self, raw: RawEvidence) -> VerificationStatus:
        return VerificationStatus.NOT_ACTIVELY_VERIFIED

    def _why_detected(self, raw: RawEvidence) -> str:
        parts = [f"{raw.plugin_name} detected {raw.vulnerability_type}"]
        if raw.matched_signature:
            parts.append(f"via signature: {raw.matched_signature}")
        if raw.parameter:
            parts.append(f"in parameter '{raw.parameter}'")
        parts.append(f"at {raw.endpoint}")
        return " ".join(parts)

    def _how_verified(self, raw: RawEvidence) -> str:
        if raw.source == EvidenceSource.ACTIVE_PLUGIN:
            if raw.raw_request and raw.raw_response:
                return f"Active detection using {raw.technique or 'unknown'} technique. Verified with request/response evidence."
            return f"Active detection using {raw.technique or 'unknown'} technique. Verification pending."
        return "Passive observation from response headers/cookies/body."

    def _severity_reason(self, raw: RawEvidence, severity: Severity) -> str:
        return f"Initial severity {severity.value} assigned based on {raw.source.value} detection of {raw.vulnerability_type}."

    def _false_positive_reasons(self, raw: RawEvidence) -> List[str]:
        reasons = []
        if raw.source == EvidenceSource.PASSIVE_PLUGIN:
            reasons.append("Passive observations may be affected by CDN/reverse-proxy behavior.")
        if not raw.raw_response:
            reasons.append("No response body captured for validation.")
        if raw.response_status and raw.response_status >= 300:
            reasons.append(f"HTTP {raw.response_status} response may indicate redirect or error.")
        return reasons


# ── Pipeline Step ─────────────────────────────────────────────────────────────

class CentralEvaluationStep:
    """Pipeline step that applies CentralFindingEvaluator to raw evidence.

    This step should run FIRST in the pipeline, converting all raw plugin
    outputs into standardized Finding objects before any downstream processing.
    """

    def __init__(self, evaluator: Optional[CentralFindingEvaluator] = None):
        self.evaluator = evaluator or CentralFindingEvaluator()

    async def process(
        self,
        item: Any,
        scan_id: Optional[str] = None,
    ) -> Optional[Finding]:
        if isinstance(item, PassiveObservation):
            raw = CentralFindingEvaluator.from_passive_observation(item)
            return self.evaluator.evaluate(raw)
        elif isinstance(item, DetectionCandidate):
            raw = CentralFindingEvaluator.from_detection_candidate(item)
            return self.evaluator.evaluate(raw)
        elif isinstance(item, ExposedServiceFinding):
            return self._convert_exposed_service(item)
        elif isinstance(item, Finding):
            return item
        elif isinstance(item, RawEvidence):
            return self.evaluator.evaluate(item)
        else:
            logger.debug("Unrecognized pipeline item type", type=type(item).__name__)
            return None

    def _convert_exposed_service(self, exposure: ExposedServiceFinding) -> Finding:
        """Convert ExposedServiceFinding to a standardized Finding."""
        evidence = Evidence(
            type="network_exposure",
            description=f"Service {exposure.service} exposed on port {exposure.port}",
            data={
                "port": exposure.port,
                "service": exposure.service,
                "product": exposure.product,
                "version": exposure.version,
                "endpoint": exposure.endpoint,
                "risk_score": exposure.risk_score,
                "is_expected": exposure.is_expected,
                "is_authenticated": exposure.is_authenticated,
                "is_internet_facing": exposure.is_internet_facing,
            },
            detection_method="Active",
            reason=exposure.why_detected,
        )

        severity = Severity.INFO
        if exposure.severity.value == "Critical":
            severity = Severity.CRITICAL
        elif exposure.severity.value == "High":
            severity = Severity.HIGH
        elif exposure.severity.value == "Medium":
            severity = Severity.MEDIUM
        elif exposure.severity.value == "Low":
            severity = Severity.LOW

        confidence = Confidence.LOW
        if exposure.confidence >= 0.95:
            confidence = Confidence.CERTAIN
        elif exposure.confidence >= 0.80:
            confidence = Confidence.HIGH
        elif exposure.confidence >= 0.50:
            confidence = Confidence.MEDIUM

        return Finding(
            plugin_id=exposure.plugin_id,
            title=exposure.title,
            description=exposure.description,
            severity=severity,
            confidence=confidence,
            confidence_score=exposure.confidence,
            endpoint=exposure.endpoint,
            evidence=[evidence],
            verification_status=VerificationStatus.VERIFIED,
            detection_method=DetectionMethod.ACTIVE,
            remediation=exposure.remediation,
            references=exposure.references,
            cwe_id=exposure.cwe_id,
            owasp_category=exposure.owasp_category,
            capec_id=exposure.capec_id,
            why_detected=exposure.why_detected,
            how_verified=exposure.how_verified,
            severity_reason=exposure.severity_reason,
            false_positive_reasons=exposure.false_positive_reasons,
        )
