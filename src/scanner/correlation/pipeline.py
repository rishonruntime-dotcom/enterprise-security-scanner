from abc import ABC, abstractmethod
from typing import Optional, Any, Union, List, Dict
import structlog

from ..models.finding import Finding
from .models import EnrichedFinding
from ..active.models import DetectionCandidate
from ..passive.models import PassiveObservation
from .correlator import FindingCorrelator
from .severity_context import ContextualSeverityStep
from .central_evaluator import CentralEvaluationStep, RawEvidence

logger = structlog.get_logger(__name__)

class PipelineStep(ABC):
    """Abstract step in the finding pipeline."""
    
    @abstractmethod
    async def process(self, item: Any, scan_id: Optional[str] = None) -> Optional[Any]:
        """Process an item asynchronously. Return None if the finding should be dropped."""
        pass

import urllib.parse

class FindingPipeline:
    """Orchestrates the evaluation, verification, deduplication, and enrichment of findings.
    
    Pipeline stages (in order):
      1. CentralEvaluationStep  : Payload/Evidence → Finding
      2. EvidenceVerificationStep: Finding → verified Finding (active retry, stability, baseline)
      3. DeduplicationStep      : aggregate duplicate findings
      4. IntelligenceEnrichmentStep: map CWE/OWASP/CAPEC
      5. CVSSCalculationStep    : compute CVSS
      6. RiskCalculationStep    : compute risk/priority
      7. BusinessPriorityStep   : business context adjustment
      
    Post-processing (applied after pipeline steps):
      - ContextualSeverityStep
      - FalsePositiveReductionStep
      - DynamicConfidenceStep
      - DynamicSeverityStep
    """
    
    def __init__(self, steps: list[PipelineStep] = None, correlator: FindingCorrelator | None = None, severity_context_step: ContextualSeverityStep | None = None, false_positive_step: Any = None, dynamic_severity_step: Any = None, dynamic_confidence_step: Any = None, central_evaluation_step: Any = None):
        self.steps = list(steps or [])
        self.correlator = correlator or FindingCorrelator()
        self.severity_context_step = severity_context_step
        self.false_positive_step = false_positive_step
        self.dynamic_severity_step = dynamic_severity_step
        self.dynamic_confidence_step = dynamic_confidence_step
        self.central_evaluation_step = central_evaluation_step
        
    def add_step(self, step: PipelineStep):
        self.steps.append(step)
        
    async def process(
        self, 
        item: Union[DetectionCandidate, PassiveObservation, RawEvidence, Finding, List[Union[DetectionCandidate, PassiveObservation, RawEvidence, Finding]]], 
        scan_id: Optional[str] = None,
        severity_context: Optional[dict[str, Any]] = None,
    ) -> Union[Optional[EnrichedFinding], List[EnrichedFinding]]:
        """Run raw candidate(s) or observation(s) through the pipeline asynchronously."""
        if isinstance(item, (list, tuple)):
            results: List[EnrichedFinding] = []
            for sub_item in item:
                res = await self._process_single(sub_item, scan_id=scan_id, aggregate=True)
                if res is not None:
                    res = await self._apply_severity_context(res, scan_id, severity_context)
                    res = await self.apply_false_positive_reduction(res)
                    res = await self.apply_dynamic_severity(res, scan_id)
                    if res is not None:
                        results.append(res)
            correlated = self.correlator.correlate(self._deduplicate_findings(results))
            final: List[EnrichedFinding] = []
            for f in correlated:
                f = await self.apply_dynamic_confidence(f, scan_id)
                if f is not None:
                    final.append(f)
            return final

        result = await self._process_single(item, scan_id=scan_id)
        if result is None:
            return None
        result = await self._apply_severity_context(result, scan_id, severity_context)
        result = await self.apply_dynamic_confidence(result, scan_id)
        result = await self.apply_false_positive_reduction(result)
        return await self.apply_dynamic_severity(result, scan_id)

    async def _apply_severity_context(self, finding: EnrichedFinding, scan_id: Optional[str], context: Optional[dict[str, Any]]) -> EnrichedFinding:
        if not self.severity_context_step:
            return finding
        return await self.severity_context_step.process(finding, scan_id=scan_id, context=context)

    def _deduplicate_findings(self, findings: List[EnrichedFinding]) -> List[EnrichedFinding]:
        """Deduplicate and aggregate global server-wide findings (headers, CSP, cookies) by plugin_id and host."""
        from .confidence import ConfidenceCalculator
        seen_keys: Dict[str, EnrichedFinding] = {}
        unique_results: List[EnrichedFinding] = []

        for finding in findings:
            p_id = getattr(finding, "plugin_id", "")
            title = getattr(finding, "title", "")
            
            if p_id.startswith("PASS-") or "Header" in title or "CSP" in title or "Cookie" in title:
                try:
                    parsed = urllib.parse.urlparse(finding.endpoint)
                    host = parsed.netloc or parsed.path
                except Exception:
                    host = "global"

                dedup_key = f"{host}:{p_id}:{title}"
                if dedup_key in seen_keys:
                    existing = seen_keys[dedup_key]
                    existing.merge_count = getattr(existing, "merge_count", 1) + 1
                    affected_endpoints = list(getattr(existing, "affected_endpoints", []) or [existing.endpoint])
                    affected_endpoints.extend(getattr(finding, "affected_endpoints", []) or [finding.endpoint])
                    existing.affected_endpoints = list(dict.fromkeys(affected_endpoints))
                    if finding.evidence and existing.evidence:
                        for ev in finding.evidence:
                            if ev.description and ev.description not in [e.description for e in existing.evidence]:
                                existing.evidence.append(ev)

                    self._attach_aggregation_summary(existing)
                    
                    # Recalculate dynamic multi-signal confidence for aggregated repeat findings
                    from .dynamic_confidence import DynamicConfidenceEngine
                    conf_enum, conf_score, _ = DynamicConfidenceEngine().calculate(existing)
                    existing.confidence = conf_enum
                    existing.confidence_score = conf_score
                else:
                    finding.affected_endpoints = list(dict.fromkeys(
                        getattr(finding, "affected_endpoints", []) or [finding.endpoint]
                    ))
                    seen_keys[dedup_key] = finding
                    unique_results.append(finding)
            else:
                unique_results.append(finding)

        return unique_results

    @staticmethod
    def _attach_aggregation_summary(finding: EnrichedFinding) -> None:
        """Keep aggregation evidence durable through the existing evidence column."""
        if not finding.evidence:
            return
        primary_evidence = finding.evidence[0]
        original_data = primary_evidence.data
        if isinstance(original_data, dict) and "affected_endpoints" in original_data:
            original_data = original_data.get("primary_evidence", original_data)
        primary_evidence.data = {
            "primary_evidence": original_data,
            "affected_endpoints": finding.affected_endpoints,
            "affected_endpoint_count": len(finding.affected_endpoints),
            "aggregation": "Equivalent passive finding observed across multiple endpoints on the same origin.",
        }
        base_description = primary_evidence.description.split(" Observed on ", 1)[0]
        primary_evidence.description = f"{base_description} Observed on {len(finding.affected_endpoints)} affected endpoint(s)."

    async def _process_single(
        self, 
        item: Union[DetectionCandidate, PassiveObservation, RawEvidence, Finding], 
        scan_id: Optional[str] = None,
        aggregate: bool = False,
    ) -> Optional[EnrichedFinding]:
        current_item: Any = item
        if self.central_evaluation_step:
            current_item = await self.central_evaluation_step.process(current_item, scan_id=scan_id)
            if current_item is None:
                logger.debug("Finding dropped by central evaluation", type=type(item).__name__)
                return None
        for step in self.steps:
            if aggregate and step.__class__.__name__ == "DeduplicationStep":
                continue
            try:
                current_item = await step.process(current_item, scan_id=scan_id)
                if current_item is None:
                    logger.debug("Finding dropped by pipeline step", step=step.__class__.__name__)
                    return None
            except Exception as e:
                logger.error("Error processing finding in pipeline step", step=step.__class__.__name__, error=str(e))
                return None
                
        if isinstance(current_item, EnrichedFinding):
            return current_item

        return None

    async def apply_dynamic_confidence(self, finding: EnrichedFinding, scan_id: Optional[str] = None) -> Optional[EnrichedFinding]:
        """Apply dynamic confidence calculation after enrichment, before FP reduction."""
        if not self.dynamic_confidence_step:
            return finding
        try:
            return await self.dynamic_confidence_step.process(finding, scan_id=scan_id)
        except Exception as e:
            logger.error("Error in dynamic confidence step", error=str(e))
            return finding

    async def apply_false_positive_reduction(self, finding: EnrichedFinding) -> Optional[EnrichedFinding]:
        """Apply false-positive reduction as the final step before reporting."""
        if not self.false_positive_step:
            return finding
        try:
            return await self.false_positive_step.process(finding)
        except Exception as e:
            logger.error("Error in false-positive reduction step", error=str(e))
            return finding

    async def apply_dynamic_severity(self, finding: EnrichedFinding, scan_id: Optional[str] = None) -> Optional[EnrichedFinding]:
        """Apply dynamic severity calculation as the absolute last step."""
        if not self.dynamic_severity_step:
            return finding
        try:
            return await self.dynamic_severity_step.process(finding, scan_id=scan_id)
        except Exception as e:
            logger.error("Error in dynamic severity step", error=str(e))
            return finding
