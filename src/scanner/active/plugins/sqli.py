"""
Enterprise SQL Injection Detection Plugin.

Emits DetectionCandidate objects for centralized verification.
Does NOT verify independently.
"""
import re
import time
import urllib.parse
from typing import List, Union, Dict, Optional, Tuple

import structlog

from ...interfaces.active import ActivePluginInterface
from ...passive.models import PluginMetadata
from ...network.http.manager import HTTPClientManager
from ...network.models import HTTPRequest, HTTPResponse
from ...models.finding import Finding, Evidence, VerificationStatus, Severity, Confidence
from ...crawler.models import Endpoint
from ..models import (
    DetectionCandidate, BaselineResult, Payload, PayloadTechnique, TestCase,
)
from ..mutator import EnterpriseRequestMutator

logger = structlog.get_logger(__name__)


DB_ERROR_PATTERNS = {
    "MySQL": [r"SQL syntax.*?MySQL", r"Warning.*?\bmysql_", r"com\.mysql\.jdbc"],
    "PostgreSQL": [r"PostgreSQL.*?ERROR", r"Warning.*?\bpg_", r"org\.postgresql\.util\.PSQLException"],
    "SQLite": [r"sqlite3\.OperationalError", r"SQLite/JDBCDriver", r"SQLITE_ERROR"],
    "SQLServer": [r"Driver.*?SQL Server", r"OLE DB.*?SQL Server", r"com\.microsoft\.sqlserver\.jdbc"],
    "Oracle": [r"ORA-\d{5}", r"Oracle.*?Driver", r"oracle\.jdbc\.driver"],
    "DB2": [r"CLI Driver.*?DB2", r"DB2 SQL error", r"com\.ibm\.db2\.jcc"],
}

class SQLInjectionPlugin(ActivePluginInterface):
    """Enterprise SQL Injection detector emitting unverified candidates."""

    ERROR_PAYLOADS = [
        Payload(value="'", technique=PayloadTechnique.ERROR_BASED, category="sqli"),
        Payload(value='"', technique=PayloadTechnique.ERROR_BASED, category="sqli"),
        Payload(value="' OR '1'='1", technique=PayloadTechnique.ERROR_BASED, category="sqli"),
        Payload(value='" OR "1"="1', technique=PayloadTechnique.ERROR_BASED, category="sqli"),
    ]

    BOOLEAN_PAIRS = [
        ("1' AND '1'='1", "1' AND '1'='2"),
        ('1" AND "1"="1', '1" AND "1"="2'),
        ("1 AND 1=1", "1 AND 1=2"),
        ("1' OR '1'='1", "1' OR '1'='2"),
        ("' OR 1=1--", "' OR 1=2--"),
    ]

    TIME_PAYLOADS = [
        Payload(value="1' AND SLEEP(5)--", technique=PayloadTechnique.TIME_BASED, category="sqli", expected_timing_delta=5.0),
        Payload(value="1'; WAITFOR DELAY '0:0:5'--", technique=PayloadTechnique.TIME_BASED, category="sqli", expected_timing_delta=5.0),
        Payload(value="1'; SELECT pg_sleep(5)--", technique=PayloadTechnique.TIME_BASED, category="sqli", expected_timing_delta=5.0),
        Payload(value="1) AND SLEEP(5)--", technique=PayloadTechnique.TIME_BASED, category="sqli", expected_timing_delta=5.0),
    ]

    UNION_MARKER = "qz7x9"

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="ACT-SQLI-001",
            name="SQL Injection (SQLi)",
            description="Detects SQL Injection candidates for centralized verification.",
        )

    async def execute(self, endpoint: Union[str, Endpoint], http_manager: HTTPClientManager) -> List[DetectionCandidate]:
        candidates = []
        client = http_manager.get_shared_client()
        endpoint_url = endpoint.url if not isinstance(endpoint, str) else endpoint
        mutator = EnterpriseRequestMutator()

        params = self._get_params(endpoint)
        if not params: return candidates

        baseline = await self._capture_baseline(client, endpoint_url)
        if not baseline or baseline.error: return candidates

        vulnerable_params = set()

        for param_name in params:
            if param_name in vulnerable_params: continue

            # Error-based
            for payload in self.ERROR_PAYLOADS:
                cases = mutator.mutate(endpoint, [payload])
                case = next((tc for tc in cases if tc.mutated_parameter == param_name), None)
                if not case: continue

                resp = await client.send(case.request)
                resp_text = resp.text if isinstance(resp.text, str) else ""
                match = self._check_db_errors(resp_text)
                if match:
                    candidate = DetectionCandidate(
                        plugin_id=self.metadata.id,
                        vulnerability_type="sqli",
                        technique=PayloadTechnique.ERROR_BASED,
                        endpoint=endpoint_url,
                        parameter=param_name,
                        payload=payload,
                        baseline=baseline,
                        fuzzed_request=case.request,
                        fuzzed_response=resp,
                        fuzzed_timing_ms=resp.latency * 1000 if resp.latency else 0.0,
                        matched_signature=match[1],
                        db_type=match[0],
                    )
                    candidates.append(candidate)
                    vulnerable_params.add(param_name)
                    break

            if param_name in vulnerable_params: continue

            # Boolean-based
            for true_str, false_str in self.BOOLEAN_PAIRS:
                t_payload = Payload(value=true_str, technique=PayloadTechnique.BOOLEAN_BASED, category="sqli")
                f_payload = Payload(value=false_str, technique=PayloadTechnique.BOOLEAN_BASED, category="sqli")
                
                t_case = next((tc for tc in mutator.mutate(endpoint, [t_payload]) if tc.mutated_parameter == param_name), None)
                f_case = next((tc for tc in mutator.mutate(endpoint, [f_payload]) if tc.mutated_parameter == param_name), None)
                
                if not t_case or not f_case: continue
                
                resp_t = await client.send(t_case.request)
                resp_f = await client.send(f_case.request)
                
                t_text = resp_t.text if isinstance(resp_t.text, str) else ""
                f_text = resp_f.text if isinstance(resp_f.text, str) else ""
                
                if abs(len(t_text) - len(f_text)) > 5:
                    candidate = DetectionCandidate(
                        plugin_id=self.metadata.id,
                        vulnerability_type="sqli",
                        technique=PayloadTechnique.BOOLEAN_BASED,
                        endpoint=endpoint_url,
                        parameter=param_name,
                        payload=t_payload,
                        baseline=baseline,
                        fuzzed_request=t_case.request,
                        fuzzed_response=resp_t,
                        false_response=resp_f,
                        detection_evidence={
                            "true_length": len(t_text),
                            "false_length": len(f_text),
                            "length_delta": abs(len(t_text) - len(f_text)),
                        },
                    )
                    candidates.append(candidate)
                    vulnerable_params.add(param_name)
                    break

            if param_name in vulnerable_params: continue

            # Time-based
            for payload in self.TIME_PAYLOADS:
                case = next((tc for tc in mutator.mutate(endpoint, [payload]) if tc.mutated_parameter == param_name), None)
                if not case: continue
                
                start = time.monotonic()
                resp = await client.send(case.request)
                elapsed = (time.monotonic() - start) * 1000
                
                if (elapsed - baseline.response_time_ms) > 3000:
                    candidate = DetectionCandidate(
                        plugin_id=self.metadata.id,
                        vulnerability_type="sqli",
                        technique=PayloadTechnique.TIME_BASED,
                        endpoint=endpoint_url,
                        parameter=param_name,
                        payload=payload,
                        baseline=baseline,
                        fuzzed_request=case.request,
                        fuzzed_response=resp,
                        fuzzed_timing_ms=elapsed,
                    )
                    candidates.append(candidate)
                    vulnerable_params.add(param_name)
                    break

            if param_name in vulnerable_params: continue

            # UNION-based
            column_count = 0
            for n in range(1, 10):
                order_payload = Payload(value=f"1' ORDER BY {n}--", technique=PayloadTechnique.UNION_BASED, category="sqli")
                case = next((tc for tc in mutator.mutate(endpoint, [order_payload]) if tc.mutated_parameter == param_name), None)
                if not case: break
                resp = await client.send(case.request)
                if resp.status_code >= 500 or self._check_db_errors(resp.text if isinstance(resp.text, str) else ""):
                    column_count = n - 1
                    break
            
            if column_count > 0:
                markers = [f"'{self.UNION_MARKER}{i}'" for i in range(1, column_count + 1)]
                union_payload = Payload(value=f"' UNION SELECT {','.join(markers)}--", technique=PayloadTechnique.UNION_BASED, category="sqli")
                case = next((tc for tc in mutator.mutate(endpoint, [union_payload]) if tc.mutated_parameter == param_name), None)
                if case:
                    resp = await client.send(case.request)
                    resp_text = resp.text if isinstance(resp.text, str) else ""
                    if self.UNION_MARKER in resp_text:
                        candidate = DetectionCandidate(
                            plugin_id=self.metadata.id,
                            vulnerability_type="sqli",
                            technique=PayloadTechnique.UNION_BASED,
                            endpoint=endpoint_url,
                            parameter=param_name,
                            payload=union_payload,
                            baseline=baseline,
                            fuzzed_request=case.request,
                            fuzzed_response=resp,
                            matched_signature=self.UNION_MARKER,
                        )
                        candidates.append(candidate)
                        vulnerable_params.add(param_name)

        return candidates

    def _get_params(self, endpoint: Union[str, Endpoint]) -> Dict[str, str]:
        if isinstance(endpoint, str):
            parsed = urllib.parse.urlparse(endpoint)
            return dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        return endpoint.parameters or {}

    async def _capture_baseline(self, client, url: str) -> BaselineResult:
        try:
            req = HTTPRequest(method="GET", url=url)
            start = time.monotonic()
            resp = await client.send(req)
            elapsed = (time.monotonic() - start) * 1000
            return BaselineResult(request=req, response=resp, response_time_ms=elapsed)
        except Exception as e:
            return BaselineResult(request=HTTPRequest(method="GET", url=url), error=str(e))

    def _check_db_errors(self, text: str) -> Optional[Tuple[str, str]]:
        for db_name, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return (db_name, pattern)
        return None
