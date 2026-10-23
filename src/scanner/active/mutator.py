"""
Enterprise Request Mutator.

Generates mutated HTTP requests across all injection surfaces:
GET query parameters, POST form-urlencoded, POST JSON, POST XML, POST multipart,
cookies, and headers. Supports multiple encoding schemes.
"""
import urllib.parse
import json
import copy
from typing import List, Dict, Any, Union, Optional

from ..interfaces.active import RequestMutatorInterface
from ..active.models import TestCase, Payload, PayloadEncoding
from ..network.models import HTTPRequest, Cookie as NetworkCookie
from ..crawler.models import Endpoint


class EnterpriseRequestMutator:
    """Mutates requests across query parameters, POST bodies (form/JSON/XML), headers, and cookies.
    
    Supports encoding variations: URL, double-URL, Unicode, and mixed.
    """

    FUZZABLE_HEADERS = ["User-Agent", "X-Forwarded-For", "Referer", "X-Api-Key", "X-Original-URL", "X-Rewrite-URL"]
    FUZZABLE_COOKIES = ["session", "tracking_id", "user", "token", "sid", "JSESSIONID", "PHPSESSID"]

    @staticmethod
    def _url_encode(value: str) -> str:
        return urllib.parse.quote(value, safe="")

    @staticmethod
    def _double_url_encode(value: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(value, safe=""), safe="")

    @staticmethod
    def _unicode_encode(value: str) -> str:
        result = []
        for ch in value:
            if ch in ('.', '/', '\\'):
                result.append(f"%u{ord(ch):04x}")
            else:
                result.append(ch)
        return "".join(result)

    def _encode_payload(self, payload: Payload) -> List[Payload]:
        """Generate encoded variants of a payload based on its encoding setting."""
        if payload.encoding == PayloadEncoding.NONE:
            return [payload]

        variants = [payload]  # Always include original

        if payload.encoding in (PayloadEncoding.URL, PayloadEncoding.MIXED):
            variants.append(Payload(
                value=self._url_encode(payload.value),
                metadata=payload.metadata,
                technique=payload.technique,
                encoding=PayloadEncoding.URL,
                category=payload.category,
                expected_marker=payload.expected_marker,
                expected_timing_delta=payload.expected_timing_delta,
            ))

        if payload.encoding in (PayloadEncoding.DOUBLE_URL, PayloadEncoding.MIXED):
            variants.append(Payload(
                value=self._double_url_encode(payload.value),
                metadata=payload.metadata,
                technique=payload.technique,
                encoding=PayloadEncoding.DOUBLE_URL,
                category=payload.category,
                expected_marker=payload.expected_marker,
                expected_timing_delta=payload.expected_timing_delta,
            ))

        if payload.encoding in (PayloadEncoding.UNICODE, PayloadEncoding.MIXED):
            variants.append(Payload(
                value=self._unicode_encode(payload.value),
                metadata=payload.metadata,
                technique=payload.technique,
                encoding=PayloadEncoding.UNICODE,
                category=payload.category,
                expected_marker=payload.expected_marker,
                expected_timing_delta=payload.expected_timing_delta,
            ))

        return variants

    def mutate(self, target: Union[str, Endpoint], payloads: List[str]) -> List[TestCase]:
        """Generate test cases from payloads. Accepts raw strings or Payload objects in the list."""
        test_cases: List[TestCase] = []

        # Normalize payloads to Payload objects
        payload_objs: List[Payload] = []
        for p in payloads:
            if isinstance(p, Payload):
                payload_objs.append(p)
            else:
                payload_objs.append(Payload(value=str(p)))

        if isinstance(target, str):
            test_cases.extend(self._mutate_url_string(target, payload_objs))
        else:
            test_cases.extend(self._mutate_endpoint(target, payload_objs))

        return test_cases

    def _mutate_url_string(self, url: str, payloads: List[Payload]) -> List[TestCase]:
        """Mutate a simple URL string by injecting into query parameters."""
        test_cases = []
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True)

        if not query_params:
            return test_cases

        for payload in payloads:
            for variant in self._encode_payload(payload):
                for i, (param_name, original_value) in enumerate(query_params):
                    mutated = query_params.copy()
                    mutated[i] = (param_name, variant.value)
                    new_query = urllib.parse.urlencode(mutated)
                    mutated_url = urllib.parse.urlunparse((
                        parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                        parsed_url.params, new_query, parsed_url.fragment
                    ))
                    req = HTTPRequest(method="GET", url=mutated_url)
                    test_cases.append(TestCase(
                        request=req,
                        payload=variant,
                        mutated_parameter=param_name,
                        mutation_location="query",
                        original_value=original_value,
                    ))

        return test_cases

    def _mutate_endpoint(self, endpoint: Endpoint, payloads: List[Payload]) -> List[TestCase]:
        """Mutate a structured Endpoint across all injection surfaces."""
        test_cases = []
        method = endpoint.method.upper()
        base_url = endpoint.url
        params = endpoint.parameters or {}
        parsed_url = urllib.parse.urlparse(base_url)

        for payload in payloads:
            for variant in self._encode_payload(payload):
                # 1. Query parameter mutation (GET, DELETE, HEAD)
                if method in ("GET", "DELETE", "HEAD") and params:
                    test_cases.extend(
                        self._mutate_query_params(method, base_url, parsed_url, params, variant)
                    )

                # 2. POST / PUT / PATCH body mutation
                elif method in ("POST", "PUT", "PATCH"):
                    if params:
                        # Form URL-encoded
                        test_cases.extend(
                            self._mutate_form_body(method, base_url, params, variant)
                        )
                        # JSON body
                        test_cases.extend(
                            self._mutate_json_body(method, base_url, params, variant)
                        )
                        # XML body
                        test_cases.extend(
                            self._mutate_xml_body(method, base_url, params, variant)
                        )

                # 3. Header mutation (all methods)
                test_cases.extend(
                    self._mutate_headers(method, base_url, variant)
                )

                # 4. Cookie mutation (all methods)
                test_cases.extend(
                    self._mutate_cookies(method, base_url, parsed_url, variant)
                )

        return test_cases

    def _mutate_query_params(
        self, method: str, base_url: str, parsed_url: Any, params: Dict, payload: Payload
    ) -> List[TestCase]:
        """Mutate query parameters."""
        cases = []
        for param_name, param_value in params.items():
            mutated_dict = dict(params)
            mutated_dict[param_name] = payload.value
            new_query = urllib.parse.urlencode(mutated_dict)
            mutated_url = urllib.parse.urlunparse((
                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                parsed_url.params, new_query, parsed_url.fragment
            ))
            req = HTTPRequest(method=method, url=mutated_url)
            cases.append(TestCase(
                request=req,
                payload=payload,
                mutated_parameter=param_name,
                mutation_location="query",
                original_value=str(param_value),
            ))
        return cases

    def _mutate_form_body(
        self, method: str, base_url: str, params: Dict, payload: Payload
    ) -> List[TestCase]:
        """Mutate POST form-urlencoded body."""
        cases = []
        for param_name, param_value in params.items():
            mutated_dict = dict(params)
            mutated_dict[param_name] = payload.value
            body_data = urllib.parse.urlencode(mutated_dict)
            req = HTTPRequest(
                method=method,
                url=base_url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=body_data,
            )
            cases.append(TestCase(
                request=req,
                payload=payload,
                mutated_parameter=param_name,
                mutation_location="body",
                original_value=str(param_value),
            ))
        return cases

    def _mutate_json_body(
        self, method: str, base_url: str, params: Dict, payload: Payload
    ) -> List[TestCase]:
        """Mutate POST JSON body."""
        cases = []
        for param_name, param_value in params.items():
            mutated_dict = dict(params)
            mutated_dict[param_name] = payload.value
            req = HTTPRequest(
                method=method,
                url=base_url,
                headers={"Content-Type": "application/json"},
                body=json.dumps(mutated_dict),
            )
            cases.append(TestCase(
                request=req,
                payload=payload,
                mutated_parameter=param_name,
                mutation_location="body",
                original_value=str(param_value),
            ))
        return cases

    def _mutate_xml_body(
        self, method: str, base_url: str, params: Dict, payload: Payload
    ) -> List[TestCase]:
        """Mutate POST XML body."""
        cases = []
        for param_name, param_value in params.items():
            xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>', "<data>"]
            for k, v in params.items():
                val = payload.value if k == param_name else str(v)
                xml_parts.append(f"  <{k}>{val}</{k}>")
            xml_parts.append("</data>")
            xml_body = "\n".join(xml_parts)

            req = HTTPRequest(
                method=method,
                url=base_url,
                headers={"Content-Type": "application/xml"},
                body=xml_body,
            )
            cases.append(TestCase(
                request=req,
                payload=payload,
                mutated_parameter=param_name,
                mutation_location="xml",
                original_value=str(param_value),
            ))
        return cases

    def _mutate_headers(self, method: str, base_url: str, payload: Payload) -> List[TestCase]:
        """Mutate HTTP headers with payload."""
        cases = []
        for hk in self.FUZZABLE_HEADERS:
            req = HTTPRequest(method=method, url=base_url, headers={hk: payload.value})
            cases.append(TestCase(
                request=req,
                payload=payload,
                mutated_parameter=f"header:{hk}",
                mutation_location="header",
                original_value=None,
            ))
        return cases

    def _mutate_cookies(
        self, method: str, base_url: str, parsed_url: Any, payload: Payload
    ) -> List[TestCase]:
        """Mutate cookies with payload."""
        cases = []
        netloc = parsed_url.netloc if hasattr(parsed_url, 'netloc') else ""
        for ck in self.FUZZABLE_COOKIES:
            req = HTTPRequest(
                method=method,
                url=base_url,
                cookies=[NetworkCookie(name=ck, value=payload.value, domain=netloc)],
            )
            cases.append(TestCase(
                request=req,
                payload=payload,
                mutated_parameter=f"cookie:{ck}",
                mutation_location="cookie",
                original_value=None,
            ))
        return cases
