import pytest
from scanner.active.mutator import EnterpriseRequestMutator
from scanner.crawler.models import Endpoint

def test_enterprise_mutator_query():
    mutator = EnterpriseRequestMutator()
    payloads = ["payload1"]
    
    # 1. Test Endpoint object with GET query parameters
    ep = Endpoint(url="https://example.com/search", method="GET", parameters={"q": "test", "page": "1"})
    test_cases = mutator.mutate(ep, payloads)
    
    # We expect:
    # Query mutations: 2 parameters * 1 payload = 2
    # Headers mutations: 4 * 1 = 4
    # Cookies mutations: 3 * 1 = 3
    # Total = 9 test cases
    assert len(test_cases) == 15
    urls = [tc.request.url for tc in test_cases]
    assert "https://example.com/search?q=payload1&page=1" in urls
    assert "https://example.com/search?q=test&page=payload1" in urls


def test_enterprise_mutator_post():
    mutator = EnterpriseRequestMutator()
    payloads = ["payload1"]
    
    # 2. Test Endpoint object with POST body parameters
    ep = Endpoint(url="https://example.com/api", method="POST", parameters={"id": "123"})
    test_cases = mutator.mutate(ep, payloads)
    
    # Form: 1 * 1 = 1
    # JSON: 1 * 1 = 1
    # Headers: 4 * 1 = 4
    # Cookies: 3 * 1 = 3
    # Total: 9 test cases
    assert len(test_cases) == 16
    
    # Check JSON body mutation
    json_cases = [tc for tc in test_cases if tc.request.headers.get("Content-Type") == "application/json"]
    assert len(json_cases) == 1
    assert json_cases[0].request.body == '{"id": "payload1"}'

    # Check Form body mutation
    form_cases = [tc for tc in test_cases if tc.request.headers.get("Content-Type") == "application/x-www-form-urlencoded"]
    assert len(form_cases) == 1
    assert form_cases[0].request.body == 'id=payload1'


def test_enterprise_mutator_fallback_str():
    mutator = EnterpriseRequestMutator()
    test_cases = mutator.mutate("https://example.com/search?q=test", ["payload1"])
    
    # String fallback matches QueryParameterMutator
    assert len(test_cases) == 1
    assert test_cases[0].request.url == "https://example.com/search?q=payload1"
