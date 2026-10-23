import pytest
from scanner.passive.engine import PassiveScannerManager
from scanner.network.models import HTTPResponse, HTTPRequest

def test_passive_manager_integration():
    manager = PassiveScannerManager()
    
    # Verify plugins were loaded automatically
    assert len(manager.plugins) >= 2
    assert "PASS-001" in manager.plugins
    assert "PASS-002" in manager.plugins
    
    req = HTTPRequest(method="GET", url="https://example.com")
    resp = HTTPResponse(
        status_code=200,
        url="https://example.com",
        headers={"Server": "nginx"},
        cookies=[],
        body=b"<html></html>",
        text="<html></html>",
        request=req
    )
    
    findings = manager.analyze_response(resp)
    
    # We expect missing HSTS and X-Frame-Options at least
    assert len(findings) >= 2
    titles = [f.title for f in findings]
    assert any("Strict-Transport-Security" in t for t in titles)
    assert any("Anti-Clickjacking" in t for t in titles)
