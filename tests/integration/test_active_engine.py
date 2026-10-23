import pytest
import asyncio
from typing import Dict, Any

from scanner.active.engine import ActiveScannerManager
from scanner.network.http.manager import HTTPClientManager
from scanner.network.models import HTTPResponse, HTTPRequest
from scanner.interfaces.network import HTTPClientInterface

class MockVulnerableClient(HTTPClientInterface):
    """A mock client that reflects the 'q' parameter in the response."""
    async def request(self, method: str, url: str, **kwargs) -> HTTPResponse:
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        # Simulate reflection of 'q' parameter
        q_val = params.get('q', [''])[0]
        body_content = f"<html><body>Search results for {q_val}</body></html>"
        
        req = HTTPRequest(method=method, url=url)
        return HTTPResponse(
            status_code=200,
            url=url,
            headers={},
            cookies=[],
            body=body_content.encode(),
            text=body_content,
            request=req
        )

    async def get(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("GET", url, **kwargs)
        
    async def post(self, url: str, **kwargs) -> HTTPResponse:
        return await self.request("POST", url, **kwargs)
        
    async def send(self, request: HTTPRequest) -> HTTPResponse:
        return await self.request(request.method, request.url)
        
    async def close(self) -> None:
        pass


class MockHTTPManager(HTTPClientManager):
    def __init__(self):
        super().__init__()
        self._shared_client = MockVulnerableClient()
        
    def get_shared_client(self):
        return self._shared_client

@pytest.mark.asyncio
async def test_active_manager_integration():
    http_manager = MockHTTPManager()
    manager = ActiveScannerManager(http_manager=http_manager)
    
    assert len(manager.plugins) >= 1
    assert "ACT-XSS-001" in manager.plugins
    
    # Endpoint with a parameter
    endpoint_url = "https://example.com/search?q=safe&page=1"
    
    candidates = await manager.analyze_endpoint(endpoint_url)
    
    # The MockVulnerableClient reflects the 'q' parameter, so we should get an XSS candidate for 'q'
    # But it does NOT reflect 'page', so we should NOT get a candidate for 'page'
    xss_candidates = [c for c in candidates if c.plugin_id == "ACT-XSS-001"]
    assert len(xss_candidates) == 1
    
    candidate = xss_candidates[0]
    assert candidate.parameter == "q"
    assert candidate.vulnerability_type == "xss"
