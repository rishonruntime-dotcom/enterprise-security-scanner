import pytest

from scanner.network.http.manager import HTTPClientManager
from scanner.network.models import HTTPRequest

@pytest.mark.asyncio
async def test_http_client_integration():
    """Test actual HTTP request using HttpxClientAdapter."""
    manager = HTTPClientManager()
    client = manager.create_client()
    
    try:
        # Send a request to a reliable endpoint for integration test
        req = HTTPRequest(method="GET", url="https://example.com")
        
        response = await client.send(req)
        
        assert response.status_code == 200
        assert "example.com" in response.url
        assert isinstance(response.text, str)
        assert response.latency > 0
    finally:
        await client.close()
