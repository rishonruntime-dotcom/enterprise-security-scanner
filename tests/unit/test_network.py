import pytest

from scanner.network.models import HTTPRequest, Cookie, AuthenticationContext
from scanner.network.session import InMemorySessionManager
from scanner.logging.setup import redact_secrets

def test_http_request_model():
    """Test HTTPRequest creation and defaults."""
    req = HTTPRequest(method="GET", url="http://example.com")
    assert req.method == "GET"
    assert req.url == "http://example.com"
    assert req.allow_redirects is True
    assert req.timeout is None

def test_cookie_model():
    """Test Cookie creation."""
    cookie = Cookie(name="session_id", value="12345")
    assert cookie.name == "session_id"
    assert cookie.value == "12345"
    assert cookie.path == "/"

@pytest.mark.asyncio
async def test_session_manager():
    """Test InMemorySessionManager persistence."""
    manager = InMemorySessionManager()
    
    ctx = AuthenticationContext(username="test_user")
    ctx.tokens["auth_token"] = "abc-123"
    
    await manager.save_context(ctx)
    
    retrieved = await manager.get_context(ctx.id)
    assert retrieved is not None
    assert retrieved.username == "test_user"
    assert retrieved.tokens["auth_token"] == "abc-123"

def test_log_redaction():
    """Test the redact_secrets logging processor."""
    event_dict = {
        "event": "Sending request",
        "url": "http://example.com",
        "headers": {
            "Host": "example.com",
            "Authorization": "Bearer secret-token",
            "Cookie": "session=abc",
        },
        "password": "my-super-secret-password"
    }
    
    redacted = redact_secrets(None, None, event_dict)
    
    assert redacted["event"] == "Sending request"
    assert redacted["url"] == "http://example.com"
    assert redacted["password"] == "***REDACTED***"
    assert redacted["headers"]["Host"] == "example.com"
    assert redacted["headers"]["Authorization"] == "***REDACTED***"
    assert redacted["headers"]["Cookie"] == "***REDACTED***"
