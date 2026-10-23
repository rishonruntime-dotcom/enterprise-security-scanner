import pytest
import asyncio

from scanner.network.browser.manager import BrowserManager

@pytest.mark.asyncio
async def test_browser_integration():
    """Test actual browser navigation and DOM extraction using Playwright."""
    manager = BrowserManager(headless=True)
    
    await manager.start()
    try:
        context = await manager.create_context()
        try:
            # Navigate to a fast, reliable site
            content = await context.get_page_content("https://example.com")
            
            # Verify basic HTML content was retrieved
            assert "<html" in content.lower()
            assert "Example Domain" in content
        finally:
            await context.close()
    finally:
        await manager.stop()
