import json
import pytest
from scanner.crawler.queue import InMemoryURLQueue
from scanner.crawler.extractors import HTMLExtractor
from scanner.crawler.engine import CrawlManager, CrawlWorker, CrawlStateHelper
from scanner.crawler.models import CrawlSession, CrawlResult, Endpoint, Form, Asset
from scanner.network.http.manager import HTTPClientManager


@pytest.mark.asyncio
async def test_crawl_engine_integration():
    """Test the CrawlManager orchestration against an external reliable target."""
    http_manager = HTTPClientManager()
    shared_client = http_manager.get_shared_client()
    
    queue = InMemoryURLQueue(max_depth=1)
    extractor = HTMLExtractor()
    
    manager = CrawlManager(
        http_client=shared_client,
        queue=queue,
        extractors=[extractor],
        concurrency=2
    )
    
    import uuid
    session = CrawlSession(
        scan_id=f"test-scan-{uuid.uuid4().hex[:8]}",
        allowed_domains=["example.com"],
        max_depth=1,
        max_urls=10
    )
    
    try:
        result = await manager.crawl(["https://example.com"], session)
        
        assert len(result.endpoints) > 0
        iana_link = any(e.url == "https://iana.org/domains/example" for e in result.endpoints)
        assert iana_link is True
        
        assert queue.qsize() == 0
        assert queue.is_visited("https://example.com") is True
        assert queue.is_visited("https://iana.org/domains/example") is False
    finally:
        await http_manager.close()


class TestHTMLExtractorHiddenParameters:
    """Test hidden parameter extraction from forms, meta tags, and data attributes."""

    def test_hidden_inputs_extracted(self):
        html = """
        <form action="/login" method="POST">
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="text" name="username">
            <input type="password" name="password">
        </form>
        """
        extractor = HTMLExtractor()
        results = extractor.extract(html, "https://example.com/page")
        
        forms = [r for r in results if isinstance(r, Form)]
        assert len(forms) == 1
        assert forms[0].action == "https://example.com/login"
        assert forms[0].method == "POST"
        
        hidden_eps = [r for r in results if isinstance(r, Endpoint) and "csrf_token" in r.parameters]
        assert len(hidden_eps) >= 1
        assert hidden_eps[0].parameters["csrf_token"] == "abc123"

    def test_meta_csrf_extracted(self):
        html = """
        <html>
        <head>
            <meta name="csrf-token" content="token123">
            <meta name="csrf-param" content="authenticity_token">
        </head>
        <body></body>
        </html>
        """
        extractor = HTMLExtractor()
        results = extractor.extract(html, "https://example.com/page")
        
        eps = [r for r in results if isinstance(r, Endpoint)]
        assert len(eps) >= 1
        assert any("csrf-token" in e.parameters or "csrf_param" in e.parameters for e in eps)

    def test_data_attributes_extracted(self):
        html = """
        <form action="/search" method="GET" data-endpoint="/api/search" data-tenant="acme">
            <input type="text" name="q">
        </form>
        """
        extractor = HTMLExtractor()
        results = extractor.extract(html, "https://example.com/page")
        
        hidden_eps = [r for r in results if isinstance(r, Endpoint) and r.url == "https://example.com/search"]
        assert len(hidden_eps) >= 1
        assert any("tenant" in e.parameters or "endpoint" in e.parameters for e in hidden_eps)


class TestHTMLExtractorJSGeneratedForms:
    """Test JavaScript-generated form discovery."""

    def test_document_create_element_form(self):
        html = """
        <script>
        var form = document.createElement('form');
        form.action = '/api/submit';
        form.method = 'POST';
        var input1 = document.createElement('input');
        input1.name = 'email';
        var input2 = document.createElement('input');
        input2.name = 'password';
        document.body.appendChild(form);
        </script>
        """
        extractor = HTMLExtractor()
        results = extractor.extract(html, "https://example.com/page")
        
        forms = [r for r in results if isinstance(r, Form)]
        assert len(forms) >= 1
        js_form = forms[0]
        assert js_form.action == "https://example.com/api/submit"
        assert js_form.method == "POST"
        assert any(i["name"] == "email" for i in js_form.inputs)
        assert any(i["name"] == "password" for i in js_form.inputs)


class TestHTMLExtractorWebSocketAndAPIs:
    """Test WebSocket and API discovery in inline scripts."""

    def test_websocket_urls_in_js(self):
        html = """
        <script>
        var ws = new WebSocket('wss://example.com/socket');
        var ws2 = new WebSocket("ws://example.com/stream");
        </script>
        """
        extractor = HTMLExtractor()
        results = extractor.extract(html, "https://example.com/page")
        
        ws_eps = [r for r in results if isinstance(r, Endpoint) and r.method == "WS"]
        assert len(ws_eps) >= 1
        urls = [e.url for e in ws_eps]
        assert "wss://example.com/socket" in urls
        assert "ws://example.com/stream" in urls

    def test_graphql_in_js(self):
        html = """
        <script>
        fetch('/graphql', { method: 'POST', body: JSON.stringify({ query: '{ users }' }) });
        fetch('/gql', { method: 'POST' });
        </script>
        """
        extractor = HTMLExtractor()
        results = extractor.extract(html, "https://example.com/page")
        
        gql_eps = [r for r in results if isinstance(r, Endpoint) and "graphql" in r.url.lower()]
        assert len(gql_eps) >= 1
        assert any(e.method == "POST" for e in gql_eps)


class TestCrawlResultModel:
    """Test new CrawlResult fields."""

    def test_new_fields_exist(self):
        result = CrawlResult()
        assert hasattr(result, "websocket_urls")
        assert hasattr(result, "spa_routes")
        assert hasattr(result, "openapi_specs")
        assert hasattr(result, "manifest_urls")
        assert hasattr(result, "service_worker_urls")
        assert result.websocket_urls == []
        assert result.spa_routes == []
        assert result.openapi_specs == []
        assert result.manifest_urls == []
        assert result.service_worker_urls == []

    def test_new_fields_populated(self):
        result = CrawlResult(
            websocket_urls=["wss://example.com/socket"],
            spa_routes=["https://example.com/dashboard"],
            openapi_specs=["https://example.com/openapi.json"],
            manifest_urls=["https://example.com/manifest.json"],
            service_worker_urls=["https://example.com/sw.js"]
        )
        assert len(result.websocket_urls) == 1
        assert len(result.spa_routes) == 1
        assert len(result.openapi_specs) == 1
        assert len(result.manifest_urls) == 1
        assert len(result.service_worker_urls) == 1


class TestOpenAPIDiscovery:
    """Test OpenAPI/Swagger spec discovery and parsing."""

    def test_parse_openapi_spec(self):
        spec_text = json.dumps({
            "openapi": "3.0.0",
            "paths": {
                "/users": {"get": {"summary": "List users"}, "post": {"summary": "Create user"}},
                "/users/{id}": {"get": {"summary": "Get user"}, "parameters": [{"name": "id", "in": "path"}]}
            }
        })
        
        worker = _make_crawl_worker()
        endpoints = worker._parse_openapi_spec("https://example.com/openapi.json", spec_text)
        
        assert len(endpoints) == 3
        methods = {e.method for e in endpoints}
        assert "GET" in methods
        assert "POST" in methods
        urls = [e.url for e in endpoints]
        assert "https://example.com/users" in urls
        assert "https://example.com/users/{id}" in urls

    def test_parse_openapi_with_query_params(self):
        spec_text = json.dumps({
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [
                            {"name": "q", "in": "query"},
                            {"name": "limit", "in": "query"}
                        ]
                    }
                }
            }
        })
        
        worker = _make_crawl_worker()
        endpoints = worker._parse_openapi_spec("https://example.com/openapi.json", spec_text)
        
        assert len(endpoints) == 1
        assert endpoints[0].url == "https://example.com/search"
        assert "q" in endpoints[0].parameters
        assert "limit" in endpoints[0].parameters


class TestManifestDiscovery:
    """Test manifest.json discovery and parsing."""

    def test_parse_manifest(self):
        manifest_text = json.dumps({
            "name": "Test App",
            "start_url": "/dashboard",
            "scope": "/app/",
            "icons": [{"src": "/icon.png", "sizes": "192x192"}],
            "related_applications": [{"platform": "play", "url": "https://play.google.com/store/apps/details?id=test"}]
        })
        
        worker = _make_crawl_worker()
        parsed = worker._parse_manifest("https://example.com/manifest.json", manifest_text, "https://example.com")
        
        assert "https://example.com/dashboard" in parsed["routes"]
        assert "https://example.com/app/" in parsed["routes"]
        assert "https://example.com/icon.png" in parsed["icons"]
        assert "https://play.google.com/store/apps/details?id=test" in parsed["routes"]

    def test_parse_manifest_empty(self):
        worker = _make_crawl_worker()
        parsed = worker._parse_manifest("https://example.com/manifest.json", "{}", "https://example.com")
        assert parsed["routes"] == []
        assert parsed["icons"] == []


class TestCrawlStateHelper:
    """Test crawl state persistence."""

    def test_get_state_path(self):
        path = CrawlStateHelper.get_state_path("scan-123")
        assert path.endswith("scan-123.json")
        assert ".gemini" in path

    def test_save_and_load_state(self):
        import os
        import tempfile
        original_cwd = os.getcwd()
        tmp_dir = tempfile.mkdtemp()
        try:
            os.chdir(tmp_dir)
            visited = {"https://example.com", "https://example.com/about"}
            enqueued = [("https://example.com/contact", 1)]
            
            CrawlStateHelper.save_state("test-scan", visited, enqueued)
            loaded = CrawlStateHelper.load_state("test-scan")
            
            assert loaded is not None
            assert set(loaded["visited"]) == visited
            assert [tuple(x) for x in loaded["enqueued"]] == enqueued
        finally:
            os.chdir(original_cwd)
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_clear_state(self):
        import os
        import tempfile
        original_cwd = os.getcwd()
        tmp_dir = tempfile.mkdtemp()
        try:
            os.chdir(tmp_dir)
            CrawlStateHelper.save_state("test-scan", {"url1"}, [])
            CrawlStateHelper.clear_state("test-scan")
            loaded = CrawlStateHelper.load_state("test-scan")
            assert loaded is None
        finally:
            os.chdir(original_cwd)
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _make_crawl_worker() -> CrawlWorker:
    """Helper to create a minimal CrawlWorker for unit testing."""
    from unittest.mock import AsyncMock
    http_client = AsyncMock()
    queue = InMemoryURLQueue(max_depth=3)
    extractors = [HTMLExtractor()]
    
    from scanner.crawler.utils import ScopeValidator
    scope = ScopeValidator(["example.com"])
    
    return CrawlWorker(
        http_client=http_client,
        extractors=extractors,
        queue=queue,
        scope=scope,
        browser_context=None,
        cond=None,
        session=None
    )


class TestHTMLExtractorServiceWorkerDiscovery:
    """Test Service Worker discovery in inline scripts."""

    def test_service_worker_registration(self):
        html = """
        <script>
        navigator.serviceWorker.register('/sw.js');
        navigator.serviceWorker.register('/service-worker.js');
        </script>
        """
        extractor = HTMLExtractor()
        results = extractor.extract(html, "https://example.com/page")
        
        sw_eps = [r for r in results if isinstance(r, Endpoint) and r.url in ["https://example.com/sw.js", "https://example.com/service-worker.js"]]
        assert len(sw_eps) >= 1


class TestHTMLExtractorSocketIOAndHiddenForms:
    """Test Socket.IO and hidden form discovery."""

    def test_socket_io_detection(self):
        html = """
        <script>
        var socket = io('https://example.com/socket.io/');
        </script>
        """
        extractor = HTMLExtractor()
        results = extractor.extract(html, "https://example.com/page")
        
        ws_eps = [r for r in results if isinstance(r, Endpoint) and r.method == "WS"]
        assert len(ws_eps) >= 1
        assert "https://example.com/socket.io/" in [e.url for e in ws_eps]

    def test_hidden_form_detection(self):
        html = """
        <form action="/hidden-submit" method="POST" style="display:none">
            <input type="hidden" name="csrf_token" value="secret123">
            <input type="hidden" name="action" value="update">
        </form>
        <form action="/visible" method="GET">
            <input type="text" name="q">
        </form>
        """
        extractor = HTMLExtractor()
        results = extractor.extract(html, "https://example.com/page")
        
        forms = [r for r in results if isinstance(r, Form)]
        assert len(forms) >= 2
        actions = [f.action for f in forms]
        assert "https://example.com/hidden-submit" in actions
        assert "https://example.com/visible" in actions


class TestCrawlWorkerServiceWorkerDiscovery:
    """Test Service Worker discovery in CrawlWorker."""

    def test_discover_service_workers_from_html(self):
        html = """
        <script>
        navigator.serviceWorker.register('/sw.js');
        </script>
        <script src="/app.js"></script>
        """
        from unittest.mock import AsyncMock
        http_client = AsyncMock()
        http_client.send.return_value = type('Response', (), {
            'status_code': 200,
            'text': "self.addEventListener('install', event => { event.waitUntil(caches.open('v1').then(cache => cache.addAll(['/']))); });",
            'headers': {}
        })()
        
        queue = InMemoryURLQueue(max_depth=3)
        extractors = [HTMLExtractor()]
        
        from scanner.crawler.utils import ScopeValidator
        scope = ScopeValidator(["example.com"])
        
        worker = CrawlWorker(
            http_client=http_client,
            extractors=extractors,
            queue=queue,
            scope=scope,
            browser_context=None,
            cond=None,
            session=None
        )
        result = CrawlResult()
        
        import asyncio
        asyncio.run(worker._discover_service_workers("https://example.com", html, result))
        
        assert "https://example.com/sw.js" in result.service_worker_urls


class TestGraphQLIntrospectionDiscovery:
    """Test GraphQL introspection detection."""

    def test_graphql_introspection_in_js(self):
        html = """
        <script>
        fetch('/graphql', {
            method: 'POST',
            body: JSON.stringify({ query: '{ __schema { types { name } } }' })
        });
        </script>
        """
        extractor = HTMLExtractor()
        results = extractor.extract(html, "https://example.com/page")
        
        gql_eps = [r for r in results if isinstance(r, Endpoint) and "graphql" in r.url.lower()]
        assert len(gql_eps) >= 1
        assert any("__schema" in str(e.parameters.get("query", "")) for e in gql_eps)
