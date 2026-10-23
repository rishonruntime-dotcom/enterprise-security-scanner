import pytest
import os
from scanner.crawler.utils import URLNormalizer, ScopeValidator
from scanner.crawler.extractors import HTMLExtractor
from scanner.crawler.models import Endpoint, Form, Asset
from scanner.crawler.engine import CrawlStateHelper

def test_url_normalizer():
    assert URLNormalizer.normalize("https://example.com/page#section") == "https://example.com/page"
    assert URLNormalizer.normalize("HTTP://EXAMPLE.COM/page") == "http://example.com/page"
    
    # Relative resolution
    assert URLNormalizer.resolve_relative("https://example.com/dir/", "page.html") == "https://example.com/dir/page.html"
    assert URLNormalizer.resolve_relative("https://example.com/dir", "/page.html") == "https://example.com/page.html"


def test_scope_validator():
    scope = ScopeValidator(allowed_domains=["example.com", "test.local"])
    
    assert scope.in_scope("https://example.com/index.html") is True
    assert scope.in_scope("http://sub.example.com/page") is True
    assert scope.in_scope("https://test.local:8443/api") is True
    
    assert scope.in_scope("https://attacker.com") is False
    assert scope.in_scope("https://example.com.evil.org") is False


def test_html_extractor():
    html = """
    <html>
        <body>
            <a href="/about">About</a>
            <a href="https://external.com">External</a>
            <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
            </form>
            <script src="/js/app.js"></script>
            <link rel="stylesheet" href="/css/style.css" />
        </body>
    </html>
    """
    
    extractor = HTMLExtractor()
    results = extractor.extract(html, "https://example.com")
    
    endpoints = [r for r in results if isinstance(r, Endpoint)]
    forms = [r for r in results if isinstance(r, Form)]
    assets = [r for r in results if isinstance(r, Asset)]
    
    assert len(endpoints) == 2
    assert endpoints[0].url == "https://example.com/about"
    assert endpoints[1].url == "https://external.com"
    
    assert len(forms) == 1
    assert forms[0].action == "https://example.com/login"
    assert forms[0].method == "POST"
    assert len(forms[0].inputs) == 2
    assert forms[0].inputs[0]["name"] == "username"
    
    assert len(assets) == 2
    # The html has 1 script[src] + 1 link rel stylesheet => 2 assets. Let's check length
    assert len([x for x in assets if x.type in ["script", "stylesheet"]]) == 2


def test_api_discovery_in_html_extractor():
    html = """
    <html>
        <script>
            const gql = "/api/graphql";
            const soap = "/services/User.asmx?wsdl";
        </script>
    </html>
    """
    extractor = HTMLExtractor()
    results = extractor.extract(html, "https://example.com")
    endpoints = [r for r in results if isinstance(r, Endpoint)]
    
    assert any("graphql" in ep.url for ep in endpoints)
    assert any(".asmx" in ep.url for ep in endpoints)
    
    # GraphQL endpoints are mapped as POST
    gql_ep = [ep for ep in endpoints if "graphql" in ep.url][0]
    assert gql_ep.method == "POST"
    assert gql_ep.parameters.get("query") is not None


def test_crawl_state_helper():
    scan_id = "test-scan-state-123"
    visited = {"https://example.com/visited1", "https://example.com/visited2"}
    enqueued = [("https://example.com/queue1", 1), ("https://example.com/queue2", 2)]
    
    CrawlStateHelper.save_state(scan_id, visited, enqueued)
    
    state = CrawlStateHelper.load_state(scan_id)
    assert state is not None
    assert set(state["visited"]) == visited
    assert len(state["enqueued"]) == 2
    
    CrawlStateHelper.clear_state(scan_id)
    assert CrawlStateHelper.load_state(scan_id) is None
