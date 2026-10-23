import asyncio
import structlog
import os
import json
import re
import urllib.parse
from typing import List, Optional, Tuple, Set, Dict, Any, Union

from ..interfaces.crawler import URLQueueInterface, DiscoveryExtractorInterface
from ..interfaces.network import HTTPClientInterface, BrowserInterface
from ..network.models import HTTPRequest
from .models import CrawlSession, CrawlResult, Endpoint, Form, Asset
from .utils import ScopeValidator

logger = structlog.get_logger(__name__)


class CrawlStateHelper:
    """Helper class to serialize/deserialize visited/enqueued links to handle pause/resume states."""

    @staticmethod
    def get_state_path(scan_id: str) -> str:
        state_dir = os.path.join(os.getcwd(), ".gemini", "crawls_state")
        os.makedirs(state_dir, exist_ok=True)
        return os.path.join(state_dir, f"{scan_id}.json")

    @classmethod
    def save_state(cls, scan_id: str, visited: Set[str], enqueued: List[Tuple[str, int]]) -> None:
        try:
            path = cls.get_state_path(scan_id)
            state = {
                "visited": list(visited),
                "enqueued": enqueued
            }
            with open(path, "w") as f:
                json.dump(state, f)
        except Exception as e:
            logger.warning("Failed to save crawl state", scan_id=scan_id, error=str(e))

    @classmethod
    def load_state(cls, scan_id: str) -> Optional[dict]:
        try:
            path = cls.get_state_path(scan_id)
            if os.path.exists(path):
                with open(path, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.warning("Failed to load crawl state", scan_id=scan_id, error=str(e))
        return None

    @classmethod
    def clear_state(cls, scan_id: str) -> None:
        try:
            path = cls.get_state_path(scan_id)
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


class CrawlWorker:
    """Processes individual URLs during a crawl, executing active network extractors."""

    def __init__(
        self,
        http_client: HTTPClientInterface,
        extractors: List[DiscoveryExtractorInterface],
        queue: URLQueueInterface,
        scope: ScopeValidator,
        browser_context: Optional[BrowserInterface] = None,
        cond: Optional[asyncio.Condition] = None,
        session: Optional[CrawlSession] = None
    ):
        self.http_client = http_client
        self.extractors = extractors
        self.queue = queue
        self.scope = scope
        self.browser_context = browser_context
        self.cond = cond
        self.session = session

    async def _notify_queue_update(self) -> None:
        if self.cond:
            async with self.cond:
                self.cond.notify_all()

    async def _discover_js_endpoints(self, js_url: str, source_url: str) -> List[Endpoint]:
        """Fetch a JavaScript file and extract REST paths, GraphQL, WebSocket, Service Worker, and API endpoints."""
        endpoints: List[Endpoint] = []
        try:
            logger.debug("Fetching script for API discovery", url=js_url)
            req = HTTPRequest(method="GET", url=js_url)
            if self.session and self.session.custom_headers:
                req.headers.update(self.session.custom_headers)
                
            resp = await self.http_client.send(req)
            js_code = resp.text if isinstance(resp.text, str) else ""
            if not js_code:
                return endpoints

            discovered_paths = set()
            discovered_ws = set()
            discovered_sw = set()

            # Find API routes using regex
            path_pattern = r'"(/api/v[0-9]+/[a-zA-Z0-9_\-\{\}\/]+)"|\'(/api/v[0-9]+/[a-zA-Z0-9_\-\{\}\/]+)\''
            matches = re.findall(path_pattern, js_code)
            for m in matches:
                for path in m:
                    if path:
                        discovered_paths.add((path, "GET"))

            route_pattern = r'"(/[a-zA-Z0-9_\-]+)"|\'(/[a-zA-Z0-9_\-]+)\''
            route_matches = re.findall(route_pattern, js_code)
            for m in route_matches:
                for path in m:
                    if path and not path.endswith(('.js', '.css', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.ico')):
                        discovered_paths.add((path, "GET"))

            # GraphQL endpoints
            gql_pattern = r'"(/graphql|/gql|/query|/api/graphql|/graphiql)"|\'(/graphql|/gql|/query|/api/graphql|/graphiql)\''
            gql_matches = re.findall(gql_pattern, js_code)
            for m in gql_matches:
                for path in m:
                    if path:
                        discovered_paths.add((path, "POST"))

            # GraphQL introspection detection
            if "IntrospectionQuery" in js_code or "__schema" in js_code or "__type" in js_code:
                endpoints.append(
                    Endpoint(
                        method="POST",
                        url=urllib.parse.urljoin(source_url, "/graphql"),
                        source_url=js_url,
                        parameters={"query": "{ __schema { types { name } } }"}
                    )
                )

            # WebSocket URLs
            ws_pattern = r'(new\s+WebSocket\s*\(\s*["\'](ws://[^"\']+|wss://[^"\']+)["\']\s*\))'
            ws_matches = re.findall(ws_pattern, js_code)
            for ws_url in ws_matches:
                if ws_url:
                    discovered_ws.add(ws_url)
            
            # Socket.IO detection
            socket_io_pattern = r'io\s*\(\s*["\']([^"\']+)["\']\s*\)'
            socket_io_matches = re.findall(socket_io_pattern, js_code)
            for ws_url in socket_io_matches:
                if ws_url:
                    discovered_ws.add(ws_url)
            
            # Service Worker registration
            sw_pattern = r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']\s*\)'
            sw_matches = re.findall(sw_pattern, js_code)
            for sw_path in sw_matches:
                if sw_path:
                    discovered_sw.add(sw_path)
            
            # Service Worker cache URLs
            cache_pattern = r'cache\.add\s*\(\s*["\']([^"\']+)["\']\s*\)'
            cache_matches = re.findall(cache_pattern, js_code)
            for cache_url in cache_matches:
                if cache_url:
                    discovered_paths.add((cache_url, "GET"))
            
            # OpenAPI/Swagger references in JS
            openapi_pattern = r'["\']([/][^"\']*(?:openapi|swagger)[^"\']*)["\']'
            openapi_matches = re.findall(openapi_pattern, js_code, re.IGNORECASE)
            for spec_path in openapi_matches:
                if spec_path:
                    full_spec_url = urllib.parse.urljoin(source_url, spec_path)
                    endpoints.append(
                        Endpoint(
                            method="GET",
                            url=full_spec_url,
                            source_url=js_url,
                            parameters={}
                        )
                    )

            for path in discovered_paths:
                if isinstance(path, tuple):
                    path, method = path
                else:
                    method = "GET"
                full_url = urllib.parse.urljoin(source_url, path)
                params = {}

                # Path parameters e.g., /user/{id} or /user/:id
                path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}|:([a-zA-Z0-9_]+)', path)
                for p in path_params:
                    for p_name in p:
                        if p_name:
                            params[p_name] = "test"

                # Query parameters
                parsed_path = urllib.parse.urlparse(path)
                if parsed_path.query:
                    qs_params = urllib.parse.parse_qs(parsed_path.query)
                    for k, v in qs_params.items():
                        params[k] = v[0] if v else "test"

                endpoints.append(
                    Endpoint(
                        method=method,
                        url=full_url,
                        source_url=js_url,
                        parameters=params
                    )
                )
            
            for ws_url in discovered_ws:
                endpoints.append(
                    Endpoint(
                        method="WS",
                        url=ws_url,
                        source_url=js_url,
                        parameters={}
                    )
                )
            
            for sw_path in discovered_sw:
                full_sw_url = urllib.parse.urljoin(source_url, sw_path)
                endpoints.append(
                    Endpoint(
                        method="GET",
                        url=full_sw_url,
                        source_url=js_url,
                        parameters={}
                    )
                )
        except Exception as e:
            logger.error("Error discovering endpoints in JS", url=js_url, error=str(e))
        return endpoints

    async def process(self, url: str, current_depth: int) -> CrawlResult:
        """Fetch the URL, extract assets, and enqueue new links."""
        result = CrawlResult()
        
        try:
            html_content = ""
            dynamic_endpoints = []
            dynamic_websockets = []
            dynamic_spa_routes = []
            
            if self.browser_context:
                logger.debug("Crawling via Browser", url=url, depth=current_depth)
                l_storage = self.session.local_storage if self.session else None
                try:
                    html_content = await self.browser_context.get_page_content(
                        url,
                        discovered_endpoints=dynamic_endpoints,
                        local_storage=l_storage,
                        discovered_websockets=dynamic_websockets,
                        discovered_spa_routes=dynamic_spa_routes
                    )
                except Exception as b_err:
                    logger.warning("Browser navigation error, falling back to HTTP client", url=url, error=str(b_err))
                    html_content = ""

            if not html_content:
                logger.debug("Crawling via HTTP (Primary/Fallback)", url=url, depth=current_depth)
                req = HTTPRequest(method="GET", url=url)
                if self.session and self.session.custom_headers:
                    req.headers.update(self.session.custom_headers)
                
                try:
                    resp = await self.http_client.send(req)
                    if resp and isinstance(resp.text, str):
                        html_content = resp.text
                except Exception as http_err:
                    logger.warning("HTTP fetch error during crawl", url=url, error=str(http_err))

            # Aggregate dynamically sniffed AJAX endpoints during browser load
            for dyn_ep in dynamic_endpoints:
                if self.scope.in_scope(dyn_ep.url):
                    result.endpoints.append(dyn_ep)
                    if dyn_ep.method.upper() == "GET":
                        await self.queue.enqueue(dyn_ep.url, current_depth + 1, source_url=url)
                        await self._notify_queue_update()

            # Aggregate WebSocket endpoints discovered during browser load
            for ws_url in dynamic_websockets:
                if ws_url not in result.websocket_urls:
                    result.websocket_urls.append(ws_url)

            # Aggregate SPA routes discovered during browser load
            for spa_route in dynamic_spa_routes:
                if spa_route and spa_route not in result.spa_routes:
                    result.spa_routes.append(spa_route)
                    # Enqueue SPA routes for further crawling
                    if self.scope.in_scope(spa_route):
                        await self.queue.enqueue(spa_route, current_depth + 1, source_url=url)
                        await self._notify_queue_update()

            if not html_content:
                return result

            # Run DOM link/form/asset extractors
            for extractor in self.extractors:
                items = extractor.extract(html_content, url)
                for item in items:
                    if isinstance(item, Endpoint):
                        result.endpoints.append(item)
                        if self.scope.in_scope(item.url):
                            await self.queue.enqueue(item.url, current_depth + 1, source_url=url)
                            await self._notify_queue_update()
                    elif isinstance(item, Form):
                        result.forms.append(item)
                        
                        # POST Form mapping to active endpoints fuzzer targets
                        params = {inp["name"]: inp.get("value", "") or "test" for inp in item.inputs if inp.get("name")}
                        result.endpoints.append(
                            Endpoint(
                                method=item.method.upper(),
                                url=item.action,
                                source_url=url,
                                parameters=params
                            )
                        )
                        
                        if self.scope.in_scope(item.action) and item.method.upper() == "GET":
                            await self.queue.enqueue(item.action, current_depth + 1, source_url=url)
                            await self._notify_queue_update()
                    elif isinstance(item, Asset):
                        result.assets.append(item)
                        if item.type == "script" and self.scope.in_scope(item.url):
                            result.javascript_files_analyzed += 1
                            js_endpoints = await self._discover_js_endpoints(item.url, url)
                            for js_ep in js_endpoints:
                                result.endpoints.append(js_ep)
                                if self.scope.in_scope(js_ep.url):
                                    await self.queue.enqueue(js_ep.url, current_depth + 1, source_url=url)
                                    await self._notify_queue_update()
                        else:
                            result.assets_skipped += 1
                        
                        from ..classification.classifier import AssetClassifier
                        asset_class = AssetClassifier.classify(item.url)
                        if asset_class.asset_category != "First-party":
                            result.third_party_assets += 1

            # Discover OpenAPI/Swagger specs and manifest files from HTML content
            await self._discover_openapi_specs(url, html_content, result)
            await self._discover_manifest(url, html_content, result)
            
            # Discover Service Workers from HTML content
            await self._discover_service_workers(url, html_content, result)
            
            # Navigate discovered SPA routes for deeper crawling
            if dynamic_spa_routes:
                await self._crawl_spa_routes(url, dynamic_spa_routes, current_depth, result)

        except Exception as e:
            logger.error("Error processing URL", url=url, error=str(e))
        
        return result

    async def _discover_openapi_specs(self, url: str, html_content: str, result: CrawlResult) -> None:
        """Discover and parse OpenAPI/Swagger specifications."""
        openapi_paths = set()
        
        # Look for OpenAPI spec references in HTML
        common_specs = [
            "/openapi.json", "/openapi.yaml", "/openapi.yml",
            "/swagger.json", "/swagger.yaml", "/swagger.yml",
            "/v2/api-docs", "/v3/api-docs",
            "/swagger-ui.html", "/swagger-ui/index.html",
            "/api-docs", "/docs/openapi.json",
            "/redoc", "/rapidoc"
        ]
        
        # Extract from HTML links and scripts
        for path in common_specs:
            full_url = urllib.parse.urljoin(url, path)
            if full_url not in openapi_paths:
                openapi_paths.add(full_url)
        
        # Look for OpenAPI references in inline scripts
        try:
            from selectolax.parser import HTMLParser
            tree = HTMLParser(html_content)
            for node in tree.css("script"):
                inline_js = node.text()
                if inline_js:
                    # Look for Swagger UI / Redoc / RapiDoc configurations
                    urls_in_js = re.findall(r'url:\s*["\']([^"\']*(?:openapi|swagger|api-docs)[^"\']*)["\']', inline_js, re.IGNORECASE)
                    for u in urls_in_js:
                        full_url = urllib.parse.urljoin(url, u)
                        openapi_paths.add(full_url)
                    
                    # Look for spec URL assignments
                    spec_urls = re.findall(r'["\'](/[a-zA-Z0-9_\-\/]*(?:openapi|swagger)[a-zA-Z0-9_\-\/\.]*)["\']', inline_js, re.IGNORECASE)
                    for u in spec_urls:
                        full_url = urllib.parse.urljoin(url, u)
                        openapi_paths.add(full_url)
        except Exception:
            pass

        for spec_url in openapi_paths:
            if self.scope.in_scope(spec_url):
                try:
                    req = HTTPRequest(method="GET", url=spec_url)
                    if self.session and self.session.custom_headers:
                        req.headers.update(self.session.custom_headers)
                    resp = await self.http_client.send(req)
                    if resp and resp.status_code == 200 and isinstance(resp.text, str):
                        endpoints = self._parse_openapi_spec(spec_url, resp.text)
                        for ep in endpoints:
                            result.endpoints.append(ep)
                            if self.scope.in_scope(ep.url):
                                await self.queue.enqueue(ep.url, current_depth + 1, source_url=spec_url)
                                await self._notify_queue_update()
                        result.openapi_specs.append(spec_url)
                        logger.info("Parsed OpenAPI spec", url=spec_url, endpoints_found=len(endpoints))
                except Exception as e:
                    logger.debug("Failed to fetch OpenAPI spec", url=spec_url, error=str(e))

    def _parse_openapi_spec(self, spec_url: str, spec_text: str) -> List[Endpoint]:
        """Parse OpenAPI/Swagger JSON/YAML spec and extract endpoints."""
        endpoints: List[Endpoint] = []
        try:
            spec = json.loads(spec_text)
        except Exception:
            return endpoints

        paths = spec.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.lower() in ("get", "post", "put", "delete", "patch", "options", "head", "trace"):
                    full_url = urllib.parse.urljoin(spec_url, path)
                    params = {}
                    
                    # Extract parameters
                    if isinstance(details, dict):
                        for param in details.get("parameters", []):
                            if isinstance(param, dict):
                                pname = param.get("name")
                                if pname:
                                    params[pname] = "test"
                    
                    # Extract path parameters
                    path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}|:([a-zA-Z0-9_]+)', path)
                    for p in path_params:
                        for p_name in p:
                            if p_name and p_name not in params:
                                params[p_name] = "test"
                    
                    endpoints.append(
                        Endpoint(
                            method=method.upper(),
                            url=full_url,
                            source_url=spec_url,
                            parameters=params
                        )
                    )
        return endpoints

    async def _discover_manifest(self, url: str, html_content: str, result: CrawlResult) -> None:
        """Discover and parse Web App Manifest files."""
        manifest_urls = set()
        
        try:
            from selectolax.parser import HTMLParser
            tree = HTMLParser(html_content)
            for node in tree.css("link[rel='manifest']"):
                href = node.attributes.get("href")
                if href:
                    full_url = urllib.parse.urljoin(url, href)
                    manifest_urls.add(full_url)
        except Exception:
            pass

        # Also try common manifest locations
        common_manifests = ["/manifest.json", "/site.webmanifest", "/manifest.webmanifest"]
        for path in common_manifests:
            full_url = urllib.parse.urljoin(url, path)
            manifest_urls.add(full_url)

        for manifest_url in manifest_urls:
            if self.scope.in_scope(manifest_url):
                try:
                    req = HTTPRequest(method="GET", url=manifest_url)
                    if self.session and self.session.custom_headers:
                        req.headers.update(self.session.custom_headers)
                    resp = await self.http_client.send(req)
                    if resp and resp.status_code == 200 and isinstance(resp.text, str):
                        parsed = self._parse_manifest(spec_url=manifest_url, manifest_text=resp.text, base_url=url)
                        result.manifest_urls.append(manifest_url)
                        for route in parsed.get("routes", []):
                            if self.scope.in_scope(route):
                                await self.queue.enqueue(route, current_depth + 1, source_url=manifest_url)
                                await self._notify_queue_update()
                        for icon_url in parsed.get("icons", []):
                            if self.scope.in_scope(icon_url):
                                result.assets.append(Asset(url=icon_url, type="image", source_url=manifest_url))
                        logger.debug("Parsed manifest file", url=manifest_url)
                except Exception as e:
                    logger.debug("Failed to fetch manifest", url=manifest_url, error=str(e))

    def _parse_manifest(self, spec_url: str, manifest_text: str, base_url: str) -> Dict[str, List[str]]:
        """Parse manifest.json and extract routes, icons, and related apps."""
        routes: List[str] = []
        icons: List[str] = []
        try:
            manifest = json.loads(manifest_text)
            start_url = manifest.get("start_url", "")
            if start_url:
                routes.append(urllib.parse.urljoin(base_url, start_url))
            
            scope = manifest.get("scope", "")
            if scope:
                routes.append(urllib.parse.urljoin(base_url, scope))
            
            for icon in manifest.get("icons", []):
                src = icon.get("src", "")
                if src:
                    icons.append(urllib.parse.urljoin(base_url, src))
            
            for related in manifest.get("related_applications", []):
                app_url = related.get("url", "")
                if app_url:
                    routes.append(app_url)
        except Exception:
            pass
        
        return {"routes": routes, "icons": icons}

    async def _discover_service_workers(self, url: str, html_content: str, result: CrawlResult) -> None:
        """Discover Service Worker registrations and cached routes."""
        sw_urls = set()
        
        # Look for service worker registrations in inline scripts
        try:
            from selectolax.parser import HTMLParser
            tree = HTMLParser(html_content)
            for node in tree.css("script"):
                inline_js = node.text()
                if inline_js:
                    sw_matches = re.findall(r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']', inline_js)
                    for sw_path in sw_matches:
                        full_url = urllib.parse.urljoin(url, sw_path)
                        sw_urls.add(full_url)
                    
                    cache_matches = re.findall(r'cache\.add\s*\(\s*["\']([^"\']+)["\']', inline_js)
                    for cache_url in cache_matches:
                        full_url = urllib.parse.urljoin(url, cache_url)
                        if self.scope.in_scope(full_url):
                            result.endpoints.append(
                                Endpoint(method="GET", url=full_url, source_url=url, parameters={})
                            )
        except Exception:
            pass

        # Also try common service worker locations
        common_sw = ["/sw.js", "/service-worker.js", "/serviceworker.js", "/worker.js"]
        for path in common_sw:
            full_url = urllib.parse.urljoin(url, path)
            sw_urls.add(full_url)

        for sw_url in sw_urls:
            if self.scope.in_scope(sw_url):
                try:
                    req = HTTPRequest(method="GET", url=sw_url)
                    if self.session and self.session.custom_headers:
                        req.headers.update(self.session.custom_headers)
                    resp = await self.http_client.send(req)
                    if resp and resp.status_code == 200 and isinstance(resp.text, str):
                        result.service_worker_urls.append(sw_url)
                        
                        cache_urls = re.findall(r'cache\.add\s*\(\s*["\']([^"\']+)["\']', resp.text)
                        for cache_url in cache_urls:
                            full_url = urllib.parse.urljoin(url, cache_url)
                            if self.scope.in_scope(full_url):
                                result.endpoints.append(
                                    Endpoint(method="GET", url=full_url, source_url=sw_url, parameters={})
                                )
                        
                        precache_matches = re.findall(r'precacheAndRoute\s*\(\s*\[([^\]]+)\]', resp.text)
                        for precache_str in precache_matches:
                            urls_in_precache = re.findall(r'["\']([^"\']+)["\']', precache_str)
                            for precache_url in urls_in_precache:
                                full_url = urllib.parse.urljoin(url, precache_url)
                                if self.scope.in_scope(full_url):
                                    result.endpoints.append(
                                        Endpoint(method="GET", url=full_url, source_url=sw_url, parameters={})
                                    )
                        
                        logger.debug("Parsed service worker", url=sw_url, cached_urls=len(cache_urls))
                except Exception as e:
                    logger.debug("Failed to fetch service worker", url=sw_url, error=str(e))

    async def _crawl_spa_routes(self, source_url: str, spa_routes: List[str], current_depth: int, result: CrawlResult) -> None:
        """Navigate discovered SPA routes to extract additional endpoints and forms."""
        if not self.browser_context or not spa_routes:
            return

        for spa_route in spa_routes[:10]:
            if not self.scope.in_scope(spa_route):
                continue
            
            try:
                route_endpoints = []
                route_forms = []
                route_websockets = []
                
                html = await self.browser_context.get_page_content(
                    spa_route,
                    discovered_endpoints=route_endpoints,
                    discovered_websockets=route_websockets
                )
                
                if html:
                    for extractor in self.extractors:
                        items = extractor.extract(html, spa_route)
                        for item in items:
                            if isinstance(item, Endpoint):
                                result.endpoints.append(item)
                                if self.scope.in_scope(item.url):
                                    await self.queue.enqueue(item.url, current_depth + 1, source_url=spa_route)
                                    await self._notify_queue_update()
                            elif isinstance(item, Form):
                                result.forms.append(item)
                                params = {inp["name"]: inp.get("value", "") or "test" for inp in item.inputs if inp.get("name")}
                                result.endpoints.append(
                                    Endpoint(
                                        method=item.method.upper(),
                                        url=item.action,
                                        source_url=spa_route,
                                        parameters=params
                                    )
                                )
                    
                    for dyn_ep in route_endpoints:
                        if self.scope.in_scope(dyn_ep.url):
                            result.endpoints.append(dyn_ep)
                            if dyn_ep.method.upper() == "GET":
                                await self.queue.enqueue(dyn_ep.url, current_depth + 1, source_url=spa_route)
                                await self._notify_queue_update()
                    
                    for ws_url in route_websockets:
                        if ws_url not in result.websocket_urls:
                            result.websocket_urls.append(ws_url)
            except Exception as e:
                logger.debug("SPA route crawl failed", url=spa_route, error=str(e))

    async def _discover_js_endpoints(self, js_url: str, source_url: str) -> List[Endpoint]:
        """Fetch a JavaScript file and extract REST paths, GraphQL, WebSocket, and API endpoints."""
        endpoints: List[Endpoint] = []
        try:
            logger.debug("Fetching script for API discovery", url=js_url)
            req = HTTPRequest(method="GET", url=js_url)
            if self.session and self.session.custom_headers:
                req.headers.update(self.session.custom_headers)
                
            resp = await self.http_client.send(req)
            js_code = resp.text if isinstance(resp.text, str) else ""
            if not js_code:
                return endpoints

            discovered_paths = set()
            discovered_ws = set()

            # Find API routes using regex
            path_pattern = r'"(/api/v[0-9]+/[a-zA-Z0-9_\-\{\}\/]+)"|\'(/api/v[0-9]+/[a-zA-Z0-9_\-\{\}\/]+)\''
            matches = re.findall(path_pattern, js_code)
            for m in matches:
                for path in m:
                    if path:
                        discovered_paths.add(path)

            route_pattern = r'"(/[a-zA-Z0-9_\-]+)"|\'(/[a-zA-Z0-9_\-]+)\''
            route_matches = re.findall(route_pattern, js_code)
            for m in route_matches:
                for path in m:
                    if path and not path.endswith(('.js', '.css', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.ico')):
                        discovered_paths.add(path)

            # GraphQL endpoints
            gql_pattern = r'"(/graphql|/gql|/query|/api/graphql)"|\'(/graphql|/gql|/query|/api/graphql)\''
            gql_matches = re.findall(gql_pattern, js_code)
            for m in gql_matches:
                for path in m:
                    if path:
                        discovered_paths.add((path, "POST"))

            # WebSocket URLs
            ws_pattern = r'(new\s+WebSocket\s*\(\s*["\'](ws://[^"\']+|wss://[^"\']+)["\']\s*\))'
            ws_matches = re.findall(ws_pattern, js_code)
            for ws_url in ws_matches:
                if ws_url:
                    discovered_ws.add(ws_url)
            
            # OpenAPI/Swagger references in JS
            openapi_pattern = r'["\']([/][^"\']*(?:openapi|swagger)[^"\']*)["\']'
            openapi_matches = re.findall(openapi_pattern, js_code, re.IGNORECASE)
            for spec_path in openapi_matches:
                if spec_path:
                    full_spec_url = urllib.parse.urljoin(source_url, spec_path)
                    endpoints.append(
                        Endpoint(
                            method="GET",
                            url=full_spec_url,
                            source_url=js_url,
                            parameters={}
                        )
                    )

            for path in discovered_paths:
                if isinstance(path, tuple):
                    path, method = path
                else:
                    method = "GET"
                full_url = urllib.parse.urljoin(source_url, path)
                params = {}

                # Path parameters e.g., /user/{id} or /user/:id
                path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}|:([a-zA-Z0-9_]+)', path)
                for p in path_params:
                    for p_name in p:
                        if p_name:
                            params[p_name] = "test"

                # Query parameters
                parsed_path = urllib.parse.urlparse(path)
                if parsed_path.query:
                    qs_params = urllib.parse.parse_qs(parsed_path.query)
                    for k, v in qs_params.items():
                        params[k] = v[0] if v else "test"

                endpoints.append(
                    Endpoint(
                        method=method,
                        url=full_url,
                        source_url=js_url,
                        parameters=params
                    )
                )
            
            for ws_url in discovered_ws:
                endpoints.append(
                    Endpoint(
                        method="WS",
                        url=ws_url,
                        source_url=js_url,
                        parameters={}
                    )
                )
        except Exception as e:
            logger.error("Error discovering endpoints in JS", url=js_url, error=str(e))
        return endpoints


class CrawlManager:
    """Orchestrates the crawling loop, loading robots.txt and XML sitemaps recursively."""

    def __init__(
        self,
        http_client: HTTPClientInterface,
        queue: URLQueueInterface,
        extractors: List[DiscoveryExtractorInterface],
        browser_context: Optional[BrowserInterface] = None,
        concurrency: int = 5,
        browser_manager: Optional[Any] = None
    ):
        self.http_client = http_client
        self.queue = queue
        self.extractors = extractors
        self.browser_context = browser_context
        self.concurrency = concurrency
        self.browser_manager = browser_manager
        self.results = CrawlResult()
        self._active_workers = 0
        self._worker_cond = asyncio.Condition()

    async def _parse_robots(self, base_url: str) -> Tuple[List[str], List[str]]:
        """Parses robots.txt for disallowed directories and sitemap URLs."""
        sitemaps = []
        disallowed = []
        try:
            parsed = urllib.parse.urlparse(base_url)
            robots_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))
            
            req = HTTPRequest(method="GET", url=robots_url)
            resp = await self.http_client.send(req)
            if resp.status_code != 200:
                return sitemaps, disallowed
            txt = resp.text if isinstance(resp.text, str) else ""
            if not txt:
                return sitemaps, disallowed
                
            for line in txt.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    k, v = line.split(":", 1)
                    k = k.strip().lower()
                    v = v.strip()
                    if k == "sitemap":
                        sitemaps.append(v)
                    elif k == "disallow" and v and v != "/":
                        full_disallowed = urllib.parse.urljoin(base_url, v)
                        disallowed.append(full_disallowed)
        except Exception as e:
            logger.warning("Error fetching/parsing robots.txt", url=base_url, error=str(e))
        return sitemaps, disallowed

    async def _parse_sitemap(self, sitemap_url: str, depth: int = 0) -> List[str]:
        """Recursively parses XML sitemaps and sitemap indexes."""
        urls = []
        if depth > 3: # Safe nesting limit
            return urls
        try:
            req = HTTPRequest(method="GET", url=sitemap_url)
            resp = await self.http_client.send(req)
            if resp.status_code != 200:
                return urls
            xml = resp.text if isinstance(resp.text, str) else ""
            if not xml:
                return urls
            
            locs = re.findall(r'<loc>\s*(.*?)\s*</loc>', xml, re.IGNORECASE)
            for loc in locs:
                loc = loc.strip()
                if loc.endswith(".xml"):
                    nested = await self._parse_sitemap(loc, depth + 1)
                    urls.extend(nested)
                else:
                    urls.append(loc)
        except Exception as e:
            logger.warning("Error loading sitemap XML node", url=sitemap_url, error=str(e))
        return urls

    async def _worker_loop(self, session: CrawlSession, scope: ScopeValidator, browser_context: Optional[BrowserInterface]):
        """Continuous loop for a single worker task with starvation prevention and progress serialization."""
        worker = CrawlWorker(
            http_client=self.http_client,
            extractors=self.extractors,
            queue=self.queue,
            scope=scope,
            browser_context=browser_context,
            cond=self._worker_cond,
            session=session
        )
        
        while True:
            async with self._worker_cond:
                while self.queue.qsize() == 0:
                    if self._active_workers == 0:
                        self._worker_cond.notify_all()
                        return
                    await self._worker_cond.wait()
                
                item = await self.queue.dequeue()
                if not item:
                    continue
                
                self._active_workers += 1

            url, depth = item
            
            if self.queue.is_visited(url):
                async with self._worker_cond:
                    self._active_workers -= 1
                    if self._active_workers == 0 and self.queue.qsize() == 0:
                        self._worker_cond.notify_all()
                continue
                
            self.queue.mark_visited(url)
            
            if len(self.results.endpoints) >= session.max_urls:
                async with self._worker_cond:
                    self._active_workers -= 1
                    if self._active_workers == 0 and self.queue.qsize() == 0:
                        self._worker_cond.notify_all()
                break
            
            result = await worker.process(url, depth)
            
            self.results.endpoints.extend(result.endpoints)
            self.results.forms.extend(result.forms)
            self.results.assets.extend(result.assets)
            self.results.websocket_urls.extend(result.websocket_urls)
            self.results.spa_routes.extend(result.spa_routes)
            self.results.openapi_specs.extend(result.openapi_specs)
            self.results.manifest_urls.extend(result.manifest_urls)
            
            # Persist state after processing each URL
            if hasattr(self.queue, "get_visited_set") and hasattr(self.queue, "get_flat_queue"):
                CrawlStateHelper.save_state(
                    session.scan_id,
                    self.queue.get_visited_set(),
                    self.queue.get_flat_queue()
                )

            async with self._worker_cond:
                self._active_workers -= 1
                self._worker_cond.notify_all()

    async def crawl(self, start_urls: List[str], session: CrawlSession) -> CrawlResult:
        """Start the crawling process, resuming from state if available."""
        logger.info("Starting crawl", start_urls=start_urls, max_depth=session.max_depth)
        
        scope = ScopeValidator(session.allowed_domains)
        self.results = CrawlResult()
        self._active_workers = 0
        
        # 1. State Restore Check
        restored = False
        state = CrawlStateHelper.load_state(session.scan_id)
        if state and hasattr(self.queue, "restore_state"):
            logger.info("Resuming crawl from saved state file", scan_id=session.scan_id)
            self.queue.restore_state(state["visited"], [tuple(x) for x in state["enqueued"]])
            restored = True

        # 2. Seed Queue if not restored
        if not restored:
            # Parse Robots.txt and Sitemaps
            for target_url in start_urls:
                # Add target_url to queue
                await self.queue.enqueue(target_url, depth=0)
                
                # Fetch robots.txt configuration
                sitemaps, disallowed = await self._parse_robots(target_url)
                
                # Record disallowed paths in result and endpoint targets
                for dis in disallowed:
                    self.results.disallowed_paths.append(dis)
                    self.results.endpoints.append(Endpoint(method="GET", url=dis, source_url=target_url))
                
                # Enqueue Sitemap endpoints
                for s_url in sitemaps:
                    s_links = await self._parse_sitemap(s_url)
                    for link in s_links:
                        if scope.in_scope(link):
                            await self.queue.enqueue(link, depth=0, source_url=s_url)

        # 3. Create Browser Context
        local_browser_context = self.browser_context
        own_context = False
        if session.use_browser and not local_browser_context and self.browser_manager:
            logger.info("Creating dynamic browser context for crawler session")
            
            # Format cookies dictionary to Playwright structures
            playwright_cookies = []
            parsed_start = urllib.parse.urlparse(start_urls[0])
            for k, v in session.session_cookies.items():
                playwright_cookies.append({
                    "name": k,
                    "value": v,
                    "domain": parsed_start.netloc,
                    "path": "/"
                })

            local_browser_context = await self.browser_manager.create_context(
                cookies=playwright_cookies,
                headers=session.custom_headers
            )
            own_context = True

        try:
            # 4. Spawn concurrent workers
            workers = []
            for _ in range(self.concurrency):
                task = asyncio.create_task(self._worker_loop(session, scope, local_browser_context))
                workers.append(task)
                
            await asyncio.gather(*workers)
        finally:
            # Clear state on completion
            CrawlStateHelper.clear_state(session.scan_id)
            if own_context and local_browser_context:
                logger.info("Closing dynamic browser context for crawler session")
                await local_browser_context.close()
        
        logger.info(
            "Crawl completed", 
            endpoints_found=len(self.results.endpoints),
            forms_found=len(self.results.forms),
            assets_found=len(self.results.assets),
            websockets_found=len(self.results.websocket_urls),
            spa_routes_found=len(self.results.spa_routes),
            openapi_specs_found=len(self.results.openapi_specs),
            manifests_found=len(self.results.manifest_urls),
            js_analyzed=self.results.javascript_files_analyzed,
            assets_skipped=self.results.assets_skipped,
            third_party_assets=self.results.third_party_assets
        )
        return self.results

    def compute_discovery_quality(self, crawl_result: CrawlResult, allowed_domains: List[str]) -> "DiscoveryQualityMetrics":
        """Compute discovery quality metrics from crawl results."""
        from ..reporting.models import DiscoveryQualityMetrics
        from ..classification.classifier import EndpointClassifier, AssetClassifier

        endpoint_types: Dict[str, int] = {}
        hidden_endpoints = 0
        apis_discovered = 0
        first_party_endpoints = 0
        third_party_endpoints = 0
        cdn_endpoints = 0
        api_endpoints = 0
        auth_endpoints = 0
        admin_endpoints = 0

        for ep in crawl_result.endpoints:
            ep_class = ep.endpoint_class or "Main Application"
            endpoint_types[ep_class] = endpoint_types.get(ep_class, 0) + 1

            if ep_class == "API":
                apis_discovered += 1
                api_endpoints += 1
            elif ep_class == "Authentication":
                auth_endpoints += 1
            elif ep_class == "Admin":
                admin_endpoints += 1

            asset_cat = ep.asset_category or "First-party"
            if asset_cat == "First-party":
                first_party_endpoints += 1
            elif asset_cat == "Third-party":
                third_party_endpoints += 1
            elif asset_cat == "CDN":
                cdn_endpoints += 1

            source = ep.source_url or ""
            if source and (".js" in source.lower() or "openapi" in source.lower() or "manifest" in source.lower() or "swagger" in source.lower()):
                hidden_endpoints += 1

        for ws in crawl_result.websocket_urls:
            hidden_endpoints += 1

        for route in crawl_result.spa_routes:
            hidden_endpoints += 1

        for spec in crawl_result.openapi_specs:
            hidden_endpoints += 1

        for manifest in crawl_result.manifest_urls:
            hidden_endpoints += 1

        total_pages = len(crawl_result.endpoints)
        crawl_coverage = min(100.0, (total_pages / max(total_pages, 1)) * 100.0)

        return DiscoveryQualityMetrics(
            crawl_coverage_percent=round(crawl_coverage, 1),
            endpoint_types=endpoint_types,
            hidden_endpoints=hidden_endpoints,
            forms_discovered=len(crawl_result.forms),
            apis_discovered=apis_discovered,
            javascript_files_analyzed=crawl_result.javascript_files_analyzed,
            assets_skipped=crawl_result.assets_skipped,
            third_party_assets=crawl_result.third_party_assets,
            total_assets=len(crawl_result.assets),
            first_party_endpoints=first_party_endpoints,
            third_party_endpoints=third_party_endpoints,
            cdn_endpoints=cdn_endpoints,
            api_endpoints=api_endpoints,
            auth_endpoints=auth_endpoints,
            admin_endpoints=admin_endpoints
        )
