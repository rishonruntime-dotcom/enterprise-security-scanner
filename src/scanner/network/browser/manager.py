from typing import Optional, Dict, Any, List
import structlog
import asyncio
import urllib.parse
from playwright.async_api import async_playwright, Playwright, Browser, BrowserContext

from ...interfaces.network import BrowserInterface

logger = structlog.get_logger(__name__)


class PlaywrightBrowserContextAdapter(BrowserInterface):
    """Adapter for an isolated Playwright BrowserContext."""

    def __init__(self, context: BrowserContext):
        self._context = context

    async def get_page_content(self, url: str, discovered_endpoints: Optional[list] = None, local_storage: Optional[dict] = None, discovered_websockets: Optional[list] = None, discovered_spa_routes: Optional[list] = None) -> str:
        """Navigate to a URL and return the HTML content, sniffing dynamic requests, injecting local storage and interacting with the DOM."""
        page = await self._context.new_page()
        
        # Dismiss alert/confirm/prompt dialogues automatically to prevent hang
        page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))

        # Setup dynamic fetch/XHR/WebSocket request listener
        if discovered_endpoints is not None or discovered_websockets is not None or discovered_spa_routes is not None:
            from ...crawler.models import Endpoint
            def on_request(req):
                try:
                    req_url = req.url
                    if req_url.startswith("http"):
                        # Skip common static files
                        if not any(req_url.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.ico', '.woff', '.woff2']):
                            method = req.method
                            params = {}
                            post_data = req.post_data
                            if post_data:
                                try:
                                    qs = urllib.parse.parse_qs(post_data)
                                    params = {k: v[0] for k, v in qs.items()}
                                except Exception:
                                    pass
                            if discovered_endpoints is not None:
                                discovered_endpoints.append(
                                    Endpoint(
                                        method=method,
                                        url=req_url,
                                        source_url=url,
                                        parameters=params
                                    )
                                )
                except Exception:
                    pass
            page.on("request", on_request)

        # Intercept WebSocket connections
        if discovered_websockets is not None:
            def on_websocket(ws):
                try:
                    ws_url = ws.url
                    if ws_url and ws_url.startswith(("ws://", "wss://")):
                        discovered_websockets.append(ws_url)
                except Exception:
                    pass
            page.on("websocket", on_websocket)

        # Inject History API interceptor for SPA route discovery
        spa_routes_script = """
        (() => {
            const routes = [];
            const origPushState = history.pushState;
            const origReplaceState = history.replaceState;
            const origBack = history.back;
            const origForward = history.forward;
            const origGo = history.go;
            
            function recordRoute() {
                routes.push(window.location.href);
            }
            
            history.pushState = function(...args) {
                try { recordRoute(); } catch(e) {}
                return origPushState.apply(this, args);
            };
            history.replaceState = function(...args) {
                try { recordRoute(); } catch(e) {}
                return origReplaceState.apply(this, args);
            };
            history.back = function(...args) {
                try { recordRoute(); } catch(e) {}
                return origBack.apply(this, args);
            };
            history.forward = function(...args) {
                try { recordRoute(); } catch(e) {}
                return origForward.apply(this, args);
            };
            history.go = function(...args) {
                try { recordRoute(); } catch(e) {}
                return origGo.apply(this, args);
            };
            
            // Intercept hash changes
            window.addEventListener('hashchange', () => {
                try { recordRoute(); } catch(e) {}
            });
            
            // Expose routes to parent
            window.__discovered_spa_routes = routes;
        })();
        """

        try:
            logger.debug("Browser navigating", url=url)
            
            # Navigate using domcontentloaded for fast SPA loading and timeout resilience
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            except Exception as goto_err:
                logger.warning("Browser page.goto timeout or navigation warning; proceeding with partial DOM", url=url, error=str(goto_err))

            # Wait for network idle to capture lazy-loaded content
            try:
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass

            # Inject local storage if present
            if local_storage:
                try:
                    for k, v in local_storage.items():
                        await page.evaluate(f"window.localStorage.setItem('{k}', '{v}')")
                except Exception as lse:
                    logger.debug("Failed to set localStorage in browser context", error=str(lse))

            # Inject SPA History API interceptor and DOM mutation observer
            try:
                await page.add_init_script(spa_routes_script)
            except Exception:
                pass

            # Scroll Down (triggers lazy loads and infinite scrolls)
            try:
                for _ in range(3):
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await asyncio.sleep(0.4)
            except Exception:
                pass

            # Click Interactive elements (menus, dropdowns, expandables)
            try:
                interactive_selectors = "button, [role='button'], nav a, .dropdown-toggle, .menu-item, [data-toggle], [data-target]"
                elements = await page.query_selector_all(interactive_selectors)
                count = 0
                for el in elements:
                    if count >= 8:
                        break
                    try:
                        if await el.is_visible() and await el.is_enabled():
                            text_val = (await el.text_content() or "").lower()
                            if not any(x in text_val for x in ["logout", "signout", "exit", "log-out"]):
                                await el.click(timeout=1000)
                                await asyncio.sleep(0.3)
                                count += 1
                    except Exception:
                        pass
            except Exception:
                pass

            # Extract SPA routes discovered via History API interception
            if discovered_spa_routes is not None:
                try:
                    extracted_routes = await page.evaluate("() => window.__discovered_spa_routes || []")
                    if extracted_routes:
                        for route in extracted_routes:
                            if route and route not in discovered_spa_routes:
                                discovered_spa_routes.append(route)
                except Exception:
                    pass

            # Extract Service Worker registrations
            try:
                sw_registrations = await page.evaluate("""
                () => {
                    if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
                        return navigator.serviceWorker.controller.scriptURL || null;
                    }
                    return null;
                }
                """)
                if sw_registrations:
                    logger.debug("Discovered active service worker", url=sw_registrations)
            except Exception:
                pass

            # Extract dynamically added links and forms via DOM observation
            try:
                dynamic_elements = await page.evaluate("""
                () => {
                    const results = { links: [], forms: [], hidden_forms: [] };
                    document.querySelectorAll('a[href], iframe[src], area[href]').forEach(el => {
                        const href = el.getAttribute('href') || el.getAttribute('src');
                        if (href && !href.startsWith('javascript:') && !href.startsWith('mailto:') && !href.startsWith('tel:')) {
                            results.links.push(href);
                        }
                    });
                    document.querySelectorAll('form').forEach(el => {
                        const action = el.getAttribute('action') || '';
                        const method = el.getAttribute('method') || 'GET';
                        const inputs = [];
                        el.querySelectorAll('input, select, textarea').forEach(inp => {
                            const name = inp.getAttribute('name');
                            if (name) {
                                inputs.push({ name: name, type: inp.getAttribute('type') || 'text', value: inp.getAttribute('value') || '' });
                            }
                        });
                        const style = window.getComputedStyle(el);
                        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                            results.hidden_forms.push({ action: action, method: method, inputs: inputs });
                        } else {
                            results.forms.push({ action: action, method: method, inputs: inputs });
                        }
                    });
                    return results;
                }
                """)
                if dynamic_elements:
                    from ...crawler.models import Endpoint, Form
                    for href in dynamic_elements.get("links", []):
                        if discovered_endpoints is not None:
                            discovered_endpoints.append(
                                Endpoint(method="GET", url=href, source_url=url, parameters={})
                            )
                    for form_data in dynamic_elements.get("forms", []) + dynamic_elements.get("hidden_forms", []):
                        if discovered_endpoints is not None:
                            discovered_endpoints.append(
                                Form(
                                    action=form_data["action"],
                                    method=form_data["method"].upper(),
                                    inputs=form_data["inputs"],
                                    source_url=url
                                )
                            )
            except Exception:
                pass

            html = await page.content()
            return html if html else ""
        except Exception as e:
            logger.warning("Error loading page content in browser context", url=url, error=str(e))
            try:
                return await page.content()
            except Exception:
                return ""
        finally:
            try:
                await page.close()
            except Exception:
                pass

    async def close(self) -> None:
        """Close this specific browser context."""
        try:
            await self._context.close()
        except Exception:
            pass


class BrowserManager:
    """Manages the overarching Playwright instance and global browser."""

    def __init__(self, headless: bool = True, timeout: float = 30000):
        self.headless = headless
        self.timeout = timeout
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None

    async def start(self) -> None:
        """Start the Playwright engine and launch the browser."""
        if self._playwright is None:
            logger.info("Starting Playwright browser engine", headless=self.headless)
            try:
                self._playwright = await async_playwright().start()
                self._browser = await self._playwright.chromium.launch(
                    headless=self.headless,
                    timeout=self.timeout
                )
                logger.info("Playwright browser launched successfully")
            except Exception as e:
                logger.error("Failed to launch Playwright browser engine", error=str(e))
                self._playwright = None
                self._browser = None

    async def stop(self) -> None:
        """Stop the browser and Playwright engine."""
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None
        
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None
            logger.info("Playwright browser engine stopped")

    async def create_context(
        self, 
        proxy: Optional[Dict[str, Any]] = None,
        cookies: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[BrowserInterface]:
        """Create a new, isolated browser context with custom cookies/headers injected."""
        if not self._browser or not self._browser.is_connected():
            await self.start()

        if not self._browser:
            logger.warning("Playwright browser instance unavailable, returning None context")
            return None
            
        kwargs = {"ignore_https_errors": True}
        if proxy:
            kwargs["proxy"] = proxy

        context = await self._browser.new_context(**kwargs)
        
        if cookies:
            try:
                await context.add_cookies(cookies)
            except Exception:
                pass
            
        if headers:
            try:
                await context.set_extra_http_headers(headers)
            except Exception:
                pass
            
        return PlaywrightBrowserContextAdapter(context)

    async def print_pdf(self, html_path: str, pdf_path: str) -> None:
        """Print local HTML file to PDF using Playwright."""
        if not self._browser or not self._browser.is_connected():
            await self.start()
        
        import os
        abs_path = os.path.abspath(html_path)
        file_url = f"file:///{abs_path.replace(os.sep, '/')}"
        
        logger.info("Printing HTML report to PDF via Playwright", file_url=file_url, pdf_path=pdf_path)
        if not self._browser:
            raise RuntimeError("Playwright browser instance could not be launched for PDF export")

        context = await self._browser.new_context()
        page = await context.new_page()
        try:
            try:
                await page.goto(file_url, wait_until="load", timeout=15000)
            except Exception as goto_err:
                logger.warning("PDF page.goto timeout/warning; proceeding with rendering", error=str(goto_err))

            await page.pdf(
                path=pdf_path,
                format="A4",
                print_background=True,
                margin={"top": "2.2cm", "bottom": "2.2cm", "left": "1.5cm", "right": "1.5cm"},
                display_header_footer=True,
                header_template='''
                    <div style="font-family: 'Segoe UI', Arial, sans-serif; font-size: 8px; color: #64748b; width: 100%; padding: 0 1.5cm; box-sizing: border-box; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; padding-bottom: 5px; margin-bottom: 10px; margin-left: auto; margin-right: auto;">
                        <span style="font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">Security Assessment Report</span>
                        <span class="title" style="font-style: italic;"></span>
                    </div>
                ''',
                footer_template='''
                    <div style="font-family: 'Segoe UI', Arial, sans-serif; font-size: 8px; color: #64748b; width: 100%; padding: 0 1.5cm; box-sizing: border-box; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid #e2e8f0; padding-top: 5px; margin-top: 10px; margin-left: auto; margin-right: auto;">
                        <span style="font-weight: 600; color: #ef4444; letter-spacing: 0.5px;">CONFIDENTIAL - ENTERPRISE ASSESSMENTS</span>
                        <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
                    </div>
                '''
            )
            logger.info("PDF report printed successfully", pdf_path=pdf_path)
        finally:
            try:
                await page.close()
            except Exception:
                pass
            try:
                await context.close()
            except Exception:
                pass
