import time
from typing import Optional
from email.utils import parsedate_to_datetime
import httpx
import structlog

from ...interfaces.network import HTTPClientInterface
from ..models import HTTPRequest, HTTPResponse, Cookie

logger = structlog.get_logger(__name__)


class HttpxClientAdapter(HTTPClientInterface):
    """Adapter for httpx.AsyncClient."""

    def __init__(self, client: httpx.AsyncClient):
        self._client = client
        self.manager = None

    async def send(self, request: HTTPRequest) -> HTTPResponse:
        """Send request using httpx."""
        start_time = time.monotonic()
        
        # Prepare httpx request arguments
        kwargs = {
            "method": request.method,
            "url": request.url,
            "headers": request.headers,
            "follow_redirects": request.allow_redirects,
        }
        
        if request.timeout is not None:
            kwargs["timeout"] = request.timeout
            
        if request.body is not None:
            if isinstance(request.body, dict):
                kwargs["json"] = request.body
            else:
                kwargs["content"] = request.body

        # Convert cookies
        if request.cookies:
            httpx_cookies = httpx.Cookies()
            for c in request.cookies:
                httpx_cookies.set(c.name, c.value, domain=c.domain, path=c.path)
            kwargs["cookies"] = httpx_cookies

        try:
            logger.debug("Sending HTTP request", method=request.method, url=request.url)
            if hasattr(self, 'manager') and self.manager:
                self.manager.total_requests += 1
            response = await self._client.request(**kwargs)
            latency = time.monotonic() - start_time
            
            # Preserve security attributes from Set-Cookie rather than using
            # only httpx's name/value cookie mapping.
            resp_cookies = self._extract_response_cookies(response)
                
            return HTTPResponse(
                status_code=response.status_code,
                url=str(response.url),
                headers=dict(response.headers),
                cookies=resp_cookies,
                body=response.content,
                text=response.text,
                request=request,
                latency=latency
            )
        except httpx.RequestError as e:
            logger.warning("HTTP request failed", url=request.url, error=str(e))
            raise

    async def close(self) -> None:
        """Close the httpx client."""
        await self._client.aclose()

    @staticmethod
    def _extract_response_cookies(response: httpx.Response) -> list[Cookie]:
        cookies: list[Cookie] = []
        for raw_header in response.headers.get_list("set-cookie"):
            parts = [part.strip() for part in raw_header.split(";") if part.strip()]
            if not parts or "=" not in parts[0]:
                continue
            name, value = parts[0].split("=", 1)
            attributes: dict[str, str | bool] = {}
            for part in parts[1:]:
                key, separator, attribute_value = part.partition("=")
                attributes[key.lower()] = attribute_value if separator else True

            expires = None
            if isinstance(attributes.get("expires"), str):
                try:
                    expires = parsedate_to_datetime(attributes["expires"])
                except (TypeError, ValueError, IndexError):
                    pass
            max_age = None
            if isinstance(attributes.get("max-age"), str):
                try:
                    max_age = int(attributes["max-age"])
                except ValueError:
                    pass
            domain = attributes.get("domain") if isinstance(attributes.get("domain"), str) else None
            cookies.append(Cookie(
                name=name,
                value=value,
                domain=domain,
                path=attributes.get("path") if isinstance(attributes.get("path"), str) else "/",
                secure="secure" in attributes,
                http_only="httponly" in attributes,
                same_site=attributes.get("samesite") if isinstance(attributes.get("samesite"), str) else None,
                max_age=max_age,
                expires=expires,
                host_only=domain is None,
                partitioned="partitioned" in attributes,
            ))

        if cookies:
            return cookies
        return [Cookie(name=cookie.name, value=cookie.value, domain=cookie.domain, path=cookie.path) for cookie in response.cookies.jar]
