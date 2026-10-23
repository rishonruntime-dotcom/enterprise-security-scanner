import pytest
from typing import List
from scanner.active.plugins.command_injection import CommandInjectionPlugin
from scanner.active.plugins.xxe import XXEPlugin
from scanner.active.plugins.ssti import SSTIPlugin
from scanner.network.http.manager import HTTPClientManager
from scanner.network.models import HTTPResponse, HTTPRequest
from scanner.interfaces.network import HTTPClientInterface
from scanner.crawler.models import Endpoint

class MockPluginClient(HTTPClientInterface):
    """Mock client that responds with target signatures depending on payload features."""
    def __init__(self, mode: str):
        self.mode = mode

    async def request(self, method: str, url: str, **kwargs) -> HTTPResponse:
        body_content = ""
        req_body = kwargs.get("content", kwargs.get("data", b""))
        if isinstance(req_body, str): req_body = req_body.encode()
        
        # XXE response mocks
        if self.mode == "xxe" and method == "POST":
            if b"ENTITY" in req_body or b"SYSTEM" in req_body:
                body_content = "root:x:0:0:root:/root:/bin/bash"
            
        # SSTI response mocks
        elif self.mode == "ssti":
            if "%" in url or "7" in url or "hello" not in url:
                body_content = "The result calculation evaluated to 49!"
            
        # Command Injection response mocks
        elif self.mode == "cmdi":
            if "%3B" in url or "%7C" in url or "%24" in url or "%60" in url or "whoami" in url:
                body_content = "uid=1000(test) gid=1000(test) groups=1000(test)"

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

    async def send(self, request: HTTPRequest) -> HTTPResponse:
        # For Command Injection time-based simulation, add delay
        if self.mode == "cmdi_time" and "sleep" in request.url:
            import asyncio
            await asyncio.sleep(4.5)
        
        body_content = ""
        req_body = request.body or b""
        if isinstance(req_body, str): req_body = req_body.encode()
        
        if self.mode == "xxe" and request.method == "POST":
            if b"ENTITY" in req_body or b"SYSTEM" in req_body:
                body_content = "root:x:0:0:root:/root:/bin/bash"
        elif self.mode == "ssti":
            if "%" in request.url or "7" in request.url:
                body_content = "The result calculation evaluated to 49!"
        elif self.mode == "cmdi":
            if "%3B" in request.url or "%7C" in request.url or "%24" in request.url or "%60" in request.url or "%26" in request.url:
                body_content = "uid=1000(test) gid=1000(test) groups=1000(test)"

        return HTTPResponse(
            status_code=200,
            url=request.url,
            headers={},
            cookies=[],
            body=body_content.encode(),
            text=body_content,
            request=request
        )

    async def close(self) -> None:
        pass


class MockHTTPManager(HTTPClientManager):
    def __init__(self, mode: str):
        super().__init__()
        self._client = MockPluginClient(mode)

    def get_shared_client(self):
        return self._client


@pytest.mark.asyncio
async def test_command_injection_plugin_output():
    plugin = CommandInjectionPlugin()
    http_manager = MockHTTPManager("cmdi")
    
    ep = Endpoint(url="https://example.com/exec", method="GET", parameters={"cmd": "whoami"})
    candidates = await plugin.execute(ep, http_manager)
    
    assert len(candidates) == 1
    assert candidates[0].plugin_id == "ACT-CMDI-001"
    assert candidates[0].parameter == "cmd"


@pytest.mark.asyncio
async def test_xxe_plugin():
    plugin = XXEPlugin()
    http_manager = MockHTTPManager("xxe")
    
    ep = Endpoint(url="https://example.com/xml", method="POST", parameters={"xml": "<test></test>"})
    candidates = await plugin.execute(ep, http_manager)
    
    assert len(candidates) == 1
    assert candidates[0].plugin_id == "ACT-XXE-001"
    assert candidates[0].parameter == "XML body"


@pytest.mark.asyncio
async def test_ssti_plugin():
    plugin = SSTIPlugin()
    http_manager = MockHTTPManager("ssti")
    
    ep = Endpoint(url="https://example.com/template", method="GET", parameters={"template": "hello"})
    candidates = await plugin.execute(ep, http_manager)
    
    assert len(candidates) == 1
    assert candidates[0].plugin_id == "ACT-SSTI-001"
    assert candidates[0].parameter == "template"
