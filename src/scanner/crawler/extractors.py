from typing import List, Union
from selectolax.parser import HTMLParser
import structlog
import re
import urllib.parse

from ..interfaces.crawler import DiscoveryExtractorInterface
from .models import Endpoint, Form, Asset
from .utils import URLNormalizer

logger = structlog.get_logger(__name__)


class HTMLExtractor(DiscoveryExtractorInterface):
    """Parses HTML to extract links, forms, static assets, and APIs (GraphQL, SOAP, REST) using selectolax."""

    def extract(self, html_content: str, current_url: str) -> List[Union[Endpoint, Form, Asset]]:
        results: List[Union[Endpoint, Form, Asset]] = []
        if not html_content:
            return results

        try:
            tree = HTMLParser(html_content)
        except Exception as e:
            logger.warning("Failed to parse HTML", url=current_url, error=str(e))
            return results

        # 1. Extract standard links
        for node in tree.css("a[href], iframe[src], area[href]"):
            href = node.attributes.get("href") or node.attributes.get("src")
            if href and not href.startswith(("javascript:", "mailto:", "tel:")):
                full_url = URLNormalizer.resolve_relative(current_url, href)
                results.append(Endpoint(method="GET", url=full_url, source_url=current_url))

        # 2. Extract Forms with hidden parameters and data attributes
        for form_node in tree.css("form"):
            action = form_node.attributes.get("action", "")
            method = form_node.attributes.get("method", "GET").upper()
            
            inputs = []
            hidden_params = {}
            
            for input_node in form_node.css("input, select, textarea"):
                name = input_node.attributes.get("name")
                if name:
                    input_type = input_node.attributes.get("type", "text").lower()
                    value = input_node.attributes.get("value", "")
                    inputs.append({
                        "name": name,
                        "type": input_type,
                        "value": value
                    })
                    if input_type == "hidden":
                        hidden_params[name] = value
            
            # Extract data-* attributes from the form element
            for attr_name, attr_value in form_node.attributes.items():
                if attr_name.startswith("data-") and attr_name not in ["data-url", "data-endpoint"]:
                    clean_name = attr_name[5:].replace("-", "_")
                    hidden_params[clean_name] = attr_value

            full_action = URLNormalizer.resolve_relative(current_url, action)
            results.append(Form(
                action=full_action,
                method=method,
                inputs=inputs,
                source_url=current_url
            ))

            # Emit hidden parameters as separate endpoints for fuzzing
            if hidden_params:
                params = dict(hidden_params)
                for k, v in params.items():
                    if not v:
                        params[k] = "test"
                results.append(
                    Endpoint(
                        method=method,
                        url=full_action,
                        source_url=current_url,
                        parameters=params
                    )
                )

        # 3. Extract hidden forms (CSS-hidden forms)
        for form_node in tree.css("form"):
            style = form_node.attributes.get("style", "")
            classes = form_node.attributes.get("class", "")
            if "display:none" in style or "display: none" in style or "hidden" in classes:
                action = form_node.attributes.get("action", "")
                method = form_node.attributes.get("method", "GET").upper()
                inputs = []
                for input_node in form_node.css("input, select, textarea"):
                    name = input_node.attributes.get("name")
                    if name:
                        inputs.append({
                            "name": name,
                            "type": input_node.attributes.get("type", "text").lower(),
                            "value": input_node.attributes.get("value", "")
                        })
                full_action = URLNormalizer.resolve_relative(current_url, action)
                results.append(Form(
                    action=full_action,
                    method=method,
                    inputs=inputs,
                    source_url=current_url
                ))

        # 4. Extract Static Assets
        for node in tree.css("script[src]"):
            src = node.attributes.get("src")
            if src:
                full_src = URLNormalizer.resolve_relative(current_url, src)
                results.append(Asset(url=full_src, type="script", source_url=current_url))

        for node in tree.css("link[rel='stylesheet']"):
            href = node.attributes.get("href")
            if href:
                full_href = URLNormalizer.resolve_relative(current_url, href)
                results.append(Asset(url=full_href, type="stylesheet", source_url=current_url))

        for node in tree.css("img[src]"):
            src = node.attributes.get("src")
            if src:
                full_src = URLNormalizer.resolve_relative(current_url, src)
                results.append(Asset(url=full_src, type="image", source_url=current_url))

        # 5. Extract hidden parameters from meta tags
        for node in tree.css("meta"):
            name = node.attributes.get("name", "").lower()
            prop = node.attributes.get("property", "").lower()
            content = node.attributes.get("content", "")
            if content and (name.startswith("csrf") or name.startswith("auth") or prop.startswith("csrf") or prop.startswith("auth")):
                if name:
                    results.append(
                        Endpoint(
                            method="POST",
                            url=current_url,
                            source_url=current_url,
                            parameters={name: content}
                        )
                    )

        # 6. Deep API Discovery: REST, GraphQL, SOAP, WebSocket, Service Worker detection inside script nodes
        for node in tree.css("script"):
            if not node.attributes.get("src"):
                inline_js = node.text()
                if inline_js:
                    discovered_paths = set()
                    
                    # REST endpoints mapping
                    path_pattern = r'"(/api/v[0-9]+/[a-zA-Z0-9_\-\{\}\/]+)"|\'(/api/v[0-9]+/[a-zA-Z0-9_\-\{\}\/]+)\''
                    matches = re.findall(path_pattern, inline_js)
                    for m in matches:
                        for path in m:
                            if path:
                                discovered_paths.add((path, "GET"))
                    
                    route_pattern = r'"(/[a-zA-Z0-9_\-]+)"|\'(/[a-zA-Z0-9_\-]+)\''
                    route_matches = re.findall(route_pattern, inline_js)
                    for m in route_matches:
                        for path in m:
                            if path and not path.endswith(('.js', '.css', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.ico')):
                                discovered_paths.add((path, "GET"))

                    # GraphQL query and endpoint checks
                    gql_pattern = r'"(/graphql|/gql|/query|/api/graphql|/graphiql)"|\'(/graphql|/gql|/query|/api/graphql|/graphiql)\''
                    gql_matches = re.findall(gql_pattern, inline_js)
                    for m in gql_matches:
                        for path in m:
                            if path:
                                discovered_paths.add((path, "POST"))

                    # GraphQL introspection detection
                    if "IntrospectionQuery" in inline_js or "__schema" in inline_js or "__type" in inline_js:
                        results.append(
                            Endpoint(
                                method="POST",
                                url=urllib.parse.urljoin(current_url, "/graphql"),
                                source_url=current_url,
                                parameters={"query": "{ __schema { types { name } } }"}
                            )
                        )

                    # SOAP endpoints checks (.wsdl, .asmx)
                    soap_pattern = r'"([a-zA-Z0-9_\-\/]+\.asmx\??[a-zA-Z0-9_\-]*)"|\'([a-zA-Z0-9_\-\/]+\.asmx\??[a-zA-Z0-9_\-]*)\''
                    soap_matches = re.findall(soap_pattern, inline_js)
                    for m in soap_matches:
                        for path in m:
                            if path:
                                discovered_paths.add((path, "POST"))

                    wsdl_pattern = r'"([a-zA-Z0-9_\-\/]+\?wsdl)"|\'([a-zA-Z0-9_\-\/]+\?wsdl)\''
                    wsdl_matches = re.findall(wsdl_pattern, inline_js)
                    for m in wsdl_matches:
                        for path in m:
                            if path:
                                discovered_paths.add((path, "GET"))

                    # WebSocket URL discovery
                    ws_pattern = r'(?:new\s+WebSocket\s*\(\s*["\'](ws://[^"\']+|wss://[^"\']+)["\']\s*\))'
                    ws_matches = re.findall(ws_pattern, inline_js)
                    for ws_url in ws_matches:
                        if ws_url:
                            results.append(
                                Endpoint(
                                    method="WS",
                                    url=ws_url,
                                    source_url=current_url,
                                    parameters={}
                                )
                            )

                    # Socket.IO detection
                    socket_io_pattern = r'io\s*\(\s*["\']([^"\']+)["\']\s*\)'
                    socket_io_matches = re.findall(socket_io_pattern, inline_js)
                    for ws_url in socket_io_matches:
                        if ws_url:
                            results.append(
                                Endpoint(
                                    method="WS",
                                    url=ws_url,
                                    source_url=current_url,
                                    parameters={}
                                )
                            )

                    # Service Worker registration
                    sw_pattern = r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']'
                    sw_matches = re.findall(sw_pattern, inline_js)
                    for sw_path in sw_matches:
                        full_sw_url = urllib.parse.urljoin(current_url, sw_path)
                        results.append(
                            Endpoint(
                                method="GET",
                                url=full_sw_url,
                                source_url=current_url,
                                parameters={}
                            )
                        )

                    # JavaScript-generated forms detection
                    form_create_pattern = r'document\.createElement\s*\(\s*["\']form["\']\s*\)'
                    form_create_matches = re.findall(form_create_pattern, inline_js, re.IGNORECASE)
                    if form_create_matches:
                        action_matches = re.findall(r'\.action\s*=\s*["\']([^"\']+)["\']', inline_js)
                        method_matches = re.findall(r'\.method\s*=\s*["\']([^"\']+)["\']', inline_js, re.IGNORECASE)
                        js_form_action = action_matches[0] if action_matches else current_url
                        js_form_method = method_matches[0].upper() if method_matches else "POST"
                        
                        input_names = re.findall(r'\.appendChild\s*\(\s*document\.createElement\s*\(\s*["\']input["\']\s*\)\s*\)[^}]*\.name\s*=\s*["\']([^"\']+)["\']', inline_js, re.DOTALL)
                        if not input_names:
                            input_names = re.findall(r'name\s*=\s*["\']([^"\']+)["\']', inline_js)
                        
                        js_form_inputs = [{"name": n, "type": "text", "value": ""} for n in input_names[:20]]
                        
                        full_action = URLNormalizer.resolve_relative(current_url, js_form_action)
                        results.append(Form(
                            action=full_action,
                            method=js_form_method,
                            inputs=js_form_inputs,
                            source_url=current_url
                        ))

                    # Re-map discovered paths to Endpoints
                    for path, method in discovered_paths:
                        full_url = URLNormalizer.resolve_relative(current_url, path)
                        params = {}

                        # Extract path parameters
                        path_params = re.findall(r'\{([a-zA-Z0-9_]+)\}|:([a-zA-Z0-9_]+)', path)
                        for p in path_params:
                            for p_name in p:
                                if p_name:
                                    params[p_name] = "test"

                        # Extract query parameters
                        parsed_path = urllib.parse.urlparse(path)
                        if parsed_path.query:
                            qs_params = urllib.parse.parse_qs(parsed_path.query)
                            for k, v in qs_params.items():
                                params[k] = v[0] if v else "test"

                        # SOAP specific parameters parsing context
                        if ".asmx" in path or "?wsdl" in path:
                            params["wsdl"] = "true"

                        # GraphQL queries parsing context
                        if "graphql" in path or "gql" in path:
                            params["query"] = "{ __schema { types { name } } }"

                        results.append(
                            Endpoint(
                                method=method,
                                url=full_url,
                                source_url=current_url,
                                parameters=params
                            )
                        )

        return results
