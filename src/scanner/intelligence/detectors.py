import re
from typing import List, Dict, Optional, Tuple
import structlog
from selectolax.parser import HTMLParser

from ..interfaces.intelligence import DetectorInterface, SignatureProviderInterface
from ..network.models import HTTPResponse
from .models import Fingerprint, TechnologyCategory

logger = structlog.get_logger(__name__)


class RegexMatcher:
    """Helper for evaluating Wappalyzer-style regex signatures."""
    
    @staticmethod
    def match_and_extract_version(pattern: str, target_string: str) -> Tuple[bool, Optional[str]]:
        """
        Matches a pattern against a string. 
        If it matches, extracts the version if a capture group and version syntax is present.
        Example Wappalyzer syntax: "nginx(?:/([\\d.]+))?\\;version:\\1"
        """
        version_syntax = "\\;version:"
        version_group = None
        
        # Split pattern and version extraction logic
        if version_syntax in pattern:
            parts = pattern.split(version_syntax)
            regex_part = parts[0]
            version_part = parts[1] if len(parts) > 1 else ""
        else:
            regex_part = pattern
            version_part = ""
            
        try:
            match = re.search(regex_part, target_string, re.IGNORECASE)
            if not match:
                return False, None
                
            version = None
            if version_part:
                match_groups = match.groups()
                if "\\1" in version_part and len(match_groups) >= 1:
                    version = match_groups[0]
                    
            return True, version
        except Exception as e:
            logger.debug("Regex match error", pattern=pattern, error=str(e))
            return False, None


class TechnologyDetector(DetectorInterface):
    """Analyzes responses using multi-source signature database and heuristic engines."""

    def __init__(self, provider: SignatureProviderInterface):
        self.provider = provider

    def analyze(self, response: HTTPResponse, html_content: str = "") -> List[Fingerprint]:
        rules = self.provider.get_rules()
        fingerprints: List[Fingerprint] = []
        
        if not html_content and hasattr(response, "text") and isinstance(response.text, str):
            html_content = response.text
            
        headers = {k.lower(): str(v) for k, v in response.headers.items()}
        
        raw_cookies = getattr(response, "cookies", [])
        cookies: Dict[str, str] = {}
        if isinstance(raw_cookies, dict):
            cookies = {k.lower(): str(v) for k, v in raw_cookies.items()}
        else:
            for c in raw_cookies:
                if hasattr(c, "name") and hasattr(c, "value"):
                    cookies[c.name.lower()] = c.value
                elif isinstance(c, dict):
                    cookies[c.get("name", "").lower()] = c.get("value", "")
        
        url_lower = str(response.url).lower()
        html_lower = html_content.lower() if html_content else ""
        
        tree = HTMLParser(html_content) if html_content else None
        
        meta_tags: Dict[str, str] = {}
        script_sources: List[str] = []
        link_hrefs: List[str] = []
        
        if tree:
            for node in tree.css("meta[name], meta[property]"):
                name = node.attributes.get("name") or node.attributes.get("property")
                content = node.attributes.get("content")
                if name and content:
                    meta_tags[name.lower()] = content
            
            for node in tree.css("script[src]"):
                src = node.attributes.get("src")
                if src:
                    script_sources.append(src)
                    
            for node in tree.css("link[href]"):
                href = node.attributes.get("href")
                if href:
                    link_hrefs.append(href)

        rule_map = {r.name: r for r in rules}

        for rule in rules:
            matched = False
            version = None
            confidence = 0
            
            # 1. Check HTTP Headers
            for h_name, h_pattern in rule.headers.items():
                h_name_lower = h_name.lower()
                if h_name_lower in headers:
                    header_val = headers[h_name_lower]
                    if not h_pattern:
                        matched = True
                        confidence += 60
                    else:
                        is_match, extracted_v = RegexMatcher.match_and_extract_version(h_pattern, header_val)
                        if is_match:
                            matched = True
                            confidence += 100
                            version = extracted_v or version

            # 2. Check Cookies
            for c_name, c_pattern in rule.cookies.items():
                c_name_lower = c_name.lower()
                if c_name_lower in cookies or any(c_name_lower in c.lower() for c in cookies.keys()):
                    matched = True
                    confidence += 70

            # 3. Check Meta Tags
            for m_name, m_pattern in rule.meta.items():
                m_name_lower = m_name.lower()
                if m_name_lower in meta_tags:
                    meta_val = meta_tags[m_name_lower]
                    is_match, extracted_v = RegexMatcher.match_and_extract_version(m_pattern, meta_val)
                    if is_match:
                        matched = True
                        confidence += 90
                        version = extracted_v or version

            # 4. Check HTML Code & Body Patterns
            if rule.html and html_content:
                for html_pattern in rule.html:
                    is_match, extracted_v = RegexMatcher.match_and_extract_version(html_pattern, html_content)
                    if is_match:
                        matched = True
                        confidence += 70
                        version = extracted_v or version
                        break

            # 5. Check Script Sources & Link Hrefs
            if rule.script_src and (script_sources or html_content):
                for script_pattern in rule.script_src:
                    target_sources = script_sources + link_hrefs if (script_sources or link_hrefs) else [html_content]
                    for src in target_sources:
                        is_match, extracted_v = RegexMatcher.match_and_extract_version(script_pattern, src)
                        if is_match:
                            matched = True
                            confidence += 85
                            version = extracted_v or version
                            break

            # 6. Specific Heuristic Patterns & Path Indicators
            r_name = rule.name
            server_header = headers.get("server", "").lower()
            x_powered_by = headers.get("x-powered-by", "").lower()
            
            if r_name == "WordPress" and ("wp-content" in url_lower or "wp-includes" in url_lower or "wp-json" in url_lower or "wordpress" in meta_tags.get("generator", "").lower()):
                matched = True
                confidence += 100
            elif r_name == "React" and ("data-reactroot" in html_lower or "react-dom" in html_lower or "_react" in html_lower):
                matched = True
                confidence += 80
            elif r_name == "Vue.js" and ("data-v-" in html_lower or "__vue__" in html_lower):
                matched = True
                confidence += 80
            elif r_name == "Next.js" and ("__next_data__" in html_lower or "_next/static" in html_lower or "next/static" in script_sources):
                matched = True
                confidence += 100
            elif r_name == "Nuxt.js" and ("__nuxt__" in html_lower or "_nuxt/" in html_lower or "_nuxt/" in script_sources):
                matched = True
                confidence += 100
            elif r_name == "Rails" and ("rails\\.js" in html_lower or "rails-ujs" in html_lower or "data-remote" in html_lower or "csrf-token" in html_lower or "_rails_session" in cookies):
                matched = True
                confidence += 90
            elif r_name == "Laravel" and ("laravel_session" in cookies or "xsrf-token" in cookies):
                matched = True
                confidence += 90
            elif r_name == "PHP" and (".php" in url_lower or "phpsessid" in cookies):
                matched = True
                confidence += 90
            elif r_name == "Nginx" and "nginx" in server_header:
                matched = True
                confidence += 100
            elif r_name == "Apache" and "apache" in server_header:
                matched = True
                confidence += 100
            elif r_name == "IIS" and "microsoft-iis" in server_header:
                matched = True
                confidence += 100
            elif r_name == "LiteSpeed" and "litespeed" in server_header:
                matched = True
                confidence += 100
            elif r_name == "Caddy" and "caddy" in server_header:
                matched = True
                confidence += 100
            elif r_name == "Tomcat" and ("apache-coyote" in server_header or "tomcat" in html_lower):
                matched = True
                confidence += 100
            elif r_name == "Cloudflare" and ("cloudflare" in server_header or "cf-ray" in headers):
                matched = True
                confidence += 100
            elif r_name == "Fastly" and ("fastly" in server_header or "x-fastly-request-id" in headers):
                matched = True
                confidence += 100
            elif r_name == "Akamai" and ("akamai" in server_header or "x-akamai-transformed" in headers):
                matched = True
                confidence += 100
            elif r_name == "AWS" and ("cloudfront" in server_header or "amazons3" in server_header or "x-amz-cf-id" in headers):
                matched = True
                confidence += 100
            elif r_name == "Azure" and ("x-azure-ref" in headers or "arraffinity" in cookies):
                matched = True
                confidence += 100
            elif r_name == "GCP" and ("google frontend" in server_header or "gfe" in server_header or "x-cloud-trace-context" in headers):
                matched = True
                confidence += 100
            elif r_name == "Vercel" and ("vercel" in server_header or "x-vercel-id" in headers):
                matched = True
                confidence += 100
            elif r_name == "Netlify" and ("netlify" in server_header or "x-nf-request-id" in headers):
                matched = True
                confidence += 100
            elif r_name == "WAF" and any(waf_indicator in server_header or waf_indicator in headers or waf_indicator in cookies for waf_indicator in ["cloudflare", "akamai", "fastly", "imperva", "sucuri", "f5-big-ip", "barracuda", "incap_ses", "visid_incap"]):
                matched = True
                confidence += 90
            elif r_name == "Django" and ("csrfmiddlewaretoken" in html_lower or "__admin__" in url_lower or "django-admin" in html_lower):
                matched = True
                confidence += 90
            elif r_name == "Flask" and ("werkzeug" in server_header or "flask" in html_lower):
                matched = True
                confidence += 85
            elif r_name == "Spring Boot" and ("spring-security" in html_lower or "Whitelabel Error Page" in html_lower or "jsessionid" in cookies):
                matched = True
                confidence += 90
            elif r_name == "Angular" and ("ng-version" in html_lower or "ng-app" in html_lower or "ng-controller" in html_lower):
                matched = True
                confidence += 80
            elif r_name == "Svelte" and ("svelte-" in html_lower or "__svelte" in html_lower):
                matched = True
                confidence += 80
            elif r_name == "Astro" and ("astro-island" in html_lower or "astro-ssr" in html_lower or "_astro/" in script_sources):
                matched = True
                confidence += 90
            elif r_name == "GraphQL" and ("graphql" in html_lower or "__typename" in html_lower or "graphql-playground" in html_lower):
                matched = True
                confidence += 85
            elif r_name == "REST" and ("/api/v" in url_lower or "/rest/" in url_lower or "application/vnd.api+json" in headers.get("content-type", "").lower()):
                matched = True
                confidence += 70
            elif r_name == "SOAP" and ("soap:envelope" in html_lower or "?wsdl" in url_lower or "text/xml" in headers.get("content-type", "").lower()):
                matched = True
                confidence += 80
            elif r_name == "gRPC" and ("application/grpc" in headers.get("content-type", "").lower() or "grpc-web" in html_lower):
                matched = True
                confidence += 85
            elif r_name == "Service Workers" and ("serviceWorker" in html_lower or "navigator.serviceWorker" in html_lower):
                matched = True
                confidence += 80
            elif r_name == "HTTP/2" and ("h2" in headers.get("alt-svc", "").lower() or "h2" in headers.get("x-firefox-spdy", "").lower()):
                matched = True
                confidence += 90
            elif r_name == "HTTP/3" and ("h3" in headers.get("alt-svc", "").lower()):
                matched = True
                confidence += 90
            elif r_name == "Brotli" and "br" in headers.get("content-encoding", "").lower():
                matched = True
                confidence += 90
            elif r_name == "Python" and "python" in server_header:
                matched = True
                confidence += 85
            elif r_name == "Java" and "apache-coyote" in server_header:
                matched = True
                confidence += 85
            elif r_name == "Node.js" and "node.js" in x_powered_by:
                matched = True
                confidence += 90
            elif r_name == "Ruby" and "ruby" in x_powered_by:
                matched = True
                confidence += 85

            if matched:
                final_confidence = min(100, confidence)
                category = (
                    TechnologyCategory(rule.category) 
                    if rule.category in [c.value for c in TechnologyCategory] 
                    else TechnologyCategory.UNKNOWN
                )
                
                fp = Fingerprint(
                    name=rule.name,
                    category=category,
                    confidence=final_confidence,
                    version=version,
                    website=rule.website
                )
                fingerprints.append(fp)
                
                for implied_name in rule.implies:
                    implied_rule = rule_map.get(implied_name)
                    implied_cat = (
                        TechnologyCategory(implied_rule.category)
                        if implied_rule and implied_rule.category in [c.value for c in TechnologyCategory]
                        else TechnologyCategory.UNKNOWN
                    )
                    implied_fp = Fingerprint(
                        name=implied_name,
                        category=implied_cat,
                        confidence=max(70, final_confidence - 10),
                        website=implied_rule.website if implied_rule else None
                    )
                    fingerprints.append(implied_fp)
                    
        return fingerprints
