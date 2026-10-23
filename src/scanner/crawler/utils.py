import urllib.parse
from typing import List, Optional


class URLNormalizer:
    """Utility for normalizing URLs for duplicate detection and consistent fetching."""
    
    @staticmethod
    def normalize(url: str) -> str:
        """
        Normalize a URL by:
        - Removing fragments (#hash)
        - Lowercasing the scheme and netloc
        - Normalizing the path
        """
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Rebuild URL dropping the fragment
            normalized = urllib.parse.urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
                parsed.params,
                parsed.query,
                ""  # Empty fragment
            ))
            return normalized
        except Exception:
            # Fallback to original if parsing fails completely
            return url

    @staticmethod
    def resolve_relative(base_url: str, target_url: str) -> str:
        """Resolve a potentially relative target URL against a base URL."""
        return urllib.parse.urljoin(base_url, target_url)


class ScopeValidator:
    """Utility to check if URLs fall within the allowed crawling scope."""

    def __init__(self, allowed_domains: List[str]):
        # Store lowercase domains for case-insensitive matching
        self.allowed_domains = [d.lower() for d in allowed_domains]

    def in_scope(self, url: str) -> bool:
        """Check if the given URL's netloc matches any allowed domains."""
        if not self.allowed_domains:
            return True
            
        try:
            parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
            netloc = parsed.netloc.lower() or parsed.path.split("/")[0].lower()
            
            if ":" in netloc:
                domain = netloc.split(":")[0]
            else:
                domain = netloc
                
            for allowed in self.allowed_domains:
                clean_allowed = allowed.replace("www.", "")
                clean_domain = domain.replace("www.", "")
                if clean_domain == clean_allowed or domain == allowed or domain.endswith(f".{clean_allowed}"):
                    return True
            return False
        except Exception:
            return False
