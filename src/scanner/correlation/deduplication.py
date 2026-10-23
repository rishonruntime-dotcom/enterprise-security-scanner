import hashlib
import urllib.parse
from typing import Optional, Set, Dict
import structlog

from .models import EnrichedFinding
from .pipeline import PipelineStep

logger = structlog.get_logger(__name__)


class DeduplicationStep(PipelineStep):
    """Drops duplicate findings within the same scan based on normalized endpoints."""

    def __init__(self):
        # Map scan_id -> set of hashes to isolate scan deduplication scopes
        self.seen_hashes: Dict[str, Set[str]] = {}

    async def process(self, finding: EnrichedFinding, scan_id: Optional[str] = None) -> Optional[EnrichedFinding]:
        normalized_url = self._normalize_url(finding.endpoint, finding.plugin_id)
        
        # Build normalized hash
        hash_input = f"{finding.plugin_id}:{normalized_url}:{finding.title}"
        finding_hash = hashlib.sha256(hash_input.encode()).hexdigest()
        
        key = scan_id or "default"
        if key not in self.seen_hashes:
            self.seen_hashes[key] = set()

        if finding_hash in self.seen_hashes[key]:
            logger.debug("Deduplicated finding dropped", url=finding.endpoint, plugin=finding.plugin_id)
            return None

        self.seen_hashes[key].add(finding_hash)
        finding.deduplication_hash = finding_hash
        return finding

    def _normalize_url(self, url: str, plugin_id: str) -> str:
        """Normalizes URL by sorting parameters for active checks or stripping them for passive checks."""
        try:
            parsed = urllib.parse.urlparse(url)
            # 1. Passive header/cookie checks apply server-wide to the host, so normalize to host root level
            if plugin_id.startswith("PASS-") or "Header" in plugin_id or "CSP" in plugin_id or "SEC" in plugin_id:
                return f"{parsed.scheme}://{parsed.netloc}/"
            
            # 2. Active parameter fuzzed checks should sort query keys to normalize URL variations
            if parsed.query:
                params = urllib.parse.parse_qsl(parsed.query)
                params.sort(key=lambda x: x[0])
                sorted_query = urllib.parse.urlencode(params)
                return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, sorted_query, parsed.fragment))
        except Exception as e:
            logger.warning("Failed to normalize URL during deduplication", url=url, error=str(e))
        return url
