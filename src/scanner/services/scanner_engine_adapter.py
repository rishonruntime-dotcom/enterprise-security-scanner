"""Adapter that bridges the domain-driven ScannerEngine interface with existing scanner components."""
from typing import Any, Dict

from ..interfaces.engine import ScannerEngine
from ..domain.scan import Scan

import structlog

logger = structlog.get_logger(__name__)


class CrawlerEngine(ScannerEngine):
    """Discovers endpoints via the crawl manager."""

    def __init__(self, crawl_manager: Any, config: Any = None):
        self._crawl_manager = crawl_manager
        self._config = config

    async def run(self, scan: Scan) -> Dict[str, Any]:
        from ..crawler.models import CrawlSession

        target = scan.target.identifier
        import urllib.parse

        parsed = urllib.parse.urlparse(target)
        domain = parsed.netloc or parsed.path

        c_depth = getattr(self._config.crawler, "max_depth", 3) if self._config and hasattr(self._config, "crawler") else 3
        c_urls = getattr(self._config.crawler, "max_urls", 250) if self._config and hasattr(self._config, "crawler") else 250

        session = CrawlSession(
            scan_id=scan.id,
            allowed_domains=[domain],
            max_depth=c_depth,
            max_urls=c_urls,
            use_browser=True,
        )

        try:
            result = await self._crawl_manager.crawl([target], session)
            return {
                "endpoints": [e.url for e in result.endpoints],
                "forms": len(result.forms),
                "assets": len(result.assets),
                "spa_routes": len(result.spa_routes),
            }
        except Exception as e:
            logger.error("CrawlerEngine failed", target=target, error=str(e))
            return {"error": str(e), "endpoints": []}


class FingerprintEngine(ScannerEngine):
    """Fingerprints technologies from HTTP responses."""

    def __init__(self, fingerprinter: Any, http_manager: Any):
        self._fingerprinter = fingerprinter
        self._http_manager = http_manager

    async def run(self, scan: Scan) -> Dict[str, Any]:
        from ..network.models import HTTPRequest

        target = scan.target.identifier
        technologies = []

        if self._http_manager:
            client = self._http_manager.get_shared_client()
            try:
                resp = await client.send(HTTPRequest(method="GET", url=target))
                if resp:
                    profile = self._fingerprinter.analyze_response(resp)
                    techs = profile.technologies if hasattr(profile, "technologies") else profile
                    for tech in techs or []:
                        technologies.append({
                            "name": getattr(tech, "name", str(tech)),
                            "category": getattr(tech, "category", "General"),
                            "version": getattr(tech, "version", "N/A"),
                            "confidence": getattr(tech, "confidence", 100),
                        })
            except Exception as e:
                logger.error("FingerprintEngine failed", target=target, error=str(e))

        return {"technologies": technologies}


class PassiveEngine(ScannerEngine):
    """Runs passive security analysis."""

    def __init__(self, passive_scanner: Any, http_manager: Any):
        self._passive_scanner = passive_scanner
        self._http_manager = http_manager

    async def run(self, scan: Scan) -> Dict[str, Any]:
        from ..network.models import HTTPRequest

        target = scan.target.identifier
        observations = []

        if self._http_manager:
            client = self._http_manager.get_shared_client()
            try:
                resp = await client.send(HTTPRequest(method="GET", url=target))
                if resp:
                    obs = self._passive_scanner.analyze_response(resp)
                    if obs:
                        for o in obs:
                            observations.append({
                                "plugin_id": o.plugin_id,
                                "title": getattr(o, "title", ""),
                                "observation_type": o.observation_type,
                            })
            except Exception as e:
                logger.error("PassiveEngine failed", target=target, error=str(e))

        return {"observations": observations}


class ActiveEngine(ScannerEngine):
    """Runs active security testing."""

    def __init__(self, active_scanner: Any):
        self._active_scanner = active_scanner

    async def run(self, scan: Scan) -> Dict[str, Any]:
        from ..crawler.models import Endpoint

        target = scan.target.identifier
        endpoint = Endpoint(method="GET", url=target, source_url=target)
        candidates = []

        try:
            result = await self._active_scanner.scan_endpoints([endpoint])
            for c in result or []:
                candidates.append({
                    "plugin_id": c.plugin_id,
                    "vulnerability_type": c.vulnerability_type,
                    "parameter": c.parameter,
                    "payload": c.payload.value if c.payload else None,
                })
        except Exception as e:
            logger.error("ActiveEngine failed", target=target, error=str(e))

        return {"candidates": candidates}
