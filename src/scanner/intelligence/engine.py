from typing import List, Any
import structlog

from ..interfaces.intelligence import DetectorInterface
from ..network.models import HTTPResponse
from .models import TechnologyProfile

logger = structlog.get_logger(__name__)


class FingerprintManager:
    """Orchestrates technology detection against HTTP responses."""

    def __init__(
        self,
        detectors: List[DetectorInterface],
        confidence_threshold: int = 40
    ):
        self.detectors = detectors
        self.confidence_threshold = confidence_threshold

    def analyze_response(self, response: HTTPResponse, html_content: str = "") -> TechnologyProfile:
        """Analyze an HTTP response and return a structured Technology Profile."""
        profile = TechnologyProfile()
        
        if not html_content and hasattr(response, "text") and isinstance(response.text, str):
            html_content = response.text
            
        logger.debug("Analyzing response for technologies", url=response.url)
        
        for detector in self.detectors:
            try:
                fingerprints = detector.analyze(response, html_content)
                for fp in fingerprints:
                    if fp.confidence >= self.confidence_threshold:
                        profile.add_fingerprint(fp)
            except Exception as e:
                logger.error("Detector analysis failed", error=str(e), detector=detector.__class__.__name__)
                
        logger.info(
            "Fingerprinting complete", 
            url=response.url, 
            techs_found=len(profile.technologies),
            tech_names=[t.name for t in profile.technologies]
        )
        return profile
        
    def analyze(self, response: HTTPResponse, html_content: str = "") -> List[Any]:
        """Alias method returning list of detected technologies."""
        profile = self.analyze_response(response, html_content)
        return profile.technologies

    def fingerprint(self, response: HTTPResponse, html_content: str = "") -> List[Any]:
        """Alias method returning list of detected technologies."""
        profile = self.analyze_response(response, html_content)
        return profile.technologies
