import json
import structlog
from typing import List

from ..interfaces.intelligence import SignatureProviderInterface
from .models import DetectionRule

logger = structlog.get_logger(__name__)


import os

class JSONSignatureProvider(SignatureProviderInterface):
    """Loads technology signatures from a JSON file."""

    def __init__(self, file_path: str):
        if not os.path.exists(file_path):
            alt_path = os.path.join(os.path.dirname(__file__), "signatures.json")
            if os.path.exists(alt_path):
                file_path = alt_path
        self.file_path = file_path
        self._rules: List[DetectionRule] = []
        self._load_signatures()

    def _load_signatures(self):
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for name, details in data.items():
                rule = DetectionRule(
                    name=name,
                    category=details.get("category", "Unknown"),
                    website=details.get("website"),
                    headers=details.get("headers", {}),
                    cookies=details.get("cookies", {}),
                    meta=details.get("meta", {}),
                    html=details.get("html", []),
                    script_src=details.get("scriptSrc", []),
                    implies=details.get("implies", [])
                )
                self._rules.append(rule)
                
            logger.info("Loaded detection rules", count=len(self._rules), file=self.file_path)
        except Exception as e:
            logger.error("Failed to load signatures", file=self.file_path, error=str(e))

    def get_rules(self) -> List[DetectionRule]:
        """Return the loaded detection rules."""
        return self._rules
