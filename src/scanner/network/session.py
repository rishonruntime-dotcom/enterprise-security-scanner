from typing import Dict, Optional
import structlog

from ..interfaces.network import SessionInterface
from .models import AuthenticationContext

logger = structlog.get_logger(__name__)


class InMemorySessionManager(SessionInterface):
    """In-memory session persistence."""

    def __init__(self):
        self._contexts: Dict[str, AuthenticationContext] = {}

    async def save_context(self, context: AuthenticationContext) -> None:
        """Persist an authentication context."""
        self._contexts[context.id] = context
        logger.debug("Saved authentication context", context_id=context.id)

    async def get_context(self, context_id: str) -> Optional[AuthenticationContext]:
        """Retrieve an authentication context by ID."""
        return self._contexts.get(context_id)
