import asyncio
import structlog
from typing import Callable, Awaitable, List

from .exceptions import ServiceStartupError

logger = structlog.get_logger(__name__)

class LifecycleManager:
    """Manages the startup and shutdown sequence of application services."""
    
    def __init__(self):
        self._startup_tasks: List[Callable[[], Awaitable[None]]] = []
        self._shutdown_tasks: List[Callable[[], Awaitable[None]]] = []
        
    def add_startup_task(self, task: Callable[[], Awaitable[None]]) -> None:
        """Register an async function to be called on startup."""
        self._startup_tasks.append(task)
        
    def add_shutdown_task(self, task: Callable[[], Awaitable[None]]) -> None:
        """Register an async function to be called on shutdown."""
        self._shutdown_tasks.append(task)
        
    async def startup(self) -> None:
        """Run all startup tasks."""
        logger.info("Starting up application services...")
        for task in self._startup_tasks:
            try:
                await task()
            except Exception as e:
                logger.exception("Failed to run startup task", task=task.__name__)
                raise ServiceStartupError(f"Startup task failed: {e}") from e
        logger.info("Application startup complete.")
                
    async def shutdown(self) -> None:
        """Run all shutdown tasks."""
        logger.info("Shutting down application services...")
        for task in reversed(self._shutdown_tasks):
            try:
                await task()
            except Exception:
                logger.exception("Failed to run shutdown task", task=task.__name__)
        logger.info("Application shutdown complete.")
