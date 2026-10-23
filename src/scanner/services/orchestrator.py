import asyncio
from datetime import datetime, timezone
from typing import Dict, Optional
import structlog
import aiometer

from ..domain.scan import Scan, ScanStatus, ScanResult, Target
from ..interfaces.repository import ScanRepository
from ..interfaces.events import EventPublisher
from ..interfaces.engine import ScannerEngine

logger = structlog.get_logger(__name__)


class StateController:
    """Manages valid state transitions for a scan."""

    VALID_TRANSITIONS = {
        ScanStatus.PENDING: {ScanStatus.RUNNING, ScanStatus.CANCELLED, ScanStatus.FAILED},
        ScanStatus.RUNNING: {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED},
        ScanStatus.COMPLETED: set(),
        ScanStatus.FAILED: set(),
        ScanStatus.CANCELLED: set(),
    }

    def __init__(self, repository: ScanRepository, publisher: EventPublisher):
        self.repository = repository
        self.publisher = publisher

    async def transition(self, scan: Scan, new_status: ScanStatus) -> bool:
        """Attempt to transition a scan to a new status."""
        if new_status not in self.VALID_TRANSITIONS.get(scan.status, set()):
            logger.warning(
                "Invalid state transition",
                scan_id=scan.id,
                current_status=scan.status,
                attempted_status=new_status,
            )
            return False

        old_status = scan.status
        scan.status = new_status
        
        if new_status == ScanStatus.RUNNING:
            scan.started_at = datetime.now(timezone.utc)
        elif new_status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}:
            scan.finished_at = datetime.now(timezone.utc)

        await self.repository.save(scan)
        
        await self.publisher.publish(
            "ScanStatusChanged",
            {
                "scan_id": scan.id,
                "old_status": old_status.value,
                "new_status": new_status.value,
            }
        )
        return True


class ScanExecutor:
    """Executes a scan against the engines."""

    def __init__(
        self,
        state_controller: StateController,
        engines: Dict[str, ScannerEngine],
        publisher: EventPublisher,
    ):
        self.state_controller = state_controller
        self.engines = engines
        self.publisher = publisher

    async def execute(self, scan: Scan) -> None:
        """Run the scan lifecycle."""
        if not await self.state_controller.transition(scan, ScanStatus.RUNNING):
            return

        logger.info("Executing scan", scan_id=scan.id, target=scan.target.identifier)
        await self.publisher.publish("ScanExecutionStarted", {"scan_id": scan.id})

        scan.result = ScanResult(findings=[], errors=[], engine_results={})
        
        # Determine engines to run based on config. If 'default', run all available.
        engines_to_run = scan.config.engines
        if "default" in engines_to_run:
            engines_to_run = list(self.engines.keys())

        try:
            # We use asyncio.gather for concurrent engine execution for a single scan.
            # In a distributed system, this might push tasks to a queue.
            async def run_engine(engine_name: str):
                engine = self.engines.get(engine_name)
                if not engine:
                    scan.result.errors.append(f"Engine not found: {engine_name}")
                    return
                
                try:
                    result = await asyncio.wait_for(
                        engine.run(scan),
                        timeout=scan.config.timeout_seconds
                    )
                    scan.result.engine_results[engine_name] = result
                except asyncio.TimeoutError:
                    scan.result.errors.append(f"Engine timeout: {engine_name}")
                except Exception as e:
                    logger.exception("Engine execution failed", engine=engine_name, scan_id=scan.id)
                    scan.result.errors.append(f"Engine {engine_name} failed: {str(e)}")

            await asyncio.gather(*(run_engine(name) for name in engines_to_run))
            
            if scan.result.errors:
                await self.state_controller.transition(scan, ScanStatus.FAILED)
                await self.publisher.publish("ScanExecutionFailed", {"scan_id": scan.id})
            else:
                await self.state_controller.transition(scan, ScanStatus.COMPLETED)
                await self.publisher.publish("ScanExecutionCompleted", {"scan_id": scan.id})
            
        except Exception as e:
            logger.exception("Scan execution encountered fatal error", scan_id=scan.id)
            if scan.result:
                scan.result.errors.append(f"Fatal execution error: {str(e)}")
            await self.state_controller.transition(scan, ScanStatus.FAILED)
            await self.publisher.publish("ScanExecutionFailed", {"scan_id": scan.id})


class ScanScheduler:
    """Schedules and limits concurrent scans."""

    def __init__(self, executor: ScanExecutor, max_concurrency: int = 10):
        self.executor = executor
        self.max_concurrency = max_concurrency
        self._queue: asyncio.Queue[Scan] = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the background scheduler."""
        if not self._worker_task:
            self._worker_task = asyncio.create_task(self._run())
            logger.info("Scan scheduler started", max_concurrency=self.max_concurrency)

    async def stop(self):
        """Stop the background scheduler."""
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
            logger.info("Scan scheduler stopped")

    async def schedule(self, scan: Scan):
        """Schedule a scan for execution."""
        await self._queue.put(scan)
        logger.debug("Scan scheduled", scan_id=scan.id)



    async def _run(self):
        """Background loop using standard asyncio Tasks and a Semaphore for concurrency limiting."""
        semaphore = asyncio.Semaphore(self.max_concurrency)
        running_tasks = set()
        
        async def _execute_with_semaphore(scan: Scan):
            async with semaphore:
                await self.executor.execute(scan)
                
        try:
            while True:
                scan = await self._queue.get()
                task = asyncio.create_task(_execute_with_semaphore(scan))
                running_tasks.add(task)
                task.add_done_callback(running_tasks.discard)
        except asyncio.CancelledError:
            # Wait for running tasks to finish or cancel them
            for task in running_tasks:
                task.cancel()
            if running_tasks:
                await asyncio.gather(*running_tasks, return_exceptions=True)
            raise


class ScanManager:
    """High-level API for scan management."""
    
    def __init__(self, repository: ScanRepository, scheduler: ScanScheduler):
        self.repository = repository
        self.scheduler = scheduler

    async def create_scan(self, target: Target) -> Scan:
        """Create and schedule a new scan."""
        scan = Scan.create(target=target)
        await self.repository.save(scan)
        await self.scheduler.schedule(scan)
        return scan

    async def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Retrieve a scan."""
        return await self.repository.get(scan_id)
