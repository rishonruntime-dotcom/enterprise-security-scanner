import asyncio
import pytest
from typing import Dict, Any

from scanner.domain.scan import Scan, Target, ScanStatus
from scanner.infrastructure.repositories import InMemoryScanRepository
from scanner.events.publisher import InMemoryEventPublisher
from scanner.services.orchestrator import StateController, ScanExecutor, ScanScheduler
from scanner.interfaces.engine import ScannerEngine


class DummyEngine(ScannerEngine):
    """A dummy engine that sleeps briefly and returns a fake finding."""
    async def run(self, scan: Scan) -> Dict[str, Any]:
        await asyncio.sleep(0.1)
        return {"finding": "Test vulnerability found."}


class FailingEngine(ScannerEngine):
    """A dummy engine that raises an exception."""
    async def run(self, scan: Scan) -> Dict[str, Any]:
        await asyncio.sleep(0.1)
        raise ValueError("Simulated engine failure")


@pytest.mark.asyncio
async def test_scheduler_successful_scan():
    """Test full flow: Scheduling -> Execution -> Completion."""
    repository = InMemoryScanRepository()
    publisher = InMemoryEventPublisher()
    state_controller = StateController(repository, publisher)
    
    engines = {"dummy": DummyEngine()}
    
    executor = ScanExecutor(state_controller, engines, publisher)
    scheduler = ScanScheduler(executor, max_concurrency=2)
    
    # Start scheduler
    await scheduler.start()
    
    try:
        # Create a scan and schedule it
        target = Target(identifier="example.com")
        scan = Scan.create(target=target)
        # We explicitly set config to use our dummy engine
        scan.config.engines = ["dummy"]
        
        await scheduler.schedule(scan)
        
        # Wait for scan to process
        await asyncio.sleep(0.3)
        
        # Assert state and results
        assert scan.status == ScanStatus.COMPLETED
        assert scan.finished_at is not None
        assert "dummy" in scan.result.engine_results
        assert scan.result.engine_results["dummy"]["finding"] == "Test vulnerability found."
        
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_scheduler_failing_engine():
    """Test full flow with a failing engine."""
    repository = InMemoryScanRepository()
    publisher = InMemoryEventPublisher()
    state_controller = StateController(repository, publisher)
    
    engines = {"failing": FailingEngine()}
    
    executor = ScanExecutor(state_controller, engines, publisher)
    scheduler = ScanScheduler(executor, max_concurrency=2)
    
    await scheduler.start()
    try:
        target = Target(identifier="example.com")
        scan = Scan.create(target=target)
        scan.config.engines = ["failing"]
        
        await scheduler.schedule(scan)
        
        await asyncio.sleep(0.3)
        
        # Assert state and results
        assert scan.status == ScanStatus.FAILED
        assert scan.finished_at is not None
        assert len(scan.result.errors) > 0
        assert "Simulated engine failure" in scan.result.errors[0]
        
    finally:
        await scheduler.stop()
