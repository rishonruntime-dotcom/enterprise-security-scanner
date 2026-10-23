import pytest

from scanner.domain.scan import Scan, Target, ScanStatus
from scanner.infrastructure.repositories import InMemoryScanRepository
from scanner.events.publisher import InMemoryEventPublisher
from scanner.services.orchestrator import StateController


@pytest.fixture
def repository():
    return InMemoryScanRepository()


@pytest.fixture
def publisher():
    return InMemoryEventPublisher()


@pytest.fixture
def state_controller(repository, publisher):
    return StateController(repository=repository, publisher=publisher)


@pytest.mark.asyncio
async def test_valid_state_transition(state_controller, repository, publisher):
    """Test a valid state transition (PENDING -> RUNNING)."""
    target = Target(identifier="127.0.0.1")
    scan = Scan.create(target=target)
    
    # Assert initial state
    assert scan.status == ScanStatus.PENDING
    
    # Transition
    success = await state_controller.transition(scan, ScanStatus.RUNNING)
    assert success is True
    
    # Assert new state
    assert scan.status == ScanStatus.RUNNING
    assert scan.started_at is not None
    
    # Verify repository save
    saved_scan = await repository.get(scan.id)
    assert saved_scan is not None
    assert saved_scan.status == ScanStatus.RUNNING
    
    # Verify event published
    assert len(publisher.published_events) == 1
    event = publisher.published_events[0]
    assert event.type == "ScanStatusChanged"
    assert event.payload["new_status"] == ScanStatus.RUNNING.value


@pytest.mark.asyncio
async def test_invalid_state_transition(state_controller, repository, publisher):
    """Test an invalid state transition (COMPLETED -> RUNNING)."""
    target = Target(identifier="127.0.0.1")
    scan = Scan.create(target=target)
    scan.status = ScanStatus.COMPLETED
    
    success = await state_controller.transition(scan, ScanStatus.RUNNING)
    assert success is False
    
    # Verify state didn't change
    assert scan.status == ScanStatus.COMPLETED
    
    # Verify no event published
    assert len(publisher.published_events) == 0
